/*
 * Optional maintenance background worker for pg_tci.
 *
 * Requires shared_preload_libraries='pg_tci' and
 * pg_tci.enable_maintenance_worker=on (PGC_POSTMASTER).
 *
 * Databases: pg_tci.maintenance_databases (comma-separated) if non-empty;
 * otherwise pg_tci.maintenance_database (empty → postgres). One bgworker is
 * registered per database (PostgreSQL backends cannot switch DB mid-life).
 *
 * Each pass: tci.maintain for unfiltered published+valid indexes, then
 * tci.maintain_filters for distinct sources that have filtered indexes.
 */
#include "postgres.h"

#include "access/xact.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"

#include "pg_tci.h"

#include <ctype.h>
#include <string.h>

#define PG_TCI_MAX_MAINT_DBS 32

PGDLLEXPORT void pg_tci_maintenance_main(Datum arg);

static bool pg_tci_enable_maintenance_worker = false;
static int	pg_tci_maintenance_naptime = 60;
static int	pg_tci_maintenance_tail_target = 16384;
static int	pg_tci_maintenance_max_live_runs = 8;
static int	pg_tci_maintenance_max_seal_rows = 8192;
static char *pg_tci_maintenance_database = NULL;
static char *pg_tci_maintenance_databases = NULL;

/* Filled at preload registration; read by workers via main_arg index. */
static char *pg_tci_maint_db_list[PG_TCI_MAX_MAINT_DBS];
static int	pg_tci_maint_db_count = 0;

static volatile sig_atomic_t got_sigterm = false;

static void
pg_tci_sigterm(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_sigterm = true;
	SetLatch(MyLatch);
	errno = save_errno;
}

static void
pg_tci_define_runtime_gucs(void)
{
	DefineCustomIntVariable("pg_tci.maintenance_naptime",
							"Seconds between maintenance sweeps.",
							NULL,
							&pg_tci_maintenance_naptime,
							60, 1, 86400,
							PGC_SIGHUP, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_tci.maintenance_tail_target",
							"tail_target passed to tci.maintain / maintain_filters.",
							NULL,
							&pg_tci_maintenance_tail_target,
							16384, 1, 100000000,
							PGC_SIGHUP, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_tci.maintenance_max_live_runs",
							"max_live_runs passed to tci.maintain / maintain_filters.",
							NULL,
							&pg_tci_maintenance_max_live_runs,
							8, 2, 100000,
							PGC_SIGHUP, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_tci.maintenance_max_seal_rows",
							"max_seal_rows passed to tci.maintain by the worker.",
							NULL,
							&pg_tci_maintenance_max_seal_rows,
							8192, 1, 100000000,
							PGC_SIGHUP, 0,
							NULL, NULL, NULL);
}

/*
 * Parse comma-separated database names into pg_tci_maint_db_list.
 * Trims whitespace; skips empty tokens. Returns count.
 */
static int
pg_tci_parse_db_list(const char *raw)
{
	char	   *buf;
	char	   *p;
	char	   *tok;
	int			n = 0;

	if (raw == NULL || raw[0] == '\0')
		return 0;

	buf = pstrdup(raw);
	p = buf;
	for (;;)
	{
		char	   *start;
		char	   *end;

		while (*p != '\0' && (isspace((unsigned char) *p) || *p == ','))
			p++;
		if (*p == '\0')
			break;
		start = p;
		while (*p != '\0' && *p != ',')
			p++;
		end = p;
		while (end > start && isspace((unsigned char) end[-1]))
			end--;
		*end = '\0';
		tok = start;
		if (tok[0] != '\0')
		{
			if (n >= PG_TCI_MAX_MAINT_DBS)
			{
				ereport(WARNING,
						(errmsg("pg_tci: maintenance_databases truncated to %d entries",
								PG_TCI_MAX_MAINT_DBS)));
				break;
			}
			pg_tci_maint_db_list[n++] = pstrdup(tok);
		}
		if (*p == ',')
			p++;
		else if (*p == '\0')
			break;
	}
	pfree(buf);
	return n;
}

static void
pg_tci_run_spi_list_and_call(const char *select_sql, bool filtered)
{
	int			ret;
	MemoryContext oldctx;
	uint64		i;
	uint64		n;
	char	  **tables;

	oldctx = CurrentMemoryContext;
	ret = SPI_execute(select_sql, true, 0);

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
		return;

	n = SPI_processed;
	tables = (char **) MemoryContextAlloc(oldctx, sizeof(char *) * n);
	for (i = 0; i < n; i++)
	{
		char	   *val = SPI_getvalue(SPI_tuptable->vals[i],
									   SPI_tuptable->tupdesc, 1);

		tables[i] = MemoryContextStrdup(oldctx, val ? val : "");
	}

	for (i = 0; i < n; i++)
	{
		StringInfoData sql;
		int			mret;

		if (tables[i][0] == '\0')
			continue;

		initStringInfo(&sql);
		if (filtered)
			appendStringInfo(&sql,
							 "SELECT * FROM tci.maintain_filters(%s::regclass, %d, %d)",
							 quote_literal_cstr(tables[i]),
							 pg_tci_maintenance_tail_target,
							 pg_tci_maintenance_max_live_runs);
		else
			appendStringInfo(&sql,
							 "SELECT * FROM tci.maintain(%s::regclass, %d, %d, 2000, 4, %d, true, 'pairwise')",
							 quote_literal_cstr(tables[i]),
							 pg_tci_maintenance_tail_target,
							 pg_tci_maintenance_max_live_runs,
							 pg_tci_maintenance_max_seal_rows);

		SetCurrentStatementStartTimestamp();
		mret = SPI_execute(sql.data, false, 0);
		if (mret != SPI_OK_SELECT)
			elog(LOG, "pg_tci: %s failed for %s",
				 filtered ? "maintain_filters" : "maintain", tables[i]);
		pfree(sql.data);
	}
}

static void
pg_tci_run_maintain_pass(void)
{
	int			ret;

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	SPI_connect();
	PushActiveSnapshot(GetTransactionSnapshot());

	ret = SPI_execute(
		"SELECT 1 FROM pg_extension WHERE extname = 'pg_tci'", true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		PopActiveSnapshot();
		SPI_finish();
		CommitTransactionCommand();
		return;
	}

	/* Unfiltered indexes only */
	pg_tci_run_spi_list_and_call(
		"SELECT format('%I.%I', source_nsp, source_rel) "
		"FROM tci_internal.indexes "
		"WHERE published AND valid AND filter_col IS NULL "
		"ORDER BY index_id",
		false);

	/* Distinct sources with at least one filtered index */
	pg_tci_run_spi_list_and_call(
		"SELECT DISTINCT format('%I.%I', source_nsp, source_rel) "
		"FROM tci_internal.indexes "
		"WHERE published AND valid AND filter_col IS NOT NULL "
		"ORDER BY 1",
		true);

	PopActiveSnapshot();
	SPI_finish();
	CommitTransactionCommand();
}

void
pg_tci_maintenance_main(Datum arg)
{
	int			db_index = DatumGetInt32(arg);
	int			n;
	const char *dbname;
	char	   *local_list[PG_TCI_MAX_MAINT_DBS];

	pqsignal(SIGTERM, pg_tci_sigterm);
	BackgroundWorkerUnblockSignals();

	/* Re-parse GUCs in this process (do not rely on postmaster static ptrs). */
	memset(local_list, 0, sizeof(local_list));
	n = 0;
	if (pg_tci_maintenance_databases != NULL &&
		pg_tci_maintenance_databases[0] != '\0')
	{
		/* reuse parser into shared slot then copy names */
		int			i;

		for (i = 0; i < PG_TCI_MAX_MAINT_DBS; i++)
			pg_tci_maint_db_list[i] = NULL;
		n = pg_tci_parse_db_list(pg_tci_maintenance_databases);
		for (i = 0; i < n; i++)
			local_list[i] = pg_tci_maint_db_list[i];
	}
	if (n == 0)
	{
		local_list[0] =
			(pg_tci_maintenance_database != NULL &&
			 pg_tci_maintenance_database[0] != '\0')
			? pg_tci_maintenance_database
			: "postgres";
		n = 1;
	}

	if (db_index < 0 || db_index >= n ||
		local_list[db_index] == NULL ||
		local_list[db_index][0] == '\0')
		dbname = "postgres";
	else
		dbname = local_list[db_index];

	BackgroundWorkerInitializeConnection(dbname, NULL, 0);

	elog(LOG,
		 "pg_tci: maintenance worker started on database \"%s\" "
		 "(naptime=%ds, db_index=%d)",
		 dbname, pg_tci_maintenance_naptime, db_index);

	while (!got_sigterm)
	{
		int			rc;

		CHECK_FOR_INTERRUPTS();

		PG_TRY();
		{
			pg_tci_run_maintain_pass();
		}
		PG_CATCH();
		{
			EmitErrorReport();
			FlushErrorState();
			if (IsTransactionState())
				AbortCurrentTransaction();
			elog(LOG, "pg_tci: maintenance pass aborted; will retry after nap");
		}
		PG_END_TRY();

		rc = WaitLatch(MyLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
					   pg_tci_maintenance_naptime * 1000L,
					   PG_WAIT_EXTENSION);
		ResetLatch(MyLatch);

		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);
	}

	proc_exit(0);
}

static void
pg_tci_register_one_worker(int db_index, const char *dbname)
{
	BackgroundWorker worker;

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 60;
	snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_tci");
	snprintf(worker.bgw_function_name, BGW_MAXLEN, "pg_tci_maintenance_main");
	snprintf(worker.bgw_name, BGW_MAXLEN, "pg_tci maintenance [%s]", dbname);
	snprintf(worker.bgw_type, BGW_MAXLEN, "pg_tci maintenance");
	worker.bgw_main_arg = Int32GetDatum(db_index);
	worker.bgw_notify_pid = 0;

	RegisterBackgroundWorker(&worker);
}

void
pg_tci_worker_init(void)
{
	int			i;

	/*
	 * Runtime (SIGHUP) GUCs are safe whether the library is preloaded or
	 * loaded later via CREATE EXTENSION / CREATE FUNCTION.
	 */
	pg_tci_define_runtime_gucs();
	MarkGUCPrefixReserved("pg_tci");

	/*
	 * POSTMASTER GUCs + worker registration only during shared_preload.
	 * Defining PGC_POSTMASTER after startup is a FATAL error.
	 */
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomBoolVariable("pg_tci.enable_maintenance_worker",
							 "Start pg_tci background maintenance worker(s) "
							 "(requires shared_preload_libraries='pg_tci').",
							 NULL,
							 &pg_tci_enable_maintenance_worker,
							 false,
							 PGC_POSTMASTER, 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("pg_tci.maintenance_database",
							   "Single database for the maintenance worker "
							   "when maintenance_databases is empty "
							   "(empty defaults to postgres).",
							   NULL,
							   &pg_tci_maintenance_database,
							   "",
							   PGC_POSTMASTER, 0,
							   NULL, NULL, NULL);

	DefineCustomStringVariable("pg_tci.maintenance_databases",
							   "Comma-separated databases for maintenance "
							   "workers (one worker per DB). When non-empty, "
							   "overrides maintenance_database.",
							   NULL,
							   &pg_tci_maintenance_databases,
							   "",
							   PGC_POSTMASTER, 0,
							   NULL, NULL, NULL);

	if (!pg_tci_enable_maintenance_worker)
		return;

	pg_tci_maint_db_count = pg_tci_parse_db_list(pg_tci_maintenance_databases);
	if (pg_tci_maint_db_count == 0)
	{
		const char *single =
			(pg_tci_maintenance_database != NULL &&
			 pg_tci_maintenance_database[0] != '\0')
			? pg_tci_maintenance_database
			: "postgres";

		pg_tci_maint_db_list[0] = pstrdup(single);
		pg_tci_maint_db_count = 1;
	}

	for (i = 0; i < pg_tci_maint_db_count; i++)
		pg_tci_register_one_worker(i, pg_tci_maint_db_list[i]);

	elog(LOG, "pg_tci: registered %d maintenance worker(s)",
		 pg_tci_maint_db_count);
}
