/*
 * PostgreSQL 18 wrappers for pg_tci (packed IAR codec + optional maint worker).
 * Not an Index Access Method. No planner hooks.
 */
#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "catalog/pg_type.h"
#include "utils/errcodes.h"

#include "pg_tci.h"

PG_MODULE_MAGIC;

void		_PG_init(void);

void
_PG_init(void)
{
	pg_tci_worker_init();
}

PG_FUNCTION_INFO_V1(pg_tci_chunk_prefix_at);
PG_FUNCTION_INFO_V1(pg_tci_pack_entries);
PG_FUNCTION_INFO_V1(pg_tci_pack_validate);
PG_FUNCTION_INFO_V1(pg_tci_unpack_entries);

Datum
pg_tci_chunk_prefix_at(PG_FUNCTION_ARGS)
{
	bytea	   *encoded = PG_GETARG_BYTEA_PP(0);
	int64		target_us = PG_GETARG_INT64(1);
	int64		prefix = 0;
	TciPackError err;

	err = tci_chunk_prefix_at((const uint8_t *) VARDATA_ANY(encoded),
							  (size_t) VARSIZE_ANY_EXHDR(encoded),
							  target_us, &prefix);
	if (err != TCI_OK)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_EXCEPTION),
				 errmsg("pg_tci: chunk_prefix_at: %s", tci_pack_errstr(err))));

	PG_RETURN_INT64(prefix);
}

Datum
pg_tci_pack_validate(PG_FUNCTION_ARGS)
{
	bytea	   *encoded = PG_GETARG_BYTEA_PP(0);
	int64		dummy = 0;
	TciPackError err;

	err = tci_chunk_prefix_at((const uint8_t *) VARDATA_ANY(encoded),
							  (size_t) VARSIZE_ANY_EXHDR(encoded),
							  PG_INT64_MIN, &dummy);
	if (err != TCI_OK)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_EXCEPTION),
				 errmsg("pg_tci: pack_validate: %s", tci_pack_errstr(err))));
	PG_RETURN_BOOL(true);
}

Datum
pg_tci_pack_entries(PG_FUNCTION_ARGS)
{
	ArrayType  *ts_arr = PG_GETARG_ARRAYTYPE_P(0);
	ArrayType  *d_arr = PG_GETARG_ARRAYTYPE_P(1);
	int32		cp_interval = PG_GETARG_INT32(2);
	int64	   *ts;
	int16	   *deltas;
	int			n_ts, n_d;
	uint8_t	   *packed = NULL;
	size_t		packed_len = 0;
	TciPackError err;
	bytea	   *result;

	if (ARR_NDIM(ts_arr) > 1 || ARR_NDIM(d_arr) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("pg_tci: pack_entries: arrays must be 1-D")));

	n_ts = ArrayGetNItems(ARR_NDIM(ts_arr), ARR_DIMS(ts_arr));
	n_d = ArrayGetNItems(ARR_NDIM(d_arr), ARR_DIMS(d_arr));
	if (n_ts != n_d)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("pg_tci: pack_entries: array length mismatch")));

	if (n_ts > 0)
	{
		if (ARR_HASNULL(ts_arr) || ARR_HASNULL(d_arr))
			ereport(ERROR,
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
					 errmsg("pg_tci: pack_entries: null elements not allowed")));
		if (ARR_ELEMTYPE(ts_arr) != INT8OID)
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("pg_tci: pack_entries: timestamps must be bigint[]")));
		if (ARR_ELEMTYPE(d_arr) != INT2OID)
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("pg_tci: pack_entries: deltas must be smallint[]")));
		ts = (int64 *) ARR_DATA_PTR(ts_arr);
		deltas = (int16 *) ARR_DATA_PTR(d_arr);
	}
	else
	{
		ts = NULL;
		deltas = NULL;
	}

	err = tci_pack_entries(ts, deltas, (uint32_t) n_ts, (uint16_t) cp_interval,
						   &packed, &packed_len);
	if (err != TCI_OK)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_EXCEPTION),
				 errmsg("pg_tci: pack_entries: %s", tci_pack_errstr(err))));

	result = (bytea *) palloc(VARHDRSZ + packed_len);
	SET_VARSIZE(result, VARHDRSZ + packed_len);
	if (packed_len > 0)
		memcpy(VARDATA(result), packed, packed_len);
	if (packed)
		free(packed);
	PG_RETURN_BYTEA_P(result);
}

Datum
pg_tci_unpack_entries(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	typedef struct
	{
		int64_t *ts;
		int16_t *ds;
		uint32_t n;
		uint32_t i;
	} UnpackState;

	if (SRF_IS_FIRSTCALL())
	{
		bytea	   *encoded = PG_GETARG_BYTEA_PP(0);
		UnpackState *st;
		TciPackError err;
		TupleDesc	tupdesc;
		MemoryContext oldcontext;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		st = (UnpackState *) palloc0(sizeof(UnpackState));
		err = tci_unpack_entries((const uint8_t *) VARDATA_ANY(encoded),
								 (size_t) VARSIZE_ANY_EXHDR(encoded),
								 &st->ts, &st->ds, &st->n);
		if (err != TCI_OK)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_EXCEPTION),
					 errmsg("pg_tci: unpack_entries: %s", tci_pack_errstr(err))));

		if (st->n > 0)
		{
			int64_t *ts2 = (int64_t *) palloc(sizeof(int64_t) * st->n);
			int16_t *ds2 = (int16_t *) palloc(sizeof(int16_t) * st->n);

			memcpy(ts2, st->ts, sizeof(int64_t) * st->n);
			memcpy(ds2, st->ds, sizeof(int16_t) * st->n);
			free(st->ts);
			free(st->ds);
			st->ts = ts2;
			st->ds = ds2;
		}

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("pg_tci: unpack_entries must be called as TABLE")));
		funcctx->tuple_desc = BlessTupleDesc(tupdesc);
		funcctx->user_fctx = st;
		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	{
		UnpackState *st = (UnpackState *) funcctx->user_fctx;

		if (st->i < st->n)
		{
			Datum		values[2];
			bool		nulls[2] = {false, false};
			HeapTuple	tuple;

			values[0] = Int64GetDatum(st->ts[st->i]);
			values[1] = Int16GetDatum(st->ds[st->i]);
			st->i++;
			tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
			SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
		}
		SRF_RETURN_DONE(funcctx);
	}
}
