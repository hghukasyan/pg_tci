# pg_tci 0.1.12 — PGXS build for PostgreSQL 18
PG_CONFIG ?= $(shell test -x /opt/homebrew/opt/postgresql@18/bin/pg_config && echo /opt/homebrew/opt/postgresql@18/bin/pg_config || echo pg_config)
.DEFAULT_GOAL := all

EXTENSION = pg_tci
DATA = sql/pg_tci--0.1.0.sql sql/pg_tci--0.1.1.sql sql/pg_tci--0.1.2.sql sql/pg_tci--0.1.3.sql sql/pg_tci--0.1.4.sql sql/pg_tci--0.1.5.sql sql/pg_tci--0.1.6.sql sql/pg_tci--0.1.7.sql sql/pg_tci--0.1.8.sql sql/pg_tci--0.1.9.sql sql/pg_tci--0.1.10.sql sql/pg_tci--0.1.11.sql sql/pg_tci--0.1.12.sql sql/pg_tci--0.1.0--0.1.1.sql sql/pg_tci--0.1.1--0.1.2.sql sql/pg_tci--0.1.2--0.1.3.sql sql/pg_tci--0.1.3--0.1.4.sql sql/pg_tci--0.1.4--0.1.5.sql sql/pg_tci--0.1.5--0.1.6.sql sql/pg_tci--0.1.6--0.1.7.sql sql/pg_tci--0.1.7--0.1.8.sql sql/pg_tci--0.1.8--0.1.9.sql sql/pg_tci--0.1.9--0.1.10.sql sql/pg_tci--0.1.10--0.1.11.sql sql/pg_tci--0.1.11--0.1.12.sql
MODULE_big = pg_tci
OBJS = codec.o decoder.o pg_tci.o worker.o

PG_CPPFLAGS += -I$(srcdir)/include -Iinclude
# Optional Homebrew paths (macOS); ignored when absent.
GETTEXT_PREFIX ?= $(shell brew --prefix gettext 2>/dev/null)
ifneq ($(GETTEXT_PREFIX),)
PG_CPPFLAGS += -I$(GETTEXT_PREFIX)/include
endif
HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)
ifneq ($(HOMEBREW_PREFIX),)
PG_CPPFLAGS += -I$(HOMEBREW_PREFIX)/include
endif

REGRESS = basic privileges mvcc filtered ops010 partition_leaf partition_parent rls_safe
REGRESS_OPTS = --inputdir=test --outputdir=test/results

ISOLATION = count_rr_insert seal_during_rr
ISOLATION_OPTS = --load-extension=pg_tci --inputdir=test/isolation --outputdir=test/results/isolation

EXTRA_CLEAN = test/results

# Custom src/→.o rules below do not emit LLVM bitcode; override before PGXS
# so Makefile.global cannot re-enable with_llvm=yes from the PG build.
override with_llvm = no

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Sources live under src/; compile explicitly after PGXS so `all` stays default.
codec.o: src/codec.c include/pg_tci.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<

decoder.o: src/decoder.c include/pg_tci.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<

pg_tci.o: src/pg_tci.c include/pg_tci.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<

worker.o: src/worker.c include/pg_tci.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<
