#!/usr/bin/env python3
"""Mixed load: filtered_tci vs native vs slice_tci under fixed offered rates."""
from __future__ import annotations

import json
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import psycopg
except ImportError:
    import psycopg2 as psycopg  # type: ignore

PGHOST = os.environ.get("PGHOST", "/tmp")
PGPORT = int(os.environ.get("PGPORT", "55432"))
PGUSER = os.environ.get("PGUSER", os.environ.get("USER", "postgres"))
PGDATABASE = os.environ.get("PGDATABASE", "tci_filt_mixed")
ROWS = int(os.environ.get("ROWS", "50000"))
SEGMENTS = int(os.environ.get("SEGMENTS", "4"))
SKEW = os.environ.get("SKEW", "hot90")
MODE = os.environ.get("MODE", "filtered_tci")
READERS = int(os.environ.get("READERS", "8"))
WRITERS = int(os.environ.get("WRITERS", "4"))
WARMUP_S = float(os.environ.get("WARMUP_S", "5"))
RUN_S = float(os.environ.get("RUN_S", "15"))
MAINT = os.environ.get("MAINT", "1") == "1"
ROOT = os.path.dirname(os.path.abspath(__file__))
TS = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)


def connect(dbname=None):
    conn = psycopg.connect(
        host=PGHOST, port=PGPORT, user=PGUSER, dbname=dbname or PGDATABASE
    )
    conn.autocommit = True
    return conn


def setup():
    admin = connect("postgres")
    with admin.cursor() as cur:
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname=%s AND pid <> pg_backend_pid()",
            (PGDATABASE,),
        )
        cur.execute(f'DROP DATABASE IF EXISTS "{PGDATABASE}"')
        cur.execute(f'CREATE DATABASE "{PGDATABASE}"')
    admin.close()

    conn = connect()
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION pg_tci")
        with open(os.path.join(ROOT, "filtered_native_lib.sql")) as f:
            cur.execute(f.read())
        cur.execute(
            "SELECT filt_bench.install(%s, %s, %s, %s)",
            (SEGMENTS, ROWS, SKEW, MODE),
        )
        cur.execute("SELECT filt_bench.assert_match()")
    conn.close()


def reader_loop(stop_at, latencies, mismatches, lock, offered_sleep):
    conn = connect()
    # Checker connection: explicit transactions (not autocommit) for RR compares.
    check_conn = None
    if mismatches is not None:
        check_conn = psycopg.connect(
            host=PGHOST, port=PGPORT, user=PGUSER, dbname=PGDATABASE
        )
        check_conn.autocommit = False
        check_conn.set_session(isolation_level="REPEATABLE READ")
    while time.time() < stop_at:
        t0 = time.perf_counter()
        with conn.cursor() as cur:
            cur.execute("SELECT filt_bench.count(0, %s)", (TS,))
            cur.fetchone()
        if check_conn is not None:
            with check_conn.cursor() as cur:
                cur.execute("SELECT filt_bench.count(0, %s)", (TS,))
                a = cur.fetchone()[0]
                cur.execute("SELECT filt_bench.native_count(0, %s)", (TS,))
                b = cur.fetchone()[0]
            check_conn.commit()
            if a != b:
                with lock:
                    mismatches[0] += 1
                    if mismatches[0] <= 3:
                        print(f"mismatch a={a} b={b}", flush=True)
        dt = (time.perf_counter() - t0) * 1000.0
        with lock:
            latencies.append(dt)
        if offered_sleep > 0:
            time.sleep(offered_sleep)
    conn.close()
    if check_conn is not None:
        check_conn.close()


def writer_loop(stop_at, write_counts, lock, offered_sleep):
    conn = connect()
    n = 0
    with conn.cursor() as cur:
        while time.time() < stop_at:
            cur.execute(
                "INSERT INTO sessions(segment, started_at, ended_at) "
                "VALUES (0, %s, %s) RETURNING id",
                (TS, datetime(2024, 1, 1, 12, 30, tzinfo=timezone.utc)),
            )
            rid = cur.fetchone()[0]
            cur.execute(
                "UPDATE sessions SET ended_at=%s WHERE id=%s",
                (datetime(2024, 1, 1, 13, 0, tzinfo=timezone.utc), rid),
            )
            if SEGMENTS > 1:
                cur.execute("UPDATE sessions SET segment=1 WHERE id=%s", (rid,))
                cur.execute("UPDATE sessions SET segment=0 WHERE id=%s", (rid,))
            cur.execute("DELETE FROM sessions WHERE id=%s", (rid,))
            n += 1
            if offered_sleep > 0:
                time.sleep(offered_sleep)
    with lock:
        write_counts.append(n)
    conn.close()


def maint_loop(stop_at):
    if not MAINT or MODE == "native":
        return
    conn = connect()
    with conn.cursor() as cur:
        while time.time() < stop_at:
            if MODE == "filtered_tci":
                cur.execute(
                    "SELECT * FROM tci.maintain_filters('sessions'::regclass, 4096, 8)"
                )
                cur.fetchall()
            elif MODE == "slice_tci":
                for i in range(SEGMENTS):
                    cur.execute(
                        "SELECT * FROM tci.maintain(%s::regclass, 4096, 8)",
                        (f"sessions_seg_{i}",),
                    )
                    cur.fetchall()
            time.sleep(0.5)
    conn.close()


def pct(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def run_phase(label, duration, check=False):
    latencies = []
    write_counts = []
    mismatches = [0] if check else None
    lock = threading.Lock()
    # Fixed offered rates: aim ~modest load, not max-qps race
    r_sleep = 0.002 if READERS else 0
    w_sleep = 0.01 if WRITERS else 0
    stop_at = time.time() + duration
    with ThreadPoolExecutor(max_workers=READERS + WRITERS + 1) as ex:
        futs = []
        for _ in range(READERS):
            futs.append(
                ex.submit(
                    reader_loop, stop_at, latencies, mismatches, lock, r_sleep
                )
            )
        for _ in range(WRITERS):
            futs.append(ex.submit(writer_loop, stop_at, write_counts, lock, w_sleep))
        futs.append(ex.submit(maint_loop, stop_at))
        for f in futs:
            f.result()
    return {
        "phase": label,
        "duration_s": duration,
        "read_ops": len(latencies),
        "read_p50_ms": pct(latencies, 50),
        "read_p95_ms": pct(latencies, 95),
        "read_p99_ms": pct(latencies, 99),
        "writes": sum(write_counts),
        "writes_per_s": sum(write_counts) / duration if duration else 0,
        "mismatches": mismatches[0] if mismatches is not None else None,
    }


def main():
    print(
        f"setup MODE={MODE} ROWS={ROWS} SEGMENTS={SEGMENTS} SKEW={SKEW} "
        f"R={READERS} W={WRITERS}"
    )
    setup()
    warm = run_phase("warmup", WARMUP_S, check=False)
    run = run_phase("run", RUN_S, check=True)
    out = {
        "mode": MODE,
        "rows": ROWS,
        "segments": SEGMENTS,
        "skew": SKEW,
        "readers": READERS,
        "writers": WRITERS,
        "maint": MAINT,
        "warmup": warm,
        "run": run,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)
    path = os.path.join(ROOT, "out", f"filtered_native_mixed_{MODE}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))
    print("wrote", path)


if __name__ == "__main__":
    main()
