#!/usr/bin/env python3
"""
pg_tci segment spike — write-sync + mixed load (experiment only).

Setup: one physical slice table + TCI per segment; AFTER trigger mirrors
writes from `sessions` into the matching slice (TCI triggers fire there).

Modes:
  native  — COUNT(*) FROM sessions WHERE segment=… AND coverage(ts)
  tci     — tci_spike.count_at_segment(seg, ts)

Env:
  ROWS SEGMENTS SKEW=uniform|hot90
  READERS WRITERS WARMUP_S RUN_S
  MAINT=0|1   OUT=out/segment_spike_mixed.json
  PGHOST PGPORT PGDATABASE PGUSER
"""
from __future__ import annotations

import json
import os
import random
import statistics
import threading
import time
from collections import defaultdict
from pathlib import Path

try:
    import psycopg as _pg

    _PSYCOPG3 = True
except ImportError:  # pragma: no cover
    import psycopg2 as _pg

    _PSYCOPG3 = False

DSN = {
    "host": os.environ.get("PGHOST", "/tmp"),
    "port": int(os.environ.get("PGPORT", "55432")),
    "dbname": os.environ.get("PGDATABASE", "postgres"),
    "user": os.environ.get("PGUSER", os.environ.get("USER", "haykghukasyan")),
}
ROWS = int(os.environ.get("ROWS", "100000"))
SEGMENTS = int(os.environ.get("SEGMENTS", "4"))
SKEW = os.environ.get("SKEW", "hot90")  # uniform | hot90
READERS = int(os.environ.get("READERS", "16"))
WRITERS = int(os.environ.get("WRITERS", "4"))
WARMUP_S = float(os.environ.get("WARMUP_S", "10"))
RUN_S = float(os.environ.get("RUN_S", "30"))
MAINT = os.environ.get("MAINT", "1") == "1"
OUT = os.environ.get("OUT", "out/segment_spike_mixed.json")
LIB = Path(__file__).with_name("segment_spike_lib.sql")


def connect(**kw):
    if _PSYCOPG3:
        return _pg.connect(**DSN, autocommit=True, **kw)
    conn = _pg.connect(**DSN, **kw)
    conn.autocommit = True
    return conn


def pct(xs, p):
    if not xs:
        return None
    ys = sorted(xs)
    k = (len(ys) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(ys) - 1)
    if f == c:
        return ys[f]
    return ys[f] + (ys[c] - ys[f]) * (k - f)


def summarize(lat):
    return {
        "n": len(lat),
        "p50": pct(lat, 50),
        "p95": pct(lat, 95),
        "p99": pct(lat, 99),
        "mean": statistics.fmean(lat) if lat else None,
    }


def setup():
    sql = LIB.read_text()
    with connect() as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS pg_tci")
        cur.execute("CREATE SCHEMA IF NOT EXISTS tci_spike")
        cur.execute(sql)
        cur.execute(
            "SELECT tci_spike.install(%s, %s, %s)",
            (SEGMENTS, ROWS, SKEW),
        )
        cur.execute("SELECT tci_spike.assert_match()")
        cur.execute(
            """
            SELECT segment, count(*) FROM sessions
            GROUP BY segment ORDER BY segment
            """
        )
        dist = cur.fetchall()
        print("segment row counts:", dist)
        # Write-path smoke via trigger
        cur.execute(
            """
            INSERT INTO sessions(segment, started_at, ended_at)
            VALUES (0, timestamptz '2024-01-01 11:59:00+00',
                       timestamptz '2024-01-01 12:01:00+00')
            RETURNING id
            """
        )
        new_id = cur.fetchone()[0]
        cur.execute(
            "UPDATE sessions SET ended_at = timestamptz '2024-01-01 12:30:00+00' WHERE id = %s",
            (new_id,),
        )
        if SEGMENTS > 1:
            cur.execute(
                "UPDATE sessions SET segment = 1 WHERE id = %s",
                (new_id,),
            )
            cur.execute(
                "UPDATE sessions SET segment = 0 WHERE id = %s",
                (new_id,),
            )
        cur.execute("DELETE FROM sessions WHERE id = %s", (new_id,))
        cur.execute("SELECT tci_spike.assert_match()")
        print("sync write-path assert_match OK")


def _pick_local(rng: random.Random) -> int:
    u = rng.random()
    if SKEW == "hot90" and SEGMENTS > 1:
        if u < 0.90:
            return 0
        return 1 + int((u - 0.90) / 0.10 * (SEGMENTS - 1)) % (SEGMENTS - 1)
    return rng.randrange(SEGMENTS)


def probe_ts(rng: random.Random) -> str:
    return (
        "timestamptz '2024-01-01' + interval "
        f"'{rng.randint(0, 86400)} seconds'"
    )


def reader_loop(mode: str, seconds: float, out: dict, stop: threading.Event):
    rng = random.Random(threading.get_ident())
    lat = []
    with connect() as conn, conn.cursor() as cur:
        end = time.perf_counter() + seconds
        while time.perf_counter() < end and not stop.is_set():
            seg = _pick_local(rng)
            ts = probe_ts(rng)
            if mode == "tci":
                q = f"SELECT tci_spike.count_at_segment({seg}, {ts})"
            else:
                q = (
                    f"SELECT count(*) FROM sessions s "
                    f"WHERE s.segment = {seg} "
                    f"AND s.started_at <= {ts} "
                    f"AND (s.ended_at IS NULL OR s.ended_at > {ts})"
                )
            t0 = time.perf_counter()
            cur.execute(q)
            cur.fetchone()
            lat.append((time.perf_counter() - t0) * 1000.0)
    out["lat_ms"] = lat
    out["n"] = len(lat)


def writer_loop(seconds: float, out: dict, stop: threading.Event):
    rng = random.Random(threading.get_ident() ^ 0xC0FFEE)
    n = 0
    errs = 0
    with connect() as conn, conn.cursor() as cur:
        end = time.perf_counter() + seconds
        while time.perf_counter() < end and not stop.is_set():
            op = rng.choice(["I", "I", "U", "D", "M"])  # M = move segment
            seg = _pick_local(rng)
            try:
                if op == "I":
                    cur.execute(
                        """
                        INSERT INTO sessions(segment, started_at, ended_at)
                        VALUES (
                          %s,
                          now() - (%s || ' minutes')::interval,
                          CASE WHEN %s THEN NULL ELSE now() END
                        )
                        """,
                        (seg, rng.randint(1, 5000), rng.random() < 0.2),
                    )
                elif op == "U":
                    cur.execute(
                        """
                        UPDATE sessions SET ended_at = now()
                        WHERE id = (
                          SELECT id FROM sessions TABLESAMPLE SYSTEM (1)
                           WHERE segment = %s
                           LIMIT 1
                        )
                        """,
                        (seg,),
                    )
                elif op == "M" and SEGMENTS > 1:
                    new_seg = (seg + 1) % SEGMENTS
                    cur.execute(
                        """
                        UPDATE sessions SET segment = %s
                        WHERE id = (
                          SELECT id FROM sessions TABLESAMPLE SYSTEM (1)
                           WHERE segment = %s
                           LIMIT 1
                        )
                        """,
                        (new_seg, seg),
                    )
                else:
                    cur.execute(
                        """
                        DELETE FROM sessions
                        WHERE id = (
                          SELECT id FROM sessions TABLESAMPLE SYSTEM (0.5)
                           WHERE segment = %s
                           LIMIT 1
                        )
                        """,
                        (seg,),
                    )
                n += 1
            except Exception:
                errs += 1
                conn.rollback()
                conn.autocommit = True
    out["writes"] = n
    out["errs"] = errs


def maint_loop(seconds: float, out: dict, stop: threading.Event):
    actions = []
    if not MAINT:
        out["actions"] = actions
        return
    with connect() as conn, conn.cursor() as cur:
        end = time.perf_counter() + seconds
        seg = 0
        while time.perf_counter() < end and not stop.is_set():
            rel = f"sessions_seg_{seg}"
            try:
                cur.execute("SET lock_timeout = '250ms'")
                cur.execute("SET statement_timeout = '3s'")
                cur.execute(
                    """
                    SELECT * FROM tci.maintain(
                      %s::regclass, 4096, 8, 1500, 64,
                      8192, true, 'pairwise')
                    """,
                    (rel,),
                )
                actions.append((rel, list(cur.fetchone())))
            except Exception as e:
                actions.append((rel, f"err:{str(e)[:120]}"))
                conn.rollback()
                conn.autocommit = True
            seg = (seg + 1) % SEGMENTS
            time.sleep(0.2)
    out["actions"] = actions


def checker_loop(seconds: float, out: dict, stop: threading.Event):
    """Periodic same-snapshot exactness under REPEATABLE READ."""
    mismatches = 0
    checks = 0
    rng = random.Random(0xA11CE)
    conn = connect()
    conn.autocommit = False
    try:
        cur = conn.cursor()
        end = time.perf_counter() + seconds
        while time.perf_counter() < end and not stop.is_set():
            seg = _pick_local(rng)
            ts = probe_ts(rng)
            try:
                cur.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
                )
                cur.execute(
                    f"SELECT tci_spike.count_at_segment({seg}, {ts})"
                )
                c_tci = cur.fetchone()[0]
                cur.execute(
                    f"""
                    SELECT count(*) FROM sessions s
                     WHERE s.segment = {seg}
                       AND s.started_at <= {ts}
                       AND (s.ended_at IS NULL OR s.ended_at > {ts})
                    """
                )
                c_nat = cur.fetchone()[0]
                conn.commit()
                checks += 1
                if c_tci != c_nat:
                    mismatches += 1
                    print(f"MISMATCH seg={seg} tci={c_tci} native={c_nat}")
            except Exception as e:
                conn.rollback()
                print(f"checker err: {e}")
            time.sleep(0.5)
        cur.close()
    finally:
        conn.close()
    out["checks"] = checks
    out["mismatches"] = mismatches


def run_mode(mode: str) -> dict:
    print(f"\n== mode={mode} readers={READERS} writers={WRITERS} maint={MAINT} ==")
    stop = threading.Event()
    readers = [{} for _ in range(READERS)]
    writers = [{} for _ in range(WRITERS)]
    maint_out: dict = {}
    check_out: dict = {}

    def spawn(seconds):
        threads = []
        for o in readers:
            t = threading.Thread(
                target=reader_loop, args=(mode, seconds, o, stop), daemon=True
            )
            threads.append(t)
        for o in writers:
            t = threading.Thread(
                target=writer_loop, args=(seconds, o, stop), daemon=True
            )
            threads.append(t)
        threads.append(
            threading.Thread(
                target=maint_loop, args=(seconds, maint_out, stop), daemon=True
            )
        )
        threads.append(
            threading.Thread(
                target=checker_loop, args=(seconds, check_out, stop), daemon=True
            )
        )
        for t in threads:
            t.start()
        return threads

    # warmup
    tw = spawn(WARMUP_S)
    time.sleep(WARMUP_S)
    stop.set()
    for t in tw:
        t.join(timeout=5)

    # reset reader outs for measured run
    stop = threading.Event()
    readers = [{} for _ in range(READERS)]
    writers = [{} for _ in range(WRITERS)]
    maint_out = {}
    check_out = {}
    tr = []
    for o in readers:
        t = threading.Thread(
            target=reader_loop, args=(mode, RUN_S, o, stop), daemon=True
        )
        tr.append(t)
    for o in writers:
        t = threading.Thread(
            target=writer_loop, args=(RUN_S, o, stop), daemon=True
        )
        tr.append(t)
    tr.append(
        threading.Thread(
            target=maint_loop, args=(RUN_S, maint_out, stop), daemon=True
        )
    )
    tr.append(
        threading.Thread(
            target=checker_loop, args=(RUN_S, check_out, stop), daemon=True
        )
    )
    t0 = time.perf_counter()
    for t in tr:
        t.start()
    time.sleep(RUN_S)
    stop.set()
    for t in tr:
        t.join(timeout=10)
    elapsed = time.perf_counter() - t0

    lat = []
    for o in readers:
        lat.extend(o.get("lat_ms", []))
    writes = sum(o.get("writes", 0) for o in writers)
    werr = sum(o.get("errs", 0) for o in writers)

    # tail / live_runs snapshot
    with connect() as conn, conn.cursor() as cur:
        stats = []
        for i in range(SEGMENTS):
            rel = f"sessions_seg_{i}"
            cur.execute(
                "SELECT n_tail, live_runs FROM tci.stats(%s::regclass)",
                (rel,),
            )
            row = cur.fetchone()
            if row:
                stats.append(
                    {"table": rel, "n_tail": row[0], "live_runs": row[1]}
                )
        cur.execute("SELECT tci_spike.assert_match()")

    summary = {
        "mode": mode,
        "elapsed_s": elapsed,
        "read_latency_ms": summarize(lat),
        "writes": writes,
        "write_errs": werr,
        "writes_per_s": writes / elapsed if elapsed else None,
        "checker": check_out,
        "maint_actions": len(maint_out.get("actions", [])),
        "slice_stats": stats,
    }
    print(json.dumps(summary, indent=2, default=str))
    return summary


def main():
    Path(OUT).parent.mkdir(parents=True, exist_ok=True)
    setup()
    results = {
        "config": {
            "rows": ROWS,
            "segments": SEGMENTS,
            "skew": SKEW,
            "readers": READERS,
            "writers": WRITERS,
            "warmup_s": WARMUP_S,
            "run_s": RUN_S,
            "maint": MAINT,
        },
        "modes": {},
    }
    for mode in ("tci", "native"):
        # reinstall between modes for fair tails
        setup()
        results["modes"][mode] = run_mode(mode)

    with open(OUT, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nwrote {OUT}")

    tci_p95 = results["modes"]["tci"]["read_latency_ms"]["p95"]
    nat_p95 = results["modes"]["native"]["read_latency_ms"]["p95"]
    mm = results["modes"]["tci"]["checker"].get("mismatches", 0)
    print(
        f"\nVERDICT: tci_p95={tci_p95:.3f}ms native_p95={nat_p95:.3f}ms "
        f"mismatches={mm}"
    )


if __name__ == "__main__":
    main()
