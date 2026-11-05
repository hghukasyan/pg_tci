-- pg_tci — SEGMENT SPIKE with write-sync (experiment, not product API)
--
-- Approximate filtered count_at(segment, ts) via one slice table + TCI per
-- fixed segment. Writers touch only `sessions`; a trigger mirrors into slices.
--
-- Prerequisites: CREATE EXTENSION pg_tci;

CREATE EXTENSION IF NOT EXISTS pg_tci;
CREATE SCHEMA IF NOT EXISTS tci_spike;

\ir ../benchmark/segment_spike_lib.sql

SELECT tci_spike.install(n_segments := 3, n_rows := 0, skew := 'uniform');
-- install(0 rows) still builds empty slices + trigger; seed manually:

INSERT INTO sessions (segment, started_at, ended_at) VALUES
  (0, '2024-06-01 09:00+00', '2024-06-01 10:00+00'),
  (0, '2024-06-01 09:30+00', NULL),
  (1, '2024-06-01 09:00+00', '2024-06-01 11:00+00'),
  (1, '2024-06-01 10:00+00', '2024-06-01 10:30+00'),
  (2, '2024-06-01 08:00+00', '2024-06-01 12:00+00');

-- Rebuild TCI after seed (trigger already filled slices)
SELECT tci.rebuild('sessions_seg_0'::regclass);
SELECT tci.rebuild('sessions_seg_1'::regclass);
SELECT tci.rebuild('sessions_seg_2'::regclass);

SELECT seg,
       tci_spike.count_at_segment(seg, ts) AS tci,
       (SELECT count(*) FROM sessions s
         WHERE s.segment = seg
           AND s.started_at <= ts
           AND (s.ended_at IS NULL OR s.ended_at > ts)) AS native
FROM (VALUES
  (0, timestamptz '2024-06-01 09:45+00'),
  (1, timestamptz '2024-06-01 09:45+00'),
  (2, timestamptz '2024-06-01 09:45+00')
) AS q(seg, ts);

-- Live write through sync trigger
INSERT INTO sessions (segment, started_at, ended_at)
VALUES (0, '2024-06-01 09:40+00', '2024-06-01 10:00+00');

SELECT tci_spike.assert_match(timestamptz '2024-06-01 09:45+00');
SELECT * FROM tci.stats('sessions_seg_0'::regclass);
