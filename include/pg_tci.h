/*
 * pg_tci — Temporal Coverage Index (preview)
 * TCIP v1 packed chunk codec + decoder. Not an Index Access Method.
 */
#ifndef PG_TCI_H
#define PG_TCI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---- TCIP v1 binary contract (frozen) ----
 *
 * Endianness: little-endian for all multi-byte fixed integers in header
 *             and checkpoints (host LE assumed; PostgreSQL research target
 *             is LE platforms). Varints are little-endian 7-bit groups.
 * Integers:   fixed fields are unsigned/signed as declared below.
 * Timestamps: int64 microseconds since PostgreSQL epoch
 *             2000-01-01 00:00:00+00 (same as timestamptz_send).
 * Checkpoints: every cp_interval entries (32, 64, or 128 only).
 * Overflow:   int64 add checked; on overflow return TCI_ERR_OVERFLOW.
 * Version:    header.version must equal TCI_PACK_VERSION (1).
 * Corruption: all offsets validated; truncated/malformed → error codes.
 */

#define TCI_PACK_MAGIC     0x50494354u  /* 'TCIP' little-endian bytes T,C,I,P */
#define TCI_PACK_VERSION   1
#define TCI_PACK_HDR_SIZE  24
#define TCI_PACK_CP_SIZE   24

#pragma pack(push, 1)
typedef struct TciPackHeader
{
	uint32_t magic;
	uint8_t  version;
	uint8_t  reserved0;
	uint16_t cp_interval;     /* 32, 64, or 128 */
	uint32_t n_entries;
	uint32_t n_checkpoints;
	uint32_t entries_offset;  /* from start of buffer */
	uint32_t reserved1;
} TciPackHeader;

typedef struct TciPackCheckpoint
{
	int64_t  ts_us;           /* absolute µs of first entry in block */
	int64_t  prefix_before;   /* cumulative delta before that entry */
	uint32_t entry_index;     /* index of first entry in block */
	uint32_t payload_off;     /* offset from entries_offset */
} TciPackCheckpoint;
#pragma pack(pop)

typedef enum TciPackError
{
	TCI_OK = 0,
	TCI_ERR_NULL,
	TCI_ERR_TOO_SHORT,
	TCI_ERR_BAD_MAGIC,
	TCI_ERR_BAD_VERSION,
	TCI_ERR_BAD_INTERVAL,
	TCI_ERR_BAD_COUNTS,
	TCI_ERR_BAD_OFFSET,
	TCI_ERR_TRUNCATED,
	TCI_ERR_OVERFLOW,
	TCI_ERR_MALFORMED
} TciPackError;

bool tci_read_uvarint(const uint8_t *buf, size_t len, size_t *off, uint64_t *out);
bool tci_read_zigzag(const uint8_t *buf, size_t len, size_t *off, int64_t *out);
bool tci_write_uvarint(uint8_t *buf, size_t cap, size_t *off, uint64_t v);
bool tci_write_zigzag(uint8_t *buf, size_t cap, size_t *off, int64_t v);

TciPackError tci_chunk_prefix_at(const uint8_t *data, size_t len,
				 int64_t target_us, int64_t *out_prefix);

TciPackError tci_pack_entries(const int64_t *ts_us, const int16_t *deltas,
			      uint32_t n, uint16_t cp_interval,
			      uint8_t **out, size_t *out_len);

TciPackError tci_unpack_entries(const uint8_t *data, size_t len,
				int64_t **out_ts, int16_t **out_deltas,
				uint32_t *out_n);

const char *tci_pack_errstr(TciPackError e);

/* Layout anchor for src/decoder.c (not exposed via SQL). */
void pg_tci_decoder_touch(void);

/* Optional maintenance bgworker (src/worker.c). */
void pg_tci_worker_init(void);

#endif /* PG_TCI_H */
