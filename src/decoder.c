/*
 * Native packed-run prefix decoder entry points.
 *
 * tci_chunk_prefix_at() is implemented in codec.c next to TCIP pack/unpack
 * so header validation stays single-sourced. This translation unit exists
 * for the frozen PGXS layout (src/decoder.c) and future decoder-only work
 * without changing the TCIP v1 contract.
 */
#include "pg_tci.h"

typedef TciPackError (*tci_decoder_fn)(const uint8_t *, size_t, int64_t, int64_t *);

static tci_decoder_fn
tci_get_chunk_prefix_fn(void)
{
	return tci_chunk_prefix_at;
}

/*
 * Keep a live edge into the decoder symbol table. Not part of the SQL API.
 */
void
pg_tci_decoder_touch(void)
{
	(void) tci_get_chunk_prefix_fn();
}
