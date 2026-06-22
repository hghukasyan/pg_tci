#include "pg_tci.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

const char *
tci_pack_errstr(TciPackError e)
{
	switch (e)
	{
		case TCI_OK: return "ok";
		case TCI_ERR_NULL: return "null input";
		case TCI_ERR_TOO_SHORT: return "buffer too short";
		case TCI_ERR_BAD_MAGIC: return "bad magic";
		case TCI_ERR_BAD_VERSION: return "bad version";
		case TCI_ERR_BAD_INTERVAL: return "bad checkpoint interval";
		case TCI_ERR_BAD_COUNTS: return "bad entry/checkpoint counts";
		case TCI_ERR_BAD_OFFSET: return "bad offset";
		case TCI_ERR_TRUNCATED: return "truncated buffer";
		case TCI_ERR_OVERFLOW: return "integer overflow";
		case TCI_ERR_MALFORMED: return "malformed varint/stream";
		default: return "unknown error";
	}
}

bool
tci_read_uvarint(const uint8_t *buf, size_t len, size_t *off, uint64_t *out)
{
	uint64_t result = 0;
	unsigned shift = 0;
	size_t i = *off;

	while (i < len && shift <= 63)
	{
		uint8_t b = buf[i++];
		result |= (uint64_t)(b & 0x7f) << shift;
		if ((b & 0x80) == 0)
		{
			*off = i;
			*out = result;
			return true;
		}
		shift += 7;
		if (shift >= 64)
			return false;
	}
	return false;
}

bool
tci_read_zigzag(const uint8_t *buf, size_t len, size_t *off, int64_t *out)
{
	uint64_t u;
	if (!tci_read_uvarint(buf, len, off, &u))
		return false;
	/* zigzag decode; check that u fits signed mapping */
	*out = (int64_t)((u >> 1) ^ (~(u & 1) + 1));
	return true;
}

bool
tci_write_uvarint(uint8_t *buf, size_t cap, size_t *off, uint64_t v)
{
	size_t i = *off;
	while (v >= 0x80)
	{
		if (i >= cap)
			return false;
		buf[i++] = (uint8_t)(v | 0x80);
		v >>= 7;
	}
	if (i >= cap)
		return false;
	buf[i++] = (uint8_t)v;
	*off = i;
	return true;
}

bool
tci_write_zigzag(uint8_t *buf, size_t cap, size_t *off, int64_t v)
{
	uint64_t u = ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
	return tci_write_uvarint(buf, cap, off, u);
}

static bool
add_i64_ok(int64_t a, int64_t b, int64_t *out)
{
	if (b > 0 && a > INT64_MAX - b)
		return false;
	if (b < 0 && a < INT64_MIN - b)
		return false;
	*out = a + b;
	return true;
}

static TciPackError
validate_header(const uint8_t *data, size_t len, TciPackHeader *hdr,
		size_t *cp_bytes, size_t *entries_end)
{
	uint32_t expect_cp;

	if (data == NULL)
		return TCI_ERR_NULL;
	if (len < TCI_PACK_HDR_SIZE)
		return TCI_ERR_TOO_SHORT;

	memcpy(hdr, data, TCI_PACK_HDR_SIZE);
	if (hdr->magic != TCI_PACK_MAGIC)
		return TCI_ERR_BAD_MAGIC;
	if (hdr->version != TCI_PACK_VERSION)
		return TCI_ERR_BAD_VERSION;
	if (hdr->cp_interval != 32 && hdr->cp_interval != 64 &&
		hdr->cp_interval != 128)
		return TCI_ERR_BAD_INTERVAL;

	if (hdr->n_entries == 0)
	{
		/* empty chunk: allowed, no checkpoints */
		if (hdr->n_checkpoints != 0)
			return TCI_ERR_BAD_COUNTS;
		*cp_bytes = 0;
		*entries_end = TCI_PACK_HDR_SIZE;
		return TCI_OK;
	}

	/* expected checkpoints = ceil(n / interval) */
	expect_cp =
		(hdr->n_entries + hdr->cp_interval - 1) / hdr->cp_interval;
	if (hdr->n_checkpoints != expect_cp || hdr->n_checkpoints == 0)
		return TCI_ERR_BAD_COUNTS;

	*cp_bytes = (size_t)hdr->n_checkpoints * TCI_PACK_CP_SIZE;
	if (TCI_PACK_HDR_SIZE + *cp_bytes > len)
		return TCI_ERR_TRUNCATED;

	if (hdr->entries_offset < TCI_PACK_HDR_SIZE + *cp_bytes ||
		hdr->entries_offset > len)
		return TCI_ERR_BAD_OFFSET;

	*entries_end = len;
	return TCI_OK;
}

TciPackError
tci_chunk_prefix_at(const uint8_t *data, size_t len, int64_t target_us,
		    int64_t *out_prefix)
{
	TciPackHeader hdr;
	size_t cp_bytes = 0, entries_end = 0;
	TciPackError err;
	const TciPackCheckpoint *cps;
	const TciPackCheckpoint *cp;
	const uint8_t *base;
	uint32_t i;
	uint32_t lo;
	uint32_t hi;
	uint32_t mid;
	uint32_t idx;
	uint32_t idx_end;
	int64_t prefix;
	int64_t cur_ts;
	int64_t next_ts;
	int64_t next_prefix;
	int64_t dlt;
	uint64_t dts;
	size_t off;
	size_t blen;

	err = validate_header(data, len, &hdr, &cp_bytes, &entries_end);
	if (err != TCI_OK)
		return err;

	if (hdr.n_entries == 0)
	{
		*out_prefix = 0;
		return TCI_OK;
	}

	cps = (const TciPackCheckpoint *)(data + TCI_PACK_HDR_SIZE);

	/* Verify checkpoint offsets are monotonic and in range */
	for (i = 0; i < hdr.n_checkpoints; i++)
	{
		if (cps[i].entry_index >= hdr.n_entries)
			return TCI_ERR_BAD_OFFSET;
		if ((size_t)hdr.entries_offset + cps[i].payload_off > len)
			return TCI_ERR_BAD_OFFSET;
		if (i > 0)
		{
			if (cps[i].entry_index <= cps[i - 1].entry_index)
				return TCI_ERR_MALFORMED;
			if (cps[i].payload_off < cps[i - 1].payload_off)
				return TCI_ERR_MALFORMED;
			if (cps[i].ts_us < cps[i - 1].ts_us)
				return TCI_ERR_MALFORMED;
		}
	}

	/* Before first entry */
	if (target_us < cps[0].ts_us)
	{
		*out_prefix = 0;
		return TCI_OK;
	}

	/* Binary search: last checkpoint with ts_us <= target */
	lo = 0;
	hi = hdr.n_checkpoints;
	while (lo + 1 < hi)
	{
		mid = lo + (hi - lo) / 2;
		if (cps[mid].ts_us <= target_us)
			lo = mid;
		else
			hi = mid;
	}

	cp = &cps[lo];
	prefix = cp->prefix_before;
	cur_ts = cp->ts_us;
	idx = cp->entry_index;
	idx_end = (lo + 1 < hdr.n_checkpoints)
				  ? cps[lo + 1].entry_index
				  : hdr.n_entries;
	off = (size_t)hdr.entries_offset + cp->payload_off;
	base = data;
	blen = len;

	/* Last accepted prefix (entries with ts <= target). */
	*out_prefix = cp->prefix_before;

	/*
	 * First entry of the block: ts = cp->ts_us, encoded as uvarint(0) + zigzag(delta)
	 * Subsequent: uvarint(ts - prev) + zigzag(delta)
	 */
	for (i = idx; i < idx_end; i++)
	{
		if (!tci_read_uvarint(base, blen, &off, &dts))
			return TCI_ERR_TRUNCATED;
		if (!tci_read_zigzag(base, blen, &off, &dlt))
			return TCI_ERR_TRUNCATED;

		if (i == idx)
		{
			if (dts != 0)
				return TCI_ERR_MALFORMED;
			cur_ts = cp->ts_us;
		}
		else
		{
			if (dts > (uint64_t)INT64_MAX)
				return TCI_ERR_OVERFLOW;
			if (!add_i64_ok(cur_ts, (int64_t)dts, &next_ts))
				return TCI_ERR_OVERFLOW;
			cur_ts = next_ts;
		}

		if (cur_ts > target_us)
			return TCI_OK;

		if (!add_i64_ok(prefix, dlt, &next_prefix))
			return TCI_ERR_OVERFLOW;
		prefix = next_prefix;
		*out_prefix = prefix;
	}

	return TCI_OK;
}

TciPackError
tci_pack_entries(const int64_t *ts_us, const int16_t *deltas, uint32_t n,
		 uint16_t cp_interval, uint8_t **out, size_t *out_len)
{
	uint32_t n_cp;
	uint32_t i;
	size_t hdr_cp;
	size_t cap;
	uint8_t *buf;
	TciPackHeader hdr;
	TciPackCheckpoint *cps;
	size_t off;
	int64_t prefix;
	int64_t prev_ts;

	if (out == NULL || out_len == NULL)
		return TCI_ERR_NULL;
	*out = NULL;
	*out_len = 0;

	if (cp_interval != 32 && cp_interval != 64 && cp_interval != 128)
		return TCI_ERR_BAD_INTERVAL;

	if (n > 0 && (ts_us == NULL || deltas == NULL))
		return TCI_ERR_NULL;

	/* timestamps must be non-decreasing */
	for (i = 1; i < n; i++)
	{
		if (ts_us[i] < ts_us[i - 1])
			return TCI_ERR_MALFORMED;
	}

	n_cp = (n == 0) ? 0 : (n + cp_interval - 1) / cp_interval;
	hdr_cp = TCI_PACK_HDR_SIZE + (size_t)n_cp * TCI_PACK_CP_SIZE;

	/* Worst case ~10 bytes/varint pair * n + headroom */
	cap = hdr_cp + (size_t)n * 20 + 64;
	buf = malloc(cap);
	if (!buf)
		return TCI_ERR_OVERFLOW;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = TCI_PACK_MAGIC;
	hdr.version = TCI_PACK_VERSION;
	hdr.cp_interval = cp_interval;
	hdr.n_entries = n;
	hdr.n_checkpoints = n_cp;
	hdr.entries_offset = (uint32_t)hdr_cp;
	memcpy(buf, &hdr, TCI_PACK_HDR_SIZE);

	cps = (TciPackCheckpoint *)(buf + TCI_PACK_HDR_SIZE);
	off = hdr_cp;
	prefix = 0;
	prev_ts = 0;

	for (i = 0; i < n; i++)
	{
		uint32_t ci;
		uint64_t dts;
		int64_t d;
		int64_t np;
		size_t ncap;
		uint8_t *nbuf;

		if (i % cp_interval == 0)
		{
			ci = i / cp_interval;
			cps[ci].ts_us = ts_us[i];
			cps[ci].prefix_before = prefix;
			cps[ci].entry_index = i;
			cps[ci].payload_off = (uint32_t)(off - hdr_cp);
		}

		if (i % cp_interval == 0)
			dts = 0;
		else
		{
			d = ts_us[i] - prev_ts;
			if (d < 0)
			{
				free(buf);
				return TCI_ERR_MALFORMED;
			}
			dts = (uint64_t)d;
		}

		if (!tci_write_uvarint(buf, cap, &off, dts) ||
			!tci_write_zigzag(buf, cap, &off, (int64_t)deltas[i]))
		{
			/* grow */
			ncap = cap * 2;
			nbuf = realloc(buf, ncap);
			if (!nbuf)
			{
				free(buf);
				return TCI_ERR_OVERFLOW;
			}
			buf = nbuf;
			cap = ncap;
			cps = (TciPackCheckpoint *)(buf + TCI_PACK_HDR_SIZE);
			if (!tci_write_uvarint(buf, cap, &off, dts) ||
				!tci_write_zigzag(buf, cap, &off, (int64_t)deltas[i]))
			{
				free(buf);
				return TCI_ERR_OVERFLOW;
			}
		}

		if (!add_i64_ok(prefix, (int64_t)deltas[i], &np))
		{
			free(buf);
			return TCI_ERR_OVERFLOW;
		}
		prefix = np;
		prev_ts = ts_us[i];
	}

	*out = buf;
	*out_len = off;
	return TCI_OK;
}

TciPackError
tci_unpack_entries(const uint8_t *data, size_t len, int64_t **out_ts,
		   int16_t **out_deltas, uint32_t *out_n)
{
	TciPackHeader hdr;
	size_t cp_bytes = 0, entries_end = 0;
	TciPackError err;
	const TciPackCheckpoint *cps;
	int64_t *ts;
	int16_t *ds;
	uint32_t ci;
	uint32_t i;
	uint32_t idx;
	uint32_t idx_end;
	uint64_t dts;
	int64_t dlt;
	int64_t next_ts;
	int64_t cur_ts;
	size_t off;

	*out_ts = NULL;
	*out_deltas = NULL;
	*out_n = 0;

	err = validate_header(data, len, &hdr, &cp_bytes, &entries_end);
	if (err != TCI_OK)
		return err;

	if (hdr.n_entries == 0)
		return TCI_OK;

	cps = (const TciPackCheckpoint *)(data + TCI_PACK_HDR_SIZE);
	ts = malloc(sizeof(int64_t) * hdr.n_entries);
	ds = malloc(sizeof(int16_t) * hdr.n_entries);
	if (!ts || !ds)
	{
		free(ts);
		free(ds);
		return TCI_ERR_OVERFLOW;
	}

	for (ci = 0; ci < hdr.n_checkpoints; ci++)
	{
		idx = cps[ci].entry_index;
		idx_end = (ci + 1 < hdr.n_checkpoints)
					  ? cps[ci + 1].entry_index
					  : hdr.n_entries;
		off = (size_t)hdr.entries_offset + cps[ci].payload_off;
		cur_ts = cps[ci].ts_us;

		for (i = idx; i < idx_end; i++)
		{
			if (!tci_read_uvarint(data, len, &off, &dts) ||
				!tci_read_zigzag(data, len, &off, &dlt))
			{
				free(ts);
				free(ds);
				return TCI_ERR_TRUNCATED;
			}
			if (i == idx)
			{
				if (dts != 0)
				{
					free(ts);
					free(ds);
					return TCI_ERR_MALFORMED;
				}
				cur_ts = cps[ci].ts_us;
			}
			else
			{
				if (dts > (uint64_t)INT64_MAX ||
					!add_i64_ok(cur_ts, (int64_t)dts, &next_ts))
				{
					free(ts);
					free(ds);
					return TCI_ERR_OVERFLOW;
				}
				cur_ts = next_ts;
			}
			if (dlt < INT16_MIN || dlt > INT16_MAX)
			{
				free(ts);
				free(ds);
				return TCI_ERR_OVERFLOW;
			}
			ts[i] = cur_ts;
			ds[i] = (int16_t)dlt;
		}
	}

	*out_ts = ts;
	*out_deltas = ds;
	*out_n = hdr.n_entries;
	return TCI_OK;
}
