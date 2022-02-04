/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <assert.h>
#include <zlib.h>

#include "fido.h"

#define BOUND (1024UL * 1024UL)
#define GZIP_HEADER_SIZE 16
#define GZIP_ADDITIONAL_WINDOW_BITS 16
// The default level is 8, for further information see https://zlib.net/manual.html.
#define ZLIB_MEM_LEVEL 8
#define ZLIB_CHUNK_SIZE 16384

/**
 * Uses the deflate compression algorithm on the data in |in| and
 * writes it to a buffer |out| (allocated by the caller).
 * It writes the number of bytes used for the compressed data to |out_size|.
 */
static int gzip_deflate(uint8_t *out, uLong *out_size, uint8_t *in, const uLong in_size) {
	int ret, flush;
	z_stream strm;
	uInt byte_counter_consumed, byte_counter_written;

	if (out_size == NULL) {
		return Z_MEM_ERROR;
	}

	// Cannot be used in-place.
	assert((in < out && in + in_size < out) || (in > out));

	// Initialize zlib.
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + GZIP_ADDITIONAL_WINDOW_BITS /* to achieve gzip format */, ZLIB_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		return ret;

	byte_counter_consumed = 0;
	byte_counter_written = 0;
	do {
		size_t bytes_left_in = in_size - byte_counter_consumed;
		size_t bytes_left_out = *out_size - byte_counter_written;
		flush = bytes_left_in < ZLIB_CHUNK_SIZE ? Z_FINISH : Z_NO_FLUSH;
		const uInt avail_in = bytes_left_in > ZLIB_CHUNK_SIZE ? ZLIB_CHUNK_SIZE : (uInt)bytes_left_in;
		strm.avail_in = avail_in;
		strm.next_in = in + byte_counter_consumed;

		do {
			const uInt avail_out = bytes_left_out > ZLIB_CHUNK_SIZE ? ZLIB_CHUNK_SIZE : (uInt)bytes_left_out;

			// Check whether output buffer is full.
			if (avail_out == 0 && avail_in > 0) {
				(void)deflateEnd(&strm);
				return Z_MEM_ERROR;
			}

			strm.avail_out = avail_out;
			strm.next_out = out + byte_counter_written;

			ret = deflate(&strm, flush);    /* no bad return value */
			assert(ret != Z_STREAM_ERROR);  /* state not clobbered */

			const uInt bytes_compressed = avail_out - strm.avail_out;
			byte_counter_written += bytes_compressed;
			bytes_left_out -= bytes_compressed;
			bytes_left_in -= avail_in;

			// When strm.avail_out == 0, the chunk is filled.
		} while (strm.avail_out == 0);
		// All input bytes should be used.
		assert(strm.avail_in == 0);
	} while (flush != Z_FINISH);
	assert(ret == Z_STREAM_END);

	// Clean up.
	(void)deflateEnd(&strm);
	*out_size = byte_counter_written;
	return Z_OK;
}

/**
 * Uses the inflate decompression algorithm on the data in |in| and
 * writes it to a buffer |out| (allocated by the caller).
 * It writes the number of bytes used for the uncompressed data to |out_size|.
 */
static int gzip_inflate(uint8_t *out, uLong *out_size, uint8_t *in, const uLong in_size) {
	int ret;
	z_stream strm;
	uInt byte_counter_consumed, byte_counter_written;

	if (out_size == NULL) {
		return Z_MEM_ERROR;
	}

	// Cannot be used in-place.
	assert((in < out && in + in_size < out) || (in > out));

	// Initialize zlib.
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = inflateInit2(&strm, MAX_WBITS + GZIP_ADDITIONAL_WINDOW_BITS /* to allow gzip format */);
	if (ret != Z_OK)
		return ret;

	byte_counter_consumed = 0;
	byte_counter_written = 0;
	do {
		const size_t bytes_left_in = in_size - byte_counter_consumed;
		size_t bytes_left_out = *out_size - byte_counter_written;

		const uInt avail_in = bytes_left_in > ZLIB_CHUNK_SIZE ? ZLIB_CHUNK_SIZE : (uInt)bytes_left_in;
		strm.avail_in = avail_in;
		if (strm.avail_in == 0)
			break;

		strm.next_in = in + byte_counter_consumed;

		do {
			const uInt avail_out = bytes_left_out > ZLIB_CHUNK_SIZE ? ZLIB_CHUNK_SIZE : (uInt)bytes_left_out;
			strm.avail_out = avail_out;
			strm.next_out = out + byte_counter_written;

			ret = inflate(&strm, Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;     /* and fall through */
				__attribute__ ((fallthrough));
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)inflateEnd(&strm);
				return ret;
			}

			const uInt bytes_decompressed = avail_out - strm.avail_out;
			bytes_left_out -= bytes_decompressed;
			byte_counter_written += bytes_decompressed;
		} while (strm.avail_out == 0);
	} while (ret != Z_STREAM_END);

	// Clean up.
	(void)inflateEnd(&strm);
	*out_size = byte_counter_written;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

static int
do_compress(fido_blob_t *out, const fido_blob_t *in, size_t origsiz, int decomp)
{
	uLong ilen, olen;
	int r;

	memset(out, 0, sizeof(*out));
	if (in->len > ULONG_MAX || (ilen = (uLong)in->len) > BOUND ||
		origsiz - 1 > ULONG_MAX || (olen = decomp ? ((uLong)origsiz + 1) :
		(compressBound(ilen) + GZIP_HEADER_SIZE)) > BOUND)
		return FIDO_ERR_INVALID_ARGUMENT;
	if ((out->ptr = calloc(1, olen)) == NULL)
		return FIDO_ERR_INTERNAL;
	out->len = olen;
	if (decomp) {
		r = gzip_inflate(out->ptr, &olen, in->ptr, ilen);
	}
	else {
		r = gzip_deflate(out->ptr, &olen, in->ptr, ilen);
	}
	if (r != Z_OK || olen > SIZE_MAX || olen > out->len) {
		fido_blob_reset(out);
		return FIDO_ERR_COMPRESS;
	}
	out->len = olen;

	return FIDO_OK;
}

int
fido_compress(fido_blob_t *out, const fido_blob_t *in)
{
	return do_compress(out, in, 0, 0);
}

int
fido_uncompress(fido_blob_t *out, const fido_blob_t *in, size_t origsiz)
{
	return do_compress(out, in, origsiz, 1);
}
