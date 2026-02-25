/*
 * BLAKE2s — RFC 7693 compliant implementation
 * Written from scratch for WireGuard on 9front.
 *
 * Reference: RFC 7693, Section 3.2 (BLAKE2s)
 * https://www.rfc-editor.org/rfc/rfc7693
 *
 * BLAKE2s uses 32-bit words, 64-byte blocks, and 10 rounds.
 * The IV values are the first 32 bits of the fractional parts
 * of the square roots of the first 8 primes (same as SHA-256).
 */

#include "blake2s.h"
#include <string.h>

/* IV: first 32 bits of fractional parts of sqrt(2..19) */
static const uint32 blake2s_IV[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

/* Message word permutation schedule (10 rounds) */
static const uchar sigma[10][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/* Load a 32-bit little-endian word from a byte pointer */
static uint32
load32(const void *src)
{
	const uchar *p = (const uchar *)src;
	return ((uint32)p[0])
	     | ((uint32)p[1] << 8)
	     | ((uint32)p[2] << 16)
	     | ((uint32)p[3] << 24);
}

/* Store a 32-bit word in little-endian byte order */
static void
store32(void *dst, uint32 w)
{
	uchar *p = (uchar *)dst;
	p[0] = (uchar)(w);
	p[1] = (uchar)(w >> 8);
	p[2] = (uchar)(w >> 16);
	p[3] = (uchar)(w >> 24);
}

/* Right rotation of a 32-bit word */
static uint32
rotr32(uint32 w, unsigned c)
{
	return (w >> c) | (w << (32 - c));
}

/*
 * The G mixing function, RFC 7693 Section 3.1.
 * Mixes two message words (x, y) into four state words (a, b, c, d).
 * Rotation constants for BLAKE2s: 16, 12, 8, 7.
 */
#define G(r, i, a, b, c, d) do { \
	a = a + b + m[sigma[r][2*i+0]]; \
	d = rotr32(d ^ a, 16); \
	c = c + d; \
	b = rotr32(b ^ c, 12); \
	a = a + b + m[sigma[r][2*i+1]]; \
	d = rotr32(d ^ a, 8); \
	c = c + d; \
	b = rotr32(b ^ c, 7); \
} while(0)

/*
 * Compression function F, RFC 7693 Section 3.2.
 * Compresses one 64-byte block into the state.
 *
 * h:    8-word state
 * block: 64-byte input block
 * t:    128-bit counter (as two 32-bit words, low then high)
 * f:    finalization flag (0xFFFFFFFF if last block, 0 otherwise)
 */
static void
blake2s_compress(Blake2s *S, const uchar block[BLAKE2S_BLOCKBYTES])
{
	uint32 v[16], m[16];
	int i;

	/* Load message block as 16 little-endian 32-bit words */
	for(i = 0; i < 16; i++)
		m[i] = load32(block + i * 4);

	/* Initialize working vector v[0..15] */
	for(i = 0; i < 8; i++)
		v[i] = S->h[i];
	v[8]  = blake2s_IV[0];
	v[9]  = blake2s_IV[1];
	v[10] = blake2s_IV[2];
	v[11] = blake2s_IV[3];
	v[12] = blake2s_IV[4] ^ S->t[0];  /* low 32 bits of counter */
	v[13] = blake2s_IV[5] ^ S->t[1];  /* high 32 bits of counter */
	v[14] = blake2s_IV[6] ^ S->f[0];  /* finalization flag */
	v[15] = blake2s_IV[7] ^ S->f[1];

	/* 10 rounds of mixing */
	for(i = 0; i < 10; i++){
		/* Column step */
		G(i, 0, v[ 0], v[ 4], v[ 8], v[12]);
		G(i, 1, v[ 1], v[ 5], v[ 9], v[13]);
		G(i, 2, v[ 2], v[ 6], v[10], v[14]);
		G(i, 3, v[ 3], v[ 7], v[11], v[15]);
		/* Diagonal step */
		G(i, 4, v[ 0], v[ 5], v[10], v[15]);
		G(i, 5, v[ 1], v[ 6], v[11], v[12]);
		G(i, 6, v[ 2], v[ 7], v[ 8], v[13]);
		G(i, 7, v[ 3], v[ 4], v[ 9], v[14]);
	}

	/* Finalize: h[i] = h[i] ^ v[i] ^ v[i+8] */
	for(i = 0; i < 8; i++)
		S->h[i] ^= v[i] ^ v[i + 8];
}

/* Increment the 64-bit counter by inc bytes */
static void
blake2s_increment_counter(Blake2s *S, uint32 inc)
{
	S->t[0] += inc;
	if(S->t[0] < inc)  /* carry */
		S->t[1]++;
}

/* Set the last-block flag */
static void
blake2s_set_lastblock(Blake2s *S)
{
	S->f[0] = 0xFFFFFFFFUL;
}

int
blake2s_init(Blake2s *S, size_t outlen)
{
	int i;

	if(outlen == 0 || outlen > BLAKE2S_OUTBYTES)
		return -1;

	memset(S, 0, sizeof(Blake2s));

	for(i = 0; i < 8; i++)
		S->h[i] = blake2s_IV[i];

	/*
	 * Parameter block: the first word encodes:
	 *   byte 0: digest length (outlen)
	 *   byte 1: key length (0 for unkeyed)
	 *   byte 2: fanout (1 for sequential)
	 *   byte 3: depth (1 for sequential)
	 *
	 * So p[0] = 0x01010000 ^ outlen for unkeyed sequential mode.
	 */
	S->h[0] ^= 0x01010000UL ^ (uint32)outlen;
	S->outlen = (uchar)outlen;
	return 0;
}

int
blake2s_init_key(Blake2s *S, size_t outlen, const void *key, size_t keylen)
{
	uchar block[BLAKE2S_BLOCKBYTES];
	int i;

	if(outlen == 0 || outlen > BLAKE2S_OUTBYTES)
		return -1;
	if(keylen == 0 || keylen > BLAKE2S_KEYBYTES)
		return -1;

	memset(S, 0, sizeof(Blake2s));

	for(i = 0; i < 8; i++)
		S->h[i] = blake2s_IV[i];

	/* p[0] = 0x01010000 ^ (keylen << 8) ^ outlen */
	S->h[0] ^= 0x01010000UL ^ ((uint32)keylen << 8) ^ (uint32)outlen;
	S->outlen = (uchar)outlen;

	/*
	 * If a key is provided, pad it to a full block and set it as
	 * the first input block. This is how BLAKE2 handles keying:
	 * the key is placed in the first block, zero-padded.
	 */
	memset(block, 0, BLAKE2S_BLOCKBYTES);
	memcpy(block, key, keylen);
	blake2s_update(S, block, BLAKE2S_BLOCKBYTES);

	/* Securely erase key material from stack */
	memset(block, 0, BLAKE2S_BLOCKBYTES);

	return 0;
}

int
blake2s_update(Blake2s *S, const void *in, size_t inlen)
{
	const uchar *pin = (const uchar *)in;
	size_t left, fill;

	if(inlen == 0)
		return 0;

	left = S->buflen;
	fill = BLAKE2S_BLOCKBYTES - left;

	/*
	 * If the buffer plus new data exceeds a block, compress.
	 * We always keep at least one byte in the buffer (or fill it)
	 * so that we know when we're on the last block in _final.
	 */
	/*
	 * If the buffer has data and adding inlen would exceed a block,
	 * fill and compress the buffer first.
	 */
	if(left && inlen > fill){
		memcpy(S->buf + left, pin, fill);
		blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
		blake2s_compress(S, S->buf);
		S->buflen = 0;
		pin += fill;
		inlen -= fill;
		left = 0;
	}

	/*
	 * Compress full blocks from the input, but always leave at least
	 * one byte unprocessed so that _final always has data to compress
	 * as the last (finalized) block.
	 */
	while(inlen > BLAKE2S_BLOCKBYTES){
		blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
		blake2s_compress(S, pin);
		pin += BLAKE2S_BLOCKBYTES;
		inlen -= BLAKE2S_BLOCKBYTES;
	}

	/* Buffer remaining bytes */
	memcpy(S->buf + S->buflen, pin, inlen);
	S->buflen += inlen;

	return 0;
}

int
blake2s_final(Blake2s *S, void *out, size_t outlen)
{
	uchar buffer[BLAKE2S_OUTBYTES];
	int i;

	if(out == NULL || outlen < S->outlen)
		return -1;

	/* Pad the last block with zeros if needed */
	if(S->buflen < BLAKE2S_BLOCKBYTES)
		memset(S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen);

	blake2s_increment_counter(S, (uint32)S->buflen);
	blake2s_set_lastblock(S);
	blake2s_compress(S, S->buf);

	/* Output the hash in little-endian byte order */
	for(i = 0; i < 8; i++)
		store32(buffer + i * 4, S->h[i]);

	memcpy(out, buffer, S->outlen);

	/* Clear sensitive state */
	memset(S, 0, sizeof(Blake2s));
	memset(buffer, 0, sizeof(buffer));

	return 0;
}

int
blake2s(void *out, size_t outlen, const void *in, size_t inlen)
{
	Blake2s S;

	if(blake2s_init(&S, outlen) < 0)
		return -1;
	blake2s_update(&S, in, inlen);
	return blake2s_final(&S, out, outlen);
}

int
blake2s_keyed(void *out, size_t outlen, const void *in, size_t inlen,
              const void *key, size_t keylen)
{
	Blake2s S;

	if(blake2s_init_key(&S, outlen, key, keylen) < 0)
		return -1;
	blake2s_update(&S, in, inlen);
	return blake2s_final(&S, out, outlen);
}
