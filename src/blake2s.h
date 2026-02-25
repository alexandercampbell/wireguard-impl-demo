/*
 * BLAKE2s — RFC 7693 compliant implementation
 * For use in WireGuard for 9front
 *
 * BLAKE2s operates on 32-bit words, producing digests up to 32 bytes.
 * Supports both unkeyed hashing and keyed MAC mode.
 */

#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stddef.h>

/* BLAKE2s constants */
#define BLAKE2S_BLOCKBYTES  64
#define BLAKE2S_OUTBYTES    32
#define BLAKE2S_KEYBYTES    32

typedef unsigned int uint32;
typedef unsigned char uchar;

typedef struct {
	uint32 h[8];                    /* state */
	uint32 t[2];                    /* counter (64-bit, split into two 32-bit words) */
	uint32 f[2];                    /* finalization flags */
	uchar  buf[BLAKE2S_BLOCKBYTES]; /* input buffer */
	size_t buflen;                  /* bytes in buf */
	uchar  outlen;                  /* desired output length */
} Blake2s;

/* Initialize for unkeyed hashing with given output length (1..32) */
int blake2s_init(Blake2s *S, size_t outlen);

/* Initialize for keyed hashing (MAC) with given key and output length */
int blake2s_init_key(Blake2s *S, size_t outlen, const void *key, size_t keylen);

/* Feed data into the hash */
int blake2s_update(Blake2s *S, const void *in, size_t inlen);

/* Produce the final hash output */
int blake2s_final(Blake2s *S, void *out, size_t outlen);

/* One-shot unkeyed hash */
int blake2s(void *out, size_t outlen, const void *in, size_t inlen);

/* One-shot keyed hash (MAC) */
int blake2s_keyed(void *out, size_t outlen, const void *in, size_t inlen,
                  const void *key, size_t keylen);

#endif /* BLAKE2S_H */
