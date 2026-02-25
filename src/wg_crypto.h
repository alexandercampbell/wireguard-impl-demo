/*
 * WireGuard crypto wrappers
 *
 * Implements the cryptographic functions defined in the WireGuard
 * whitepaper (sections 5.4.2–5.4.4) on top of our BLAKE2s and
 * vendored libsec primitives.
 *
 * Hash(input)            = BLAKE2s(input, 32)
 * Mac(key, input)        = Keyed-BLAKE2s(key, input, 16)
 * Hmac(key, input)       = HMAC-BLAKE2s (RFC 2104)
 * Kdf_n(key, input)      = HKDF-BLAKE2s extract+expand
 * Aead(key, ctr, pt, ad) = ChaCha20-Poly1305
 * DH(priv, pub)          = Curve25519
 * Timestamp()            = TAI64N
 */

#ifndef WG_CRYPTO_H
#define WG_CRYPTO_H

#include "blake2s.h"
#include "p9shim.h"

/* WireGuard constants */
#define WG_KEY_LEN       32
#define WG_HASH_LEN      32
#define WG_MAC_LEN       16
#define WG_AEAD_TAG_LEN  16
#define WG_TIMESTAMP_LEN 12

/* Hash(input) = BLAKE2s(input, 32) */
void wg_hash(uchar out[WG_HASH_LEN], const uchar *in, size_t inlen);

/* Mac(key, input) = Keyed-BLAKE2s(key, input, 16) */
void wg_mac(uchar out[WG_MAC_LEN], const uchar *key, size_t keylen,
            const uchar *in, size_t inlen);

/* HMAC-BLAKE2s(key, input) = 32-byte HMAC per RFC 2104 */
void wg_hmac(uchar out[WG_HASH_LEN], const uchar *key, size_t keylen,
             const uchar *in, size_t inlen);

/* KDF functions — HKDF-BLAKE2s extract+expand */
void wg_kdf1(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
             uchar out1[WG_HASH_LEN]);

void wg_kdf2(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
             uchar out1[WG_HASH_LEN], uchar out2[WG_HASH_LEN]);

void wg_kdf3(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
             uchar out1[WG_HASH_LEN], uchar out2[WG_HASH_LEN],
             uchar out3[WG_HASH_LEN]);

/*
 * AEAD encrypt: ChaCha20-Poly1305
 * out must have room for ptlen + 16 bytes (plaintext + tag)
 * nonce = 4 zero bytes || LE64(counter)
 */
void wg_aead_encrypt(uchar *out, const uchar key[WG_KEY_LEN],
                     uint64_t counter,
                     const uchar *pt, size_t ptlen,
                     const uchar *ad, size_t adlen);

/*
 * AEAD decrypt: ChaCha20-Poly1305
 * out must have room for ctlen - 16 bytes
 * Returns 0 on success, -1 on authentication failure
 */
int wg_aead_decrypt(uchar *out, const uchar key[WG_KEY_LEN],
                    uint64_t counter,
                    const uchar *ct, size_t ctlen,
                    const uchar *ad, size_t adlen);

/* DH: Curve25519 point multiplication */
void wg_dh(uchar out[WG_KEY_LEN], const uchar priv[WG_KEY_LEN],
           const uchar pub[WG_KEY_LEN]);

/* DH key generation: random private key + derive public key */
void wg_dh_generate(uchar priv[WG_KEY_LEN], uchar pub[WG_KEY_LEN]);

/* TAI64N timestamp: 12 bytes */
void wg_timestamp(uchar out[WG_TIMESTAMP_LEN]);

#endif /* WG_CRYPTO_H */
