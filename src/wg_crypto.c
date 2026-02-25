/*
 * WireGuard crypto wrappers
 *
 * Implements Hash, Mac, Hmac, Kdf, Aead, DH, and Timestamp
 * as defined in the WireGuard whitepaper.
 */

#include "wg_crypto.h"
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

/* Curve25519 basepoint */
static const uchar basepoint[32] = { 9 };

/* Hash(input) = BLAKE2s(input, 32) */
void
wg_hash(uchar out[WG_HASH_LEN], const uchar *in, size_t inlen)
{
	blake2s(out, WG_HASH_LEN, in, inlen);
}

/* Mac(key, input) = Keyed-BLAKE2s(key, input, 16) */
void
wg_mac(uchar out[WG_MAC_LEN], const uchar *key, size_t keylen,
       const uchar *in, size_t inlen)
{
	blake2s_keyed(out, WG_MAC_LEN, in, inlen, key, keylen);
}

/*
 * HMAC-BLAKE2s per RFC 2104.
 *
 * We implement this from scratch because libsec's hmac_x expects
 * a DigestState-based hash callback, and our BLAKE2s uses its own
 * state type.
 *
 * Block size = 64 (BLAKE2s block size)
 * Output size = 32 (BLAKE2s hash size)
 */
void
wg_hmac(uchar out[WG_HASH_LEN], const uchar *key, size_t keylen,
        const uchar *in, size_t inlen)
{
	uchar kblock[BLAKE2S_BLOCKBYTES];
	uchar ipad[BLAKE2S_BLOCKBYTES];
	uchar opad[BLAKE2S_BLOCKBYTES];
	uchar inner[WG_HASH_LEN];
	Blake2s S;
	int i;

	/* If key > block size, hash it first */
	if(keylen > BLAKE2S_BLOCKBYTES){
		blake2s(kblock, WG_HASH_LEN, key, keylen);
		memset(kblock + WG_HASH_LEN, 0, BLAKE2S_BLOCKBYTES - WG_HASH_LEN);
	} else {
		memcpy(kblock, key, keylen);
		memset(kblock + keylen, 0, BLAKE2S_BLOCKBYTES - keylen);
	}

	/* Compute ipad and opad */
	for(i = 0; i < BLAKE2S_BLOCKBYTES; i++){
		ipad[i] = kblock[i] ^ 0x36;
		opad[i] = kblock[i] ^ 0x5c;
	}

	/* inner = BLAKE2s(ipad || message) */
	blake2s_init(&S, WG_HASH_LEN);
	blake2s_update(&S, ipad, BLAKE2S_BLOCKBYTES);
	blake2s_update(&S, in, inlen);
	blake2s_final(&S, inner, WG_HASH_LEN);

	/* outer = BLAKE2s(opad || inner) */
	blake2s_init(&S, WG_HASH_LEN);
	blake2s_update(&S, opad, BLAKE2S_BLOCKBYTES);
	blake2s_update(&S, inner, WG_HASH_LEN);
	blake2s_final(&S, out, WG_HASH_LEN);

	memset(kblock, 0, sizeof(kblock));
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	memset(inner, 0, sizeof(inner));
}

/*
 * HKDF-BLAKE2s as specified in the WireGuard whitepaper:
 *
 * tau_0 = Hmac(key, input)           — extract
 * tau_1 = Hmac(tau_0, 0x01)          — expand, first output
 * tau_2 = Hmac(tau_0, tau_1 || 0x02) — expand, second output
 * tau_3 = Hmac(tau_0, tau_2 || 0x03) — expand, third output
 */
void
wg_kdf1(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
        uchar out1[WG_HASH_LEN])
{
	uchar tau0[WG_HASH_LEN];
	uchar one = 0x01;

	wg_hmac(tau0, C, WG_HASH_LEN, input, inlen);
	wg_hmac(out1, tau0, WG_HASH_LEN, &one, 1);

	memset(tau0, 0, sizeof(tau0));
}

void
wg_kdf2(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
        uchar out1[WG_HASH_LEN], uchar out2[WG_HASH_LEN])
{
	uchar tau0[WG_HASH_LEN];
	uchar tmp[WG_HASH_LEN + 1];
	uchar one = 0x01;

	wg_hmac(tau0, C, WG_HASH_LEN, input, inlen);
	wg_hmac(out1, tau0, WG_HASH_LEN, &one, 1);

	memcpy(tmp, out1, WG_HASH_LEN);
	tmp[WG_HASH_LEN] = 0x02;
	wg_hmac(out2, tau0, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);

	memset(tau0, 0, sizeof(tau0));
	memset(tmp, 0, sizeof(tmp));
}

void
wg_kdf3(const uchar C[WG_HASH_LEN], const uchar *input, size_t inlen,
        uchar out1[WG_HASH_LEN], uchar out2[WG_HASH_LEN],
        uchar out3[WG_HASH_LEN])
{
	uchar tau0[WG_HASH_LEN];
	uchar tmp[WG_HASH_LEN + 1];
	uchar one = 0x01;

	wg_hmac(tau0, C, WG_HASH_LEN, input, inlen);
	wg_hmac(out1, tau0, WG_HASH_LEN, &one, 1);

	memcpy(tmp, out1, WG_HASH_LEN);
	tmp[WG_HASH_LEN] = 0x02;
	wg_hmac(out2, tau0, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);

	memcpy(tmp, out2, WG_HASH_LEN);
	tmp[WG_HASH_LEN] = 0x03;
	wg_hmac(out3, tau0, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);

	memset(tau0, 0, sizeof(tau0));
	memset(tmp, 0, sizeof(tmp));
}

/*
 * AEAD encrypt: ChaCha20-Poly1305
 *
 * Nonce = 4 zero bytes || LE64(counter)
 * Output = ciphertext || 16-byte tag
 *
 * The ccpoly_encrypt function encrypts in-place and produces a tag,
 * so we copy plaintext to out first, then encrypt.
 */
void
wg_aead_encrypt(uchar *out, const uchar key[WG_KEY_LEN],
                uint64_t counter,
                const uchar *pt, size_t ptlen,
                const uchar *ad, size_t adlen)
{
	Chachastate cs;
	uchar nonce[12];

	/* nonce = 0x00000000 || LE64(counter) */
	memset(nonce, 0, 4);
	nonce[4]  = (uchar)(counter);
	nonce[5]  = (uchar)(counter >> 8);
	nonce[6]  = (uchar)(counter >> 16);
	nonce[7]  = (uchar)(counter >> 24);
	nonce[8]  = (uchar)(counter >> 32);
	nonce[9]  = (uchar)(counter >> 40);
	nonce[10] = (uchar)(counter >> 48);
	nonce[11] = (uchar)(counter >> 56);

	setupChachastate(&cs, (uchar*)key, 32, nonce, 12, 20);

	/* Copy plaintext to output buffer; ccpoly encrypts in-place */
	if(ptlen > 0)
		memcpy(out, pt, ptlen);

	ccpoly_encrypt(out, (ulong)ptlen, (uchar*)ad, (ulong)adlen,
	               out + ptlen, &cs);

	memset(&cs, 0, sizeof(cs));
}

/*
 * AEAD decrypt: ChaCha20-Poly1305
 *
 * Input = ciphertext || 16-byte tag  (ctlen includes the tag)
 * Returns 0 on success, -1 on authentication failure.
 */
int
wg_aead_decrypt(uchar *out, const uchar key[WG_KEY_LEN],
                uint64_t counter,
                const uchar *ct, size_t ctlen,
                const uchar *ad, size_t adlen)
{
	Chachastate cs;
	uchar nonce[12];
	uchar tag[16];
	size_t ptlen;
	int r;

	if(ctlen < WG_AEAD_TAG_LEN)
		return -1;
	ptlen = ctlen - WG_AEAD_TAG_LEN;

	/* nonce = 0x00000000 || LE64(counter) */
	memset(nonce, 0, 4);
	nonce[4]  = (uchar)(counter);
	nonce[5]  = (uchar)(counter >> 8);
	nonce[6]  = (uchar)(counter >> 16);
	nonce[7]  = (uchar)(counter >> 24);
	nonce[8]  = (uchar)(counter >> 32);
	nonce[9]  = (uchar)(counter >> 40);
	nonce[10] = (uchar)(counter >> 48);
	nonce[11] = (uchar)(counter >> 56);

	setupChachastate(&cs, (uchar*)key, 32, nonce, 12, 20);

	/* Copy ciphertext (without tag) to output; ccpoly decrypts in-place */
	if(ptlen > 0)
		memcpy(out, ct, ptlen);
	memcpy(tag, ct + ptlen, WG_AEAD_TAG_LEN);

	r = ccpoly_decrypt(out, (ulong)ptlen, (uchar*)ad, (ulong)adlen,
	                   tag, &cs);

	memset(&cs, 0, sizeof(cs));
	return r;
}

/* DH: Curve25519 point multiplication */
void
wg_dh(uchar out[WG_KEY_LEN], const uchar priv[WG_KEY_LEN],
      const uchar pub[WG_KEY_LEN])
{
	curve25519(out, (uchar*)priv, (uchar*)pub);
}

/*
 * DH key generation.
 * Read 32 random bytes from /dev/urandom, clamp for Curve25519,
 * and derive the public key.
 */
void
wg_dh_generate(uchar priv[WG_KEY_LEN], uchar pub[WG_KEY_LEN])
{
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0){
		fprintf(stderr, "cannot open /dev/urandom\n");
		abort();
	}
	if(read(fd, priv, WG_KEY_LEN) != WG_KEY_LEN){
		fprintf(stderr, "short read from /dev/urandom\n");
		close(fd);
		abort();
	}
	close(fd);

	/* Clamp private key per Curve25519 spec */
	priv[0] &= 248;
	priv[31] &= 127;
	priv[31] |= 64;

	curve25519(pub, priv, (uchar*)basepoint);
}

/*
 * TAI64N timestamp.
 *
 * 8 bytes big-endian: seconds since TAI64 epoch
 *   TAI64 label for Unix epoch 0 = 2^62 = 4611686018427387904
 *   TAI offset from UTC ≈ 37 seconds (as of 2017, unchanged through 2024)
 * 4 bytes big-endian: nanoseconds
 */
void
wg_timestamp(uchar out[WG_TIMESTAMP_LEN])
{
	struct timeval tv;
	uint64_t sec;
	uint32_t nsec;

	gettimeofday(&tv, NULL);

	/* TAI64 base + UTC->TAI offset (37 leap seconds) */
	sec = (uint64_t)4611686018427387914ULL + (uint64_t)tv.tv_sec;
	nsec = (uint32_t)(tv.tv_usec * 1000);

	/* Big-endian seconds */
	out[0] = (uchar)(sec >> 56);
	out[1] = (uchar)(sec >> 48);
	out[2] = (uchar)(sec >> 40);
	out[3] = (uchar)(sec >> 32);
	out[4] = (uchar)(sec >> 24);
	out[5] = (uchar)(sec >> 16);
	out[6] = (uchar)(sec >> 8);
	out[7] = (uchar)(sec);

	/* Big-endian nanoseconds */
	out[8]  = (uchar)(nsec >> 24);
	out[9]  = (uchar)(nsec >> 16);
	out[10] = (uchar)(nsec >> 8);
	out[11] = (uchar)(nsec);
}
