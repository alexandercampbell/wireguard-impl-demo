/*
 * WireGuard Noise IK handshake — Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * Follows the WireGuard whitepaper sections 5.4.2 and 5.4.3 exactly.
 */

#include "wg_noise.h"
#include <fcntl.h>
#include <unistd.h>

/*
 * Pre-computed initial chaining key and hash:
 *   C_i = Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
 *   H_i = Hash(C_i || "WireGuard v1 zx2c4 Jason@zx2c4.com")
 *
 * We compute these at startup rather than hard-coding so that any
 * change to the construction string propagates automatically.
 */
static uchar initial_chaining_key[32];
static uchar initial_hash[32];
static int   noise_initialized = 0;

static void
noise_init(void)
{
	Blake2s S;
	const char *construction = WG_CONSTRUCTION;
	const char *identifier   = WG_IDENTIFIER;

	if(noise_initialized)
		return;

	/* C = Hash(construction) */
	wg_hash(initial_chaining_key,
	        (const uchar *)construction, strlen(construction));

	/* H = Hash(C || identifier) */
	blake2s_init(&S, 32);
	blake2s_update(&S, initial_chaining_key, 32);
	blake2s_update(&S, (const uchar *)identifier, strlen(identifier));
	blake2s_final(&S, initial_hash, 32);

	noise_initialized = 1;
}

/*
 * Mix hash: H = Hash(H || data)
 */
static void
mix_hash(uchar H[32], const uchar *data, size_t len)
{
	Blake2s S;

	blake2s_init(&S, 32);
	blake2s_update(&S, H, 32);
	blake2s_update(&S, data, len);
	blake2s_final(&S, H, 32);
}

/*
 * Helper: write a 32-bit little-endian value
 */
static void
put_le32(uchar *p, uint32 v)
{
	p[0] = (uchar)(v);
	p[1] = (uchar)(v >> 8);
	p[2] = (uchar)(v >> 16);
	p[3] = (uchar)(v >> 24);
}

/*
 * Helper: read a 32-bit little-endian value
 */
static uint32
get_le32(const uchar *p)
{
	return (uint32)p[0]
	     | ((uint32)p[1] << 8)
	     | ((uint32)p[2] << 16)
	     | ((uint32)p[3] << 24);
}

/*
 * Compute mac1 for a handshake message (section 5.4.4).
 *
 * mac1 = Mac(Hash(LABEL_MAC1 || S_r^pub), msg_before_mac1)
 *
 * mac1 covers all bytes of the message up to (but not including) mac1 itself.
 * mac2 is all zeros for now (no cookie).
 */
static void
compute_mac1(uchar mac1[16], const uchar *msg, size_t msg_len_before_macs,
             const uchar peer_pub[32])
{
	uchar mac1_key[32];
	Blake2s S;

	/* mac1_key = Hash(LABEL_MAC1 || peer's static public key) */
	blake2s_init(&S, 32);
	blake2s_update(&S, (const uchar *)WG_LABEL_MAC1, strlen(WG_LABEL_MAC1));
	blake2s_update(&S, peer_pub, 32);
	blake2s_final(&S, mac1_key, 32);

	/* mac1 = Mac(mac1_key, msg[0..msg_len_before_macs]) */
	wg_mac(mac1, mac1_key, 32, msg, msg_len_before_macs);
}

/*
 * Initiator creates handshake initiation (message 1).
 *
 * Wire format (148 bytes):
 *   [0]      type = 1
 *   [1..3]   reserved = 0
 *   [4..7]   sender_index (LE32)
 *   [8..39]  ephemeral public key (32)
 *   [40..87] encrypted static key (32 + 16 tag)
 *   [88..115] encrypted timestamp (12 + 16 tag)
 *   [116..131] mac1 (16)
 *   [132..147] mac2 (16)
 */
int
wg_handshake_init_create(WgDevice *dev, WgPeer *peer,
                         WgHandshake *hs, uchar msg[WG_INIT_MSG_LEN])
{
	uchar C[32], H[32];
	uchar k[32];
	uchar dh_result[32];
	uchar timestamp[WG_TIMESTAMP_LEN];

	noise_init();
	memset(msg, 0, WG_INIT_MSG_LEN);
	memset(hs, 0, sizeof(*hs));

	/* 1. C = initial_chaining_key */
	memcpy(C, initial_chaining_key, 32);

	/* 2. H = Hash(initial_hash || S_r^pub) — mix in responder's static */
	memcpy(H, initial_hash, 32);
	mix_hash(H, peer->static_pub, 32);

	/* 3. Generate ephemeral keypair */
	wg_dh_generate(hs->ephemeral_priv, hs->ephemeral_pub);

	/* 4. C = Kdf1(C, E_i^pub) */
	wg_kdf1(C, hs->ephemeral_pub, 32, C);

	/* 5. H = Hash(H || E_i^pub) */
	mix_hash(H, hs->ephemeral_pub, 32);

	/* 6. (C, k) = Kdf2(C, DH(E_i^priv, S_r^pub)) */
	wg_dh(dh_result, hs->ephemeral_priv, peer->static_pub);
	wg_kdf2(C, dh_result, 32, C, k);

	/* 7. msg.static = Aead(k, 0, S_i^pub, H)
	 *    → 48 bytes at msg[40..87] */
	wg_aead_encrypt(msg + 40, k, 0,
	                dev->static_pub, 32,
	                H, 32);

	/* 8. H = Hash(H || msg.static) — includes tag */
	mix_hash(H, msg + 40, 48);

	/* 9. (C, k) = Kdf2(C, DH(S_i^priv, S_r^pub)) */
	wg_dh(dh_result, dev->static_priv, peer->static_pub);
	wg_kdf2(C, dh_result, 32, C, k);

	/* 10. msg.timestamp = Aead(k, 0, Timestamp(), H)
	 *     → 28 bytes at msg[88..115] */
	wg_timestamp(timestamp);
	wg_aead_encrypt(msg + 88, k, 0,
	                timestamp, WG_TIMESTAMP_LEN,
	                H, 32);

	/* 11. H = Hash(H || msg.timestamp) — includes tag */
	mix_hash(H, msg + 88, 28);

	/* Save handshake state */
	memcpy(hs->hash, H, 32);
	memcpy(hs->chaining_key, C, 32);

	/* Assign sender index (random) */
	{
		uchar idx_buf[4];
		int fd = open("/dev/urandom", 0);
		if(fd >= 0){
			read(fd, idx_buf, 4);
			close(fd);
		}
		hs->local_index = get_le32(idx_buf);
	}

	/* 12. Fill message header */
	msg[0] = WG_MSG_INIT;
	/* msg[1..3] = 0 (reserved, already zeroed) */
	put_le32(msg + 4, hs->local_index);
	memcpy(msg + 8, hs->ephemeral_pub, 32);
	/* msg[40..87] = encrypted static (already filled) */
	/* msg[88..115] = encrypted timestamp (already filled) */

	/* 13. mac1 */
	compute_mac1(msg + 116, msg, 116, peer->static_pub);

	/* 14. mac2 = zeros (no cookie mechanism yet) */
	/* msg[132..147] already zeroed */

	/* Clean up */
	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(dh_result, 0, sizeof(dh_result));
	memset(timestamp, 0, sizeof(timestamp));

	return 0;
}

/*
 * Responder consumes handshake initiation (message 1).
 *
 * Decrypts and verifies the initiator's static key and timestamp.
 * On success, hs contains the state needed to create the response.
 */
int
wg_handshake_init_consume(WgDevice *dev, WgPeer *peer,
                          WgHandshake *hs, const uchar msg[WG_INIT_MSG_LEN])
{
	uchar C[32], H[32];
	uchar k[32];
	uchar dh_result[32];
	uchar static_dec[32];
	uchar timestamp_dec[WG_TIMESTAMP_LEN];
	uchar mac1_check[16];

	noise_init();
	memset(hs, 0, sizeof(*hs));

	/* Verify message type */
	if(msg[0] != WG_MSG_INIT)
		return -1;

	/* Verify mac1 first */
	compute_mac1(mac1_check, msg, 116, dev->static_pub);
	if(tsmemcmp(mac1_check, (void*)(msg + 116), 16) != 0)
		return -1;

	/* 1. C = initial_chaining_key */
	memcpy(C, initial_chaining_key, 32);

	/* 2. H = Hash(initial_hash || S_r^pub) — our own static public */
	memcpy(H, initial_hash, 32);
	mix_hash(H, dev->static_pub, 32);

	/* 3. Extract initiator's ephemeral from message */
	memcpy(hs->remote_eph_pub, msg + 8, 32);

	/* 4. C = Kdf1(C, E_i^pub) */
	wg_kdf1(C, hs->remote_eph_pub, 32, C);

	/* 5. H = Hash(H || E_i^pub) */
	mix_hash(H, hs->remote_eph_pub, 32);

	/* 6. (C, k) = Kdf2(C, DH(S_r^priv, E_i^pub)) */
	wg_dh(dh_result, dev->static_priv, hs->remote_eph_pub);
	wg_kdf2(C, dh_result, 32, C, k);

	/* 7. Decrypt msg.static = Aead_dec(k, 0, msg[40..87], H) */
	if(wg_aead_decrypt(static_dec, k, 0,
	                   msg + 40, 48,
	                   H, 32) != 0)
		goto fail;

	/* 8. H = Hash(H || msg.static) — the ciphertext, not plaintext */
	mix_hash(H, msg + 40, 48);

	/* Verify that the decrypted static matches the expected peer */
	if(tsmemcmp(static_dec, peer->static_pub, 32) != 0)
		goto fail;

	/* 9. (C, k) = Kdf2(C, DH(S_r^priv, S_i^pub)) */
	wg_dh(dh_result, dev->static_priv, peer->static_pub);
	wg_kdf2(C, dh_result, 32, C, k);

	/* 10. Decrypt msg.timestamp = Aead_dec(k, 0, msg[88..115], H) */
	if(wg_aead_decrypt(timestamp_dec, k, 0,
	                   msg + 88, 28,
	                   H, 32) != 0)
		goto fail;

	/* 11. H = Hash(H || msg.timestamp) — the ciphertext */
	mix_hash(H, msg + 88, 28);

	/* Anti-replay: timestamp must be > latest */
	if(memcmp(timestamp_dec, peer->latest_timestamp, WG_TIMESTAMP_LEN) <= 0
	   && memcmp(peer->latest_timestamp,
	             "\0\0\0\0\0\0\0\0\0\0\0\0", WG_TIMESTAMP_LEN) != 0)
		goto fail;
	memcpy(peer->latest_timestamp, timestamp_dec, WG_TIMESTAMP_LEN);

	/* Save handshake state */
	memcpy(hs->hash, H, 32);
	memcpy(hs->chaining_key, C, 32);
	hs->remote_index = get_le32(msg + 4);

	/* Clean up */
	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(dh_result, 0, sizeof(dh_result));
	return 0;

fail:
	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(dh_result, 0, sizeof(dh_result));
	memset(hs, 0, sizeof(*hs));
	return -1;
}

/*
 * Responder creates handshake response (message 2).
 *
 * Wire format (92 bytes):
 *   [0]      type = 2
 *   [1..3]   reserved = 0
 *   [4..7]   sender_index (LE32)
 *   [8..11]  receiver_index (LE32)
 *   [12..43] ephemeral public key (32)
 *   [44..59] encrypted empty (0 + 16 tag)
 *   [60..75] mac1 (16)
 *   [76..91] mac2 (16)
 */
int
wg_handshake_resp_create(WgDevice *dev, WgPeer *peer,
                         WgHandshake *hs, uchar msg[WG_RESP_MSG_LEN])
{
	uchar C[32], H[32];
	uchar k[32], tau[32];
	uchar dh_result[32];

	(void)dev; /* dev not needed for response creation beyond what's in hs */

	memset(msg, 0, WG_RESP_MSG_LEN);
	memcpy(C, hs->chaining_key, 32);
	memcpy(H, hs->hash, 32);

	/* 1. Generate ephemeral keypair */
	wg_dh_generate(hs->ephemeral_priv, hs->ephemeral_pub);

	/* 2. C = Kdf1(C, E_r^pub) */
	wg_kdf1(C, hs->ephemeral_pub, 32, C);

	/* 3. H = Hash(H || E_r^pub) */
	mix_hash(H, hs->ephemeral_pub, 32);

	/* 4. C = Kdf1(C, DH(E_r^priv, E_i^pub)) */
	wg_dh(dh_result, hs->ephemeral_priv, hs->remote_eph_pub);
	wg_kdf1(C, dh_result, 32, C);

	/* 5. C = Kdf1(C, DH(E_r^priv, S_i^pub)) */
	wg_dh(dh_result, hs->ephemeral_priv, peer->static_pub);
	wg_kdf1(C, dh_result, 32, C);

	/* 6. (C, tau, k) = Kdf3(C, Q) — Q is the preshared key */
	wg_kdf3(C, peer->preshared_key, 32, C, tau, k);

	/* 7. H = Hash(H || tau) */
	mix_hash(H, tau, 32);

	/* 8. msg.empty = Aead(k, 0, "", H) — 0 bytes PT, 16 bytes tag */
	wg_aead_encrypt(msg + 44, k, 0,
	                NULL, 0,
	                H, 32);

	/* 9. H = Hash(H || msg.empty) */
	mix_hash(H, msg + 44, 16);

	/* Save updated state */
	memcpy(hs->hash, H, 32);
	memcpy(hs->chaining_key, C, 32);

	/* Assign sender index */
	{
		uchar idx_buf[4];
		int fd = open("/dev/urandom", 0);
		if(fd >= 0){
			read(fd, idx_buf, 4);
			close(fd);
		}
		hs->local_index = get_le32(idx_buf);
	}

	/* 10. Fill message */
	msg[0] = WG_MSG_RESP;
	put_le32(msg + 4, hs->local_index);
	put_le32(msg + 8, hs->remote_index);
	memcpy(msg + 12, hs->ephemeral_pub, 32);
	/* msg[44..59] = encrypted empty (already filled) */

	/* 11. mac1 */
	compute_mac1(msg + 60, msg, 60, peer->static_pub);

	/* 12. mac2 = zeros (no cookie mechanism) */
	/* msg[76..91] already zeroed */

	/* Clean up */
	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(tau, 0, sizeof(tau));
	memset(dh_result, 0, sizeof(dh_result));

	return 0;
}

/*
 * Initiator consumes handshake response (message 2).
 */
int
wg_handshake_resp_consume(WgDevice *dev, WgPeer *peer,
                          WgHandshake *hs, const uchar msg[WG_RESP_MSG_LEN])
{
	uchar C[32], H[32];
	uchar k[32], tau[32];
	uchar dh_result[32];
	uchar empty_dec[1]; /* decrypt 0 bytes */
	uchar mac1_check[16];

	/* Verify message type */
	if(msg[0] != WG_MSG_RESP)
		return -1;

	/* Verify receiver index matches our sender index */
	if(get_le32(msg + 8) != hs->local_index)
		return -1;

	/* Verify mac1 — response mac1 is keyed with the initiator's (our) static pub */
	compute_mac1(mac1_check, msg, 60, dev->static_pub);
	if(tsmemcmp(mac1_check, (void*)(msg + 60), 16) != 0)
		return -1;

	memcpy(C, hs->chaining_key, 32);
	memcpy(H, hs->hash, 32);

	/* Extract responder's ephemeral */
	memcpy(hs->remote_eph_pub, msg + 12, 32);

	/* 1. C = Kdf1(C, E_r^pub) */
	wg_kdf1(C, hs->remote_eph_pub, 32, C);

	/* 2. H = Hash(H || E_r^pub) */
	mix_hash(H, hs->remote_eph_pub, 32);

	/* 3. C = Kdf1(C, DH(E_i^priv, E_r^pub)) */
	wg_dh(dh_result, hs->ephemeral_priv, hs->remote_eph_pub);
	wg_kdf1(C, dh_result, 32, C);

	/* 4. C = Kdf1(C, DH(S_i^priv, E_r^pub)) */
	wg_dh(dh_result, dev->static_priv, hs->remote_eph_pub);
	wg_kdf1(C, dh_result, 32, C);

	/* 5. (C, tau, k) = Kdf3(C, Q) */
	wg_kdf3(C, peer->preshared_key, 32, C, tau, k);

	/* 6. H = Hash(H || tau) */
	mix_hash(H, tau, 32);

	/* 7. Decrypt msg.empty = Aead_dec(k, 0, msg[44..59], H) */
	if(wg_aead_decrypt(empty_dec, k, 0,
	                   msg + 44, 16,
	                   H, 32) != 0)
		goto fail;

	/* 8. H = Hash(H || msg.empty) */
	mix_hash(H, msg + 44, 16);

	/* Save state */
	memcpy(hs->hash, H, 32);
	memcpy(hs->chaining_key, C, 32);
	hs->remote_index = get_le32(msg + 4);

	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(tau, 0, sizeof(tau));
	memset(dh_result, 0, sizeof(dh_result));
	return 0;

fail:
	memset(C, 0, sizeof(C));
	memset(H, 0, sizeof(H));
	memset(k, 0, sizeof(k));
	memset(tau, 0, sizeof(tau));
	memset(dh_result, 0, sizeof(dh_result));
	return -1;
}

/*
 * Derive transport keys from completed handshake.
 *
 *   (T_send, T_recv) = Kdf2(C, "")
 *
 * The initiator sends with tau_1 and receives with tau_2;
 * the responder sends with tau_2 and receives with tau_1.
 */
void
wg_derive_keypair(WgHandshake *hs, WgKeypair *kp, int is_initiator)
{
	uchar t1[32], t2[32];

	wg_kdf2(hs->chaining_key, (const uchar *)"", 0, t1, t2);

	/*
	 * The initiator sends with tau_1 and receives with tau_2.
	 * The responder sends with tau_2 and receives with tau_1.
	 */
	if(is_initiator){
		memcpy(kp->send_key, t1, 32);
		memcpy(kp->recv_key, t2, 32);
	} else {
		memcpy(kp->send_key, t2, 32);
		memcpy(kp->recv_key, t1, 32);
	}
	kp->send_nonce = 0;
	kp->recv_nonce = 0;
	kp->is_initiator = is_initiator;

	/* Zero handshake secrets */
	memset(hs->ephemeral_priv, 0, 32);
	memset(hs->chaining_key, 0, 32);
	memset(t1, 0, 32);
	memset(t2, 0, 32);
}
