/*
 * WireGuard Noise IK handshake — Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * Implements the 1-RTT handshake described in the WireGuard whitepaper
 * sections 5.4.2–5.4.4.
 */

#ifndef WG_NOISE_H
#define WG_NOISE_H

#include "wg_crypto.h"

/*
 * Wire format message types
 */
enum {
	WG_MSG_INIT = 1,
	WG_MSG_RESP = 2,
};

/*
 * Wire format sizes
 * Initiation: type(1) + reserved(3) + sender(4) + ephemeral(32) +
 *             static(48) + timestamp(28) + mac1(16) + mac2(16) = 148
 * Response:   type(1) + reserved(3) + sender(4) + receiver(4) +
 *             ephemeral(32) + empty(16) + mac1(16) + mac2(16) = 92
 */
enum {
	WG_INIT_MSG_LEN = 148,
	WG_RESP_MSG_LEN = 92,
};

/*
 * Noise protocol construction and identifier strings.
 * The whitepaper defines:
 *   C = Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
 *   H = Hash(C || "WireGuard v1 zx2c4 Jason@zx2c4.com")
 */
#define WG_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_IDENTIFIER   "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WG_LABEL_MAC1   "mac1----"
#define WG_LABEL_COOKIE "cookie--"

/*
 * Data structures
 */

typedef struct WgDevice WgDevice;
struct WgDevice {
	uchar static_priv[32];  /* our static private key */
	uchar static_pub[32];   /* our static public key */
};

typedef struct WgPeer WgPeer;
struct WgPeer {
	uchar static_pub[32];        /* peer's static public key */
	uchar preshared_key[32];     /* optional PSK (zeros if unused) */
	uchar latest_timestamp[12];  /* latest TAI64N (anti-replay) */
};

typedef struct WgHandshake WgHandshake;
struct WgHandshake {
	uchar  hash[32];           /* H — running hash */
	uchar  chaining_key[32];   /* C — chaining key */
	uchar  ephemeral_priv[32]; /* our ephemeral private key */
	uchar  ephemeral_pub[32];  /* our ephemeral public key */
	uchar  remote_eph_pub[32]; /* peer's ephemeral public key */
	uint32 local_index;        /* I — our sender index */
	uint32 remote_index;       /* peer's sender index */
};

typedef struct WgKeypair WgKeypair;
struct WgKeypair {
	uchar    send_key[32]; /* T_send */
	uchar    recv_key[32]; /* T_recv */
	uint64_t send_nonce;   /* N_send */
	uint64_t recv_nonce;   /* N_recv */
	int      is_initiator;
};

/*
 * Handshake functions
 */

/* Initiator creates message 1 (148 bytes) */
int wg_handshake_init_create(WgDevice *dev, WgPeer *peer,
                             WgHandshake *hs, uchar msg[WG_INIT_MSG_LEN]);

/* Responder consumes message 1 */
int wg_handshake_init_consume(WgDevice *dev, WgPeer *peer,
                              WgHandshake *hs, const uchar msg[WG_INIT_MSG_LEN]);

/* Responder creates message 2 (92 bytes) */
int wg_handshake_resp_create(WgDevice *dev, WgPeer *peer,
                             WgHandshake *hs, uchar msg[WG_RESP_MSG_LEN]);

/* Initiator consumes message 2 */
int wg_handshake_resp_consume(WgDevice *dev, WgPeer *peer,
                              WgHandshake *hs, const uchar msg[WG_RESP_MSG_LEN]);

/* Derive transport keypair after handshake completes.
 * is_initiator: 1 if we initiated, 0 if we responded.
 * The initiator sends with tau_1 and receives with tau_2;
 * the responder sends with tau_2 and receives with tau_1. */
void wg_derive_keypair(WgHandshake *hs, WgKeypair *kp, int is_initiator);

#endif /* WG_NOISE_H */
