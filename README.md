# WireGuard for 9front

A WireGuard client implementation targeting the 9front operating system,
written in C. This is a collaborative project between Alexander and Claude,
challenged by a friend who claims it can't be done.

See `initial-prompt.md` for the original challenge description.

## Project Status

### Phase 1: BLAKE2s (COMPLETE)

From-scratch implementation of BLAKE2s per RFC 7693, with full test vector
validation. This satisfies the challenger's requirement #1.

Files:
- `src/blake2s.h` — header with state struct and public API
- `src/blake2s.c` — implementation (~220 lines)
- `src/blake2s_test.c` — 22 tests covering all modes

### Phase 2: Noise IK Handshake (COMPLETE)

Vendored libsec crypto primitives with a Plan 9 compatibility shim,
built WireGuard-specific crypto wrappers (HMAC-BLAKE2s, HKDF, AEAD, DH),
and implemented the full Noise_IKpsk2 handshake state machine. 42 tests
passing including RFC 7748 Curve25519 vectors, handshake round-trip with
transport key derivation, and tamper rejection.

Files:
- `vendored-from-9/p9shim.h` — Plan 9 type compatibility header
- `vendored-from-9/{chacha,chachablock,poly1305,ccpoly,curve25519,tsmemcmp}.c` — libsec primitives
- `src/wg_crypto.h` / `src/wg_crypto.c` — WireGuard crypto wrappers (~250 lines)
- `src/wg_noise.h` / `src/wg_noise.c` — Noise IK handshake state machine (~530 lines)
- `src/wg_noise_test.c` — 42 tests covering all crypto and handshake operations

### Phases remaining

3. Transport data (encrypt/decrypt, replay protection)
4. Timer state machine (keepalives, rekey, retransmission)
5. Cookie/DoS system (mac1/mac2, cookie replies)
6. 9front network integration (UDP, TUN, config)

See `claude-initial-analysis.txt` for the full protocol breakdown.

## Building & Testing

```sh
# Phase 1: BLAKE2s tests
cd src
cc -Wall -Wextra -std=c99 -O2 -o blake2s_test blake2s.c blake2s_test.c
./blake2s_test

# Phase 2: Noise handshake tests
cc -Wall -Wextra -std=c99 -O2 -I../vendored-from-9 \
   -o wg_noise_test \
   blake2s.c wg_crypto.c wg_noise.c wg_noise_test.c \
   ../vendored-from-9/curve25519.c \
   ../vendored-from-9/chacha.c \
   ../vendored-from-9/chachablock.c \
   ../vendored-from-9/poly1305.c \
   ../vendored-from-9/ccpoly.c \
   ../vendored-from-9/tsmemcmp.c
./wg_noise_test
```

Phase 1: 22 tests (RFC 7693 vectors, selftest grand hash, incremental hashing).
Phase 2: 42 tests (construction hashes, HMAC, KDF, AEAD, Curve25519, handshake
round-trip, transport data exchange, tamper rejection).

## Crypto Primitives

What we need vs. what exists in 9front's libsec (`drawterm/libsec`):

| Primitive | WireGuard needs | libsec | Status |
|---|---|---|---|
| BLAKE2s | Hash, MAC, HMAC, KDF | missing | **Implemented (Phase 1)** |
| Curve25519 | DH key exchange | `curve25519` | **Vendored + wrapped (Phase 2)** |
| ChaCha20-Poly1305 | Transport AEAD | `ccpoly_encrypt/decrypt` | **Vendored + wrapped (Phase 2)** |
| XChaCha20-Poly1305 | Cookie encryption | `hchacha` + `ccpoly_*` | Vendored, not yet wrapped |
| HMAC-BLAKE2s | Key derivation | N/A (incompatible callback) | **Implemented from scratch (Phase 2)** |
| HKDF-BLAKE2s | Key derivation | N/A (incompatible callback) | **Implemented from scratch (Phase 2)** |

## Work Log

### Session 1: Initial analysis & BLAKE2s

**Sources consulted:**
- WireGuard whitepaper (wireguard-whitepaper.pdf) — Jason A. Donenfeld,
  draft revision e2da747. Read in full. Protocol uses Noise IK pattern
  ("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") with 4 message types,
  timer-based state machine, and cookie DoS mitigation.
- RFC 7693 (The BLAKE2 Cryptographic Hash and MAC) — algorithm spec for
  BLAKE2s: 32-bit words, 64-byte blocks, 10 rounds, IV from SHA-256
  constants. Appendix B for the "abc" test vector, Appendix E for the
  selftest procedure with selftest_seq PRNG.
- drawterm/libsec source tree — inventoried all available crypto primitives.
  Found Curve25519, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, HMAC,
  HKDF, and genrandom all present. BLAKE2s was the only missing piece.
- Official BLAKE2 test vectors from github.com/BLAKE2/BLAKE2:
  - `testvectors/blake2s-kat.txt` — 256 keyed test vectors (input lengths
    0-255, key = 0x00..0x1f)
  - `testvectors/blake2-kat.json` — unkeyed test vectors

**Implementation notes:**
- Wrote blake2s.c from the RFC 7693 description (not copied from reference
  implementation). Uses the standard G mixing function with rotation
  constants 16/12/8/7, the 10-round sigma permutation schedule, and
  little-endian word encoding.
- Keyed mode works by padding the key into the first 64-byte block and
  feeding it via blake2s_update before user data, per the BLAKE2 spec.
- Supports streaming (incremental) hashing via init/update/final API.

**Debugging:**
- Initial test run: 17/22 passed. Failures at keyed lengths 255, 256, and
  the selftest grand hash.
- Root cause 1: The research agent provided fabricated test vectors for
  keyed lengths 255 and 256. Cross-checked against the actual
  blake2s-kat.txt file hosted on GitHub — the real hash for keyed len=255
  is 3fb73506..., and there is no len=256 entry (the file has 256 entries
  indexed 0-255).
- Root cause 2: The selftest grand hash used the wrong procedure. The
  research agent claimed the accumulator was keyed with "BLAKE2s selftest"
  and inputs were sequential bytes mod 251. The actual RFC 7693 Appendix E
  uses an unkeyed accumulator and a deterministic PRNG (selftest_seq) with
  a Fibonacci-like recurrence seeded by the input/output length.
- After correcting test vectors and selftest procedure: 22/22 pass.
- Also fixed a minor issue in blake2s_update where `fill = 0` when the
  buffer was already full (buflen == 64). The condition `left && inlen >
  fill` would enter the branch but advance pin by 0 bytes. Fixed by
  restructuring the flush logic to only enter the fill-and-compress path
  when `left > 0`.

### Session 2: Noise IK handshake

**Sources consulted:**
- WireGuard whitepaper sections 5.4.2–5.4.4 — handshake message
  construction, Noise IK pattern with PSK, mac1/mac2 computation.
- RFC 7748 Section 6.1 — Curve25519 test vectors (Alice/Bob key
  exchange). Used to validate vendored curve25519.c.
- RFC 2104 — HMAC construction. Implemented HMAC-BLAKE2s from scratch
  because libsec's `hmac_x` expects a DigestState-based callback
  incompatible with our BLAKE2s state type.
- Python hashlib.blake2s — cross-validated construction hash values
  (C = BLAKE2s("Noise_IKpsk2_...") and H = BLAKE2s(C || "WireGuard v1
  ...")) to confirm our BLAKE2s matches the reference.
- Cacophony test vectors (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) from
  haskell-cryptography/cacophony — examined for reference; the raw Noise
  IK format differs from WireGuard's wire format (no mac1/mac2 wrapping)
  so used for informational purposes.

**Vendoring approach:**
- Copied 6 files from drawterm/libsec into vendored-from-9/, replacing
  `#include "os.h"` and `#include <libsec.h>` with `#include "p9shim.h"`.
- p9shim.h provides Plan 9 type aliases (uchar, ulong, u32int, u64int,
  uvlong, vlong), nil macro, sysfatal macro, nelem macro, and the
  Chachastate/DigestState struct definitions extracted from libsec.h.
- Added typedef guards (`_P9_UCHAR`, `_P9_UINT32`) to coexist with
  blake2s.h which defines the same types.

**Implementation notes:**
- HMAC-BLAKE2s: standard RFC 2104 with 64-byte block size. ~30 lines.
- HKDF: WireGuard-specific KDF from the whitepaper (not standard HKDF).
  tau_0 = Hmac(key, input), then expand with incrementing byte suffix.
  Provides wg_kdf1/wg_kdf2/wg_kdf3 for 1/2/3-output variants.
- AEAD wrapper: constructs 12-byte nonce (4 zero + 8 LE counter), sets
  up Chachastate with ivwords=3 (96-bit nonce, RFC 7539 mode), calls
  ccpoly_encrypt/decrypt.
- DH: thin wrapper around curve25519(). wg_dh_generate reads from
  /dev/urandom, clamps, derives public key.
- TAI64N timestamps: gettimeofday + TAI64 base (2^62 + 10) + 37s UTC-TAI
  offset.

**Debugging:**
- Construction hash test initially failed: the expected values were
  incorrect (from an unreliable source). Cross-validated against Python
  hashlib.blake2s — our implementation matched exactly. Updated test
  vectors to the correct values.
- Curve25519 test initially failed: RFC 7748 test vectors are unclamped
  raw bytes, but drawterm's curve25519() does not clamp internally.
  Fixed by clamping private keys in the test (as wg_dh_generate does).
- Handshake msg2 consumption failed: mac1 verification in resp_consume
  was using peer->static_pub (responder's key) instead of dev->static_pub
  (initiator's own key). Per section 5.4.4, mac1 is keyed with the
  *recipient's* static public key — for the response message, the
  recipient is the initiator.
- Transport keys were swapped: wg_derive_keypair assigned (tau_1, tau_2)
  as (send, recv) for both sides. Fixed by adding an is_initiator
  parameter — initiator sends with tau_1, responder sends with tau_2.
