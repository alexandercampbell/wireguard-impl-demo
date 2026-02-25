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

### Phases remaining

2. Noise IK handshake (protocol state machine, key exchange)
3. Transport data (encrypt/decrypt, replay protection)
4. Timer state machine (keepalives, rekey, retransmission)
5. Cookie/DoS system (mac1/mac2, cookie replies)
6. 9front network integration (UDP, TUN, config)

See `claude-initial-analysis.txt` for the full protocol breakdown.

## Building & Testing

```
cd src
cc -Wall -Wextra -std=c99 -O2 -o blake2s_test blake2s.c blake2s_test.c
./blake2s_test
```

All 22 tests should pass, including the RFC 7693 Appendix E selftest grand
hash which exercises every combination of output length (16/20/28/32),
input length (0/3/64/65/255/1024), and keyed/unkeyed mode.

## Crypto Primitives

What we need vs. what exists in 9front's libsec (`drawterm/libsec`):

| Primitive | WireGuard needs | libsec | Status |
|---|---|---|---|
| BLAKE2s | Hash, MAC, HMAC, KDF | missing | **Implemented** |
| Curve25519 | DH key exchange | `curve25519_dh_new/finish` | Available |
| ChaCha20-Poly1305 | Transport AEAD | `ccpoly_encrypt/decrypt` | Available |
| XChaCha20-Poly1305 | Cookie encryption | `hchacha` + `ccpoly_*` | Available |
| HMAC | Key derivation | `hmac_x` (generic) | Available, needs BLAKE2s |
| HKDF | Key derivation | `hkdf_x` (generic) | Available, needs BLAKE2s |

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
