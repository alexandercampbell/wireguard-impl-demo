/*
 * Plan 9 compatibility shim for vendored libsec code.
 *
 * Provides type aliases, macros, and struct definitions so that
 * drawterm/libsec source files can compile under standard C99
 * without the full Plan 9 header chain.
 */

#ifndef P9SHIM_H
#define P9SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

/* Plan 9 type aliases — guarded to coexist with blake2s.h */
#ifndef _P9_UCHAR
#define _P9_UCHAR
typedef unsigned char	uchar;
#endif
#ifndef _P9_UINT32
#define _P9_UINT32
typedef unsigned int	uint32;
#endif
typedef unsigned int	ulong;
typedef uint32_t	u32int;
typedef uint64_t	u64int;
typedef unsigned long long uvlong;
typedef long long	vlong;

/* Plan 9 macros */
#define nil	((void*)0)
#define nelem(x)	(sizeof(x)/sizeof((x)[0]))

#define sysfatal(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); abort(); } while(0)

/*
 * ChaCha20 constants and state (from libsec.h)
 */
enum
{
	ChachaBsize	= 64,
	ChachaKeylen	= 256/8,
	ChachaIVlen	= 96/8,
	XChachaIVlen	= 192/8,
};

typedef struct Chachastate Chachastate;
struct Chachastate
{
	union{
		u32int	input[16];
		struct {
			u32int	constant[4];
			u32int	key[8];
			u32int	counter;
			u32int	iv[3];
		};
	};
	u32int	xkey[8];
	int	rounds;
	int	ivwords;
};

/*
 * Digest state (from libsec.h) — used by poly1305 and ccpoly
 */
enum
{
	Poly1305dlen	= 16,
};

typedef struct DigestState DigestState;
struct DigestState
{
	uvlong	len;
	union {
		u32int	state[16];
		u64int	bstate[8];
	};
	uchar	buf[256];
	int	blen;
	char	malloced;
	char	seeded;
};

/* ChaCha20 functions */
extern void	_chachablock(u32int x[16], int rounds);
void	setupChachastate(Chachastate*, uchar*, ulong, uchar*, ulong, int);
void	chacha_setiv(Chachastate*, uchar*);
void	chacha_setblock(Chachastate*, u64int);
void	chacha_encrypt(uchar*, ulong, Chachastate*);
void	chacha_encrypt2(uchar*, uchar*, ulong, Chachastate*);
void	hchacha(uchar h[32], uchar *key, ulong keylen, uchar nonce[16], int rounds);

/* ChaCha20-Poly1305 AEAD */
void	ccpoly_encrypt(uchar *dat, ulong ndat, uchar *aad, ulong naad, uchar tag[16], Chachastate *cs);
int	ccpoly_decrypt(uchar *dat, ulong ndat, uchar *aad, ulong naad, uchar tag[16], Chachastate *cs);

/* Poly1305 MAC */
DigestState*	poly1305(uchar*, ulong, uchar*, ulong, uchar*, DigestState*);

/* Curve25519 */
void	curve25519(uchar mypublic[32], uchar secret[32], uchar basepoint[32]);

/* Timing-safe memcmp */
int	tsmemcmp(void*, void*, ulong);

#endif /* P9SHIM_H */
