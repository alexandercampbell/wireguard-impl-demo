/*
 * BLAKE2s test suite
 * Tests against RFC 7693 vectors and official blake2s-kat.txt vectors.
 */

#include "blake2s.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;

static void
tohex(char *dst, const uchar *src, size_t len)
{
	size_t i;
	for(i = 0; i < len; i++)
		sprintf(dst + i*2, "%02x", src[i]);
	dst[len*2] = '\0';
}

static void
check(const char *name, const uchar *got, const char *expect_hex, size_t outlen)
{
	char gothex[128];
	tohex(gothex, got, outlen);
	if(strcmp(gothex, expect_hex) != 0){
		printf("FAIL %s\n  expected: %s\n  got:      %s\n", name, expect_hex, gothex);
		failures++;
	} else {
		printf("OK   %s\n", name);
	}
}

/*
 * Test 1: RFC 7693 Appendix B — BLAKE2s-256("abc")
 */
static void
test_rfc7693_abc(void)
{
	uchar out[32];
	blake2s(out, 32, "abc", 3);
	check("RFC7693 BLAKE2s-256(\"abc\")", out,
	      "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);
}

/*
 * Test 2: Unkeyed empty string
 */
static void
test_unkeyed_empty(void)
{
	uchar out[32];
	blake2s(out, 32, "", 0);
	check("Unkeyed BLAKE2s-256(\"\")", out,
	      "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 32);
}

/*
 * Test 3: Unkeyed single-byte inputs (from blake2-kat.json)
 */
static void
test_unkeyed_short(void)
{
	uchar out[32], in[3];

	in[0] = 0x00;
	blake2s(out, 32, in, 1);
	check("Unkeyed BLAKE2s-256(0x00)", out,
	      "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea", 32);

	in[0] = 0x00; in[1] = 0x01;
	blake2s(out, 32, in, 2);
	check("Unkeyed BLAKE2s-256(0x0001)", out,
	      "ddad9ab15dac4549ba42f49d262496bef6c0bae1dd342a8808f8ea267c6e210c", 32);

	in[0] = 0x00; in[1] = 0x01; in[2] = 0x02;
	blake2s(out, 32, in, 3);
	check("Unkeyed BLAKE2s-256(0x000102)", out,
	      "e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900", 32);
}

/*
 * Test 4: Keyed vectors from blake2s-kat.txt
 * All use key = 000102...1f (32 bytes)
 * Input is sequential bytes 00, 01, 02, ... of increasing length
 */
static const char *keyed_vectors[] = {
	/* input len 0 */  "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
	/* input len 1 */  "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
	/* input len 2 */  "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
	/* input len 3 */  "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b",
	/* input len 4 */  "f6c3fbadb4cc687a0064a5be6e791bec63b868ad62fba61b3757ef9ca52e05b2",
	/* input len 5 */  "49c1f21188dfd769aea0e911dd6b41f14dab109d2b85977aa3088b5c707e8598",
	/* input len 6 */  "fdd8993dcd43f696d44f3cea0ff35345234ec8ee083eb3cada017c7f78c17143",
	/* input len 7 */  "e6c8125637438d0905b749f46560ac89fd471cf8692e28fab982f73f019b83a9",
	/* input len 8 */  "19fc8ca6979d60e6edd3b4541e2f967ced740df6ec1eaebbfe813832e96b2974",
	/* input len 9 */  "a6ad777ce881b52bb5a4421ab6cdd2dfba13e963652d4d6d122aee46548c14a7",
	/* input len 10 */ "f5c4b2ba1a00781b13aba0425242c69cb1552f3f71a9a3bb22b4a6b4277b46dd",
	NULL
};

static void
test_keyed_short(void)
{
	uchar key[32], in[16], out[32];
	int i;
	char name[64];

	for(i = 0; i < 32; i++)
		key[i] = (uchar)i;

	for(i = 0; keyed_vectors[i] != NULL; i++){
		int j;
		for(j = 0; j < i; j++)
			in[j] = (uchar)j;

		blake2s_keyed(out, 32, in, (size_t)i, key, 32);
		sprintf(name, "Keyed BLAKE2s-256(len=%d)", i);
		check(name, out, keyed_vectors[i], 32);
	}
}

/*
 * Test 5: Keyed 64-byte input (block boundary)
 * From blake2s-kat.txt entry 64
 */
static void
test_keyed_64(void)
{
	uchar key[32], in[64], out[32];
	int i;

	for(i = 0; i < 32; i++)
		key[i] = (uchar)i;
	for(i = 0; i < 64; i++)
		in[i] = (uchar)i;

	blake2s_keyed(out, 32, in, 64, key, 32);
	check("Keyed BLAKE2s-256(len=64)", out,
	      "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4", 32);
}

/*
 * Test 6: Keyed 128-byte input
 * From blake2s-kat.txt entry 128
 */
static void
test_keyed_128(void)
{
	uchar key[32], in[128], out[32];
	int i;

	for(i = 0; i < 32; i++)
		key[i] = (uchar)i;
	for(i = 0; i < 128; i++)
		in[i] = (uchar)i;

	blake2s_keyed(out, 32, in, 128, key, 32);
	check("Keyed BLAKE2s-256(len=128)", out,
	      "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a", 32);
}

/*
 * Test 7: Keyed 255-byte input (last entry in blake2s-kat.txt)
 * From blake2s-kat.txt entry 255
 */
static void
test_keyed_255(void)
{
	uchar key[32], in[255], out[32];
	int i;

	for(i = 0; i < 32; i++)
		key[i] = (uchar)i;
	for(i = 0; i < 255; i++)
		in[i] = (uchar)i;

	blake2s_keyed(out, 32, in, 255, key, 32);
	check("Keyed BLAKE2s-256(len=255)", out,
	      "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd", 32);
}

/*
 * Test 8: RFC 7693 Appendix E — selftest grand hash
 *
 * Uses the selftest_seq PRNG from the RFC to generate test inputs and keys.
 * The grand hash accumulator is an unkeyed BLAKE2s-256.
 */

/* Deterministic sequence generator from RFC 7693 Appendix E */
static void
selftest_seq(uchar *out, size_t len, uint32 seed)
{
	size_t i;
	uint32 t, a, b;

	a = 0xDEAD4BADUL * seed;
	b = 1;

	for(i = 0; i < len; i++){
		t = a + b;
		a = b;
		b = t;
		out[i] = (uchar)((t >> 24) & 0xFF);
	}
}

static void
test_selftest(void)
{
	static const size_t b2s_md_len[4] = { 16, 20, 28, 32 };
	static const size_t b2s_in_len[6] = { 0, 3, 64, 65, 255, 1024 };

	uchar in[1024], md[BLAKE2S_OUTBYTES], key[BLAKE2S_KEYBYTES];
	Blake2s ctx;
	size_t i, j, outlen, inlen;
	uchar final_out[32];

	/* 256-bit unkeyed hash for accumulating results */
	blake2s_init(&ctx, 32);

	for(i = 0; i < 4; i++){
		outlen = b2s_md_len[i];
		for(j = 0; j < 6; j++){
			inlen = b2s_in_len[j];

			selftest_seq(in, inlen, (uint32)inlen);  /* unkeyed hash */
			blake2s(md, outlen, in, inlen);
			blake2s_update(&ctx, md, outlen);         /* hash the hash */

			selftest_seq(key, outlen, (uint32)outlen); /* keyed hash */
			blake2s_keyed(md, outlen, in, inlen, key, outlen);
			blake2s_update(&ctx, md, outlen);          /* hash the hash */
		}
	}

	blake2s_final(&ctx, final_out, 32);
	check("RFC7693 selftest grand hash", final_out,
	      "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe", 32);
}

/*
 * Test 9: Incremental (streaming) update produces same result as one-shot.
 * Uses keyed 255-byte hash (last entry in blake2s-kat.txt).
 */
static void
test_incremental(void)
{
	uchar key[32], in[255], out_oneshot[32], out_stream[32];
	Blake2s S;
	int i;

	for(i = 0; i < 32; i++)
		key[i] = (uchar)i;
	for(i = 0; i < 255; i++)
		in[i] = (uchar)i;

	/* One-shot */
	blake2s_keyed(out_oneshot, 32, in, 255, key, 32);

	/* Streaming: feed one byte at a time */
	blake2s_init_key(&S, 32, key, 32);
	for(i = 0; i < 255; i++)
		blake2s_update(&S, in + i, 1);
	blake2s_final(&S, out_stream, 32);

	check("Incremental (1 byte at a time) == one-shot", out_stream,
	      "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd", 32);

	/* Streaming: feed in odd-sized chunks */
	blake2s_init_key(&S, 32, key, 32);
	blake2s_update(&S, in, 7);
	blake2s_update(&S, in + 7, 63);
	blake2s_update(&S, in + 70, 1);
	blake2s_update(&S, in + 71, 100);
	blake2s_update(&S, in + 171, 84);
	blake2s_final(&S, out_stream, 32);

	check("Incremental (odd chunks) == one-shot", out_stream,
	      "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd", 32);
}

int
main(void)
{
	printf("BLAKE2s Test Suite\n");
	printf("==================\n\n");

	test_rfc7693_abc();
	test_unkeyed_empty();
	test_unkeyed_short();
	test_keyed_short();
	test_keyed_64();
	test_keyed_128();
	test_keyed_255();
	test_selftest();
	test_incremental();

	printf("\n");
	if(failures == 0)
		printf("All tests passed.\n");
	else
		printf("%d test(s) FAILED.\n", failures);

	return failures ? 1 : 0;
}
