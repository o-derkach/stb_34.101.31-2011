#include "stb_cypher.h"

void crypt_yasv(uint32_t *in, uint32_t *out, uint32_t *key)
{
	uint32_t a, b, c, d, e, x;
	int i = 1;
	a = in[0];
	b = in[1];
	c = in[2];
	d = in[3];

	roundDump(a, b, c, d);

	//for (i = 1; i <= 8; ++i)
	//1
	x = a + key[0];
	x = sub_1[x & 0xFF] ^ sub_2[(x >> 8) & 0xFF] ^ sub_3[(x >> 16) & 0xFF] ^ sub_4[(x >> 24) & 0xFF];
	x = rotHi(x, 5);
	b ^= x;
	roundDump(a, b, c, d);
	//2
	//c ^= rotHi


	out[0] = b;
	out[1] = d;
	out[2] = a;
	out[3] = c;
}
