#include "utils.h"
#include "stb_cypher.h"

int main()
{
	uint32_t a = 0xb194bac8;
	uint32_t b = 0x21;
	int i = 0;
	printf("0x%x\n", toSTBint(a));
	printf("0x%x\n", toSTBint(toSTBint(a)));
	printf("0x%x\n", rotHi(b, 5));
	/*srand(time(NULL));
	ERROR("error");
	printf("0x%x\n", RAND_MAX);
	WARNING("warning");
	DEBUG("debug");*/
	uint32_t in[4] = {0xB194BAC8, 0x0A08F53B, 0x366D008E, 0x584A5DE4};
	uint32_t out[4] = {0, 0, 0, 0};
	uint32_t key[8] = {0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6};

	crypt(in, out, key);
	/*a = toSTBint(a);
	key[0] = toSTBint(key[0]);
	x = a + key[0];
	//x = toSTBint(x);
	x = sub_1[x & 0xFF] ^ sub_2[(x >> 8) & 0xFF] ^ sub_3[(x >> 16) & 0xFF] ^ sub_4[(x >> 24) & 0xFF];
	//x = toSTBint(x);
	b = toSTBint(b);
	//x = toSTBint(x);
	b ^= rotHi(x, 5);
	roundDump(a, b, c, d);*/
	return 0;
}
