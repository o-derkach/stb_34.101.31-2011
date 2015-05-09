#include "utils.h"

void generateBytes(uint32_t *bytes, int byteLen)
{
	int i;
	for (i = 0; i < byteLen / 4; ++i)
	{
		bytes[i] = (rand() & 0x7FFFFFFF) | ((rand() & 1) << 31);
	}
}

void generateBits(uint32_t *bits, int bitLen)
{
	int i;
	for (i = 0; i < bitLen / 32; ++i)
	{
		bits[i] = (rand() & 0x7FFFFFFF) | ((rand() & 1) << 31);
	}
}

uint32_t toSTBint(const uint32_t a)
{
	return (a >> 24) | (((a >> 16) & 0xFF) << 8) | (((a >> 8) & 0xFF) << 16) | ((a & 0xFF) << 24);
	//return a;
}

uint32_t rotHi(const uint32_t a, const int r)
{
	//return ((a >> r) ^ (a << (32 - r)));
	return ((a << r) | (a >> (32 - r)));
}

void roundDump(const uint32_t a, const uint32_t b, const uint32_t c, const uint32_t d)
{
	printf("%8c %8c %8c %8c\n", 'a', 'b', 'c', 'd');
	printf("%08X %08X %08X %08X\n", a, b, c, d);
}
