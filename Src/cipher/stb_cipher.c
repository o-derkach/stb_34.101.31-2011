#include "config.h"
#include "utils.h"

//substitution blocks
const uint32_t sub_1[SBLOCK_VAL_COUNT] = {
	0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
	0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
	0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
	0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
	0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
	0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
	0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
	0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
	0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
	0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
	0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
	0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
	0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
	0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
	0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
	0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D
};

const uint32_t sub_2[SBLOCK_VAL_COUNT] = {
	0xB100, 0x9400, 0xBA00, 0xC800, 0x0A00, 0x0800, 0xF500, 0x3B00, 0x3600, 0x6D00, 0x0000, 0x8E00, 0x5800, 0x4A00, 0x5D00, 0xE400,
	0x8500, 0x0400, 0xFA00, 0x9D00, 0x1B00, 0xB600, 0xC700, 0xAC00, 0x2500, 0x2E00, 0x7200, 0xC200, 0x0200, 0xFD00, 0xCE00, 0x0D00,
	0x5B00, 0xE300, 0xD600, 0x1200, 0x1700, 0xB900, 0x6100, 0x8100, 0xFE00, 0x6700, 0x8600, 0xAD00, 0x7100, 0x6B00, 0x8900, 0x0B00,
	0x5C00, 0xB000, 0xC000, 0xFF00, 0x3300, 0xC300, 0x5600, 0xB800, 0x3500, 0xC400, 0x0500, 0xAE00, 0xD800, 0xE000, 0x7F00, 0x9900,
	0xE100, 0x2B00, 0xDC00, 0x1A00, 0xE200, 0x8200, 0x5700, 0xEC00, 0x7000, 0x3F00, 0xCC00, 0xF000, 0x9500, 0xEE00, 0x8D00, 0xF100,
	0xC100, 0xAB00, 0x7600, 0x3800, 0x9F00, 0xE600, 0x7800, 0xCA00, 0xF700, 0xC600, 0xF800, 0x6000, 0xD500, 0xBB00, 0x9C00, 0x4F00,
	0xF300, 0x3C00, 0x6500, 0x7B00, 0x6300, 0x7C00, 0x3000, 0x6A00, 0xDD00, 0x4E00, 0xA700, 0x7900, 0x9E00, 0xB200, 0x3D00, 0x3100,
	0x3E00, 0x9800, 0xB500, 0x6E00, 0x2700, 0xD300, 0xBC00, 0xCF00, 0x5900, 0x1E00, 0x1800, 0x1F00, 0x4C00, 0x5A00, 0xB700, 0x9300,
	0xE900, 0xDE00, 0xE700, 0x2C00, 0x8F00, 0x0C00, 0x0F00, 0xA600, 0x2D00, 0xDB00, 0x4900, 0xF400, 0x6F00, 0x7300, 0x9600, 0x4700,
	0x0600, 0x0700, 0x5300, 0x1600, 0xED00, 0x2400, 0x7A00, 0x3700, 0x3900, 0xCB00, 0xA300, 0x8300, 0x0300, 0xA900, 0x8B00, 0xF600,
	0x9200, 0xBD00, 0x9B00, 0x1C00, 0xE500, 0xD100, 0x4100, 0x0100, 0x5400, 0x4500, 0xFB00, 0xC900, 0x5E00, 0x4D00, 0x0E00, 0xF200,
	0x6800, 0x2000, 0x8000, 0xAA00, 0x2200, 0x7D00, 0x6400, 0x2F00, 0x2600, 0x8700, 0xF900, 0x3400, 0x9000, 0x4000, 0x5500, 0x1100,
	0xBE00, 0x3200, 0x9700, 0x1300, 0x4300, 0xFC00, 0x9A00, 0x4800, 0xA000, 0x2A00, 0x8800, 0x5F00, 0x1900, 0x4B00, 0x0900, 0xA100,
	0x7E00, 0xCD00, 0xA400, 0xD000, 0x1500, 0x4400, 0xAF00, 0x8C00, 0xA500, 0x8400, 0x5000, 0xBF00, 0x6600, 0xD200, 0xE800, 0x8A00,
	0xA200, 0xD700, 0x4600, 0x5200, 0x4200, 0xA800, 0xDF00, 0xB300, 0x6900, 0x7400, 0xC500, 0x5100, 0xEB00, 0x2300, 0x2900, 0x2100,
	0xD400, 0xEF00, 0xD900, 0xB400, 0x3A00, 0x6200, 0x2800, 0x7500, 0x9100, 0x1400, 0x1000, 0xEA00, 0x7700, 0x6C00, 0xDA00, 0x1D00
};

const uint32_t sub_3[SBLOCK_VAL_COUNT] = {
	0xB10000, 0x940000, 0xBA0000, 0xC80000, 0x0A0000, 0x080000, 0xF50000, 0x3B0000, 0x360000, 0x6D0000, 0x000000, 0x8E0000, 0x580000, 0x4A0000, 0x5D0000, 0xE40000,
	0x850000, 0x040000, 0xFA0000, 0x9D0000, 0x1B0000, 0xB60000, 0xC70000, 0xAC0000, 0x250000, 0x2E0000, 0x720000, 0xC20000, 0x020000, 0xFD0000, 0xCE0000, 0x0D0000,
	0x5B0000, 0xE30000, 0xD60000, 0x120000, 0x170000, 0xB90000, 0x610000, 0x810000, 0xFE0000, 0x670000, 0x860000, 0xAD0000, 0x710000, 0x6B0000, 0x890000, 0x0B0000,
	0x5C0000, 0xB00000, 0xC00000, 0xFF0000, 0x330000, 0xC30000, 0x560000, 0xB80000, 0x350000, 0xC40000, 0x050000, 0xAE0000, 0xD80000, 0xE00000, 0x7F0000, 0x990000,
	0xE10000, 0x2B0000, 0xDC0000, 0x1A0000, 0xE20000, 0x820000, 0x570000, 0xEC0000, 0x700000, 0x3F0000, 0xCC0000, 0xF00000, 0x950000, 0xEE0000, 0x8D0000, 0xF10000,
	0xC10000, 0xAB0000, 0x760000, 0x380000, 0x9F0000, 0xE60000, 0x780000, 0xCA0000, 0xF70000, 0xC60000, 0xF80000, 0x600000, 0xD50000, 0xBB0000, 0x9C0000, 0x4F0000,
	0xF30000, 0x3C0000, 0x650000, 0x7B0000, 0x630000, 0x7C0000, 0x300000, 0x6A0000, 0xDD0000, 0x4E0000, 0xA70000, 0x790000, 0x9E0000, 0xB20000, 0x3D0000, 0x310000,
	0x3E0000, 0x980000, 0xB50000, 0x6E0000, 0x270000, 0xD30000, 0xBC0000, 0xCF0000, 0x590000, 0x1E0000, 0x180000, 0x1F0000, 0x4C0000, 0x5A0000, 0xB70000, 0x930000,
	0xE90000, 0xDE0000, 0xE70000, 0x2C0000, 0x8F0000, 0x0C0000, 0x0F0000, 0xA60000, 0x2D0000, 0xDB0000, 0x490000, 0xF40000, 0x6F0000, 0x730000, 0x960000, 0x470000,
	0x060000, 0x070000, 0x530000, 0x160000, 0xED0000, 0x240000, 0x7A0000, 0x370000, 0x390000, 0xCB0000, 0xA30000, 0x830000, 0x030000, 0xA90000, 0x8B0000, 0xF60000,
	0x920000, 0xBD0000, 0x9B0000, 0x1C0000, 0xE50000, 0xD10000, 0x410000, 0x010000, 0x540000, 0x450000, 0xFB0000, 0xC90000, 0x5E0000, 0x4D0000, 0x0E0000, 0xF20000,
	0x680000, 0x200000, 0x800000, 0xAA0000, 0x220000, 0x7D0000, 0x640000, 0x2F0000, 0x260000, 0x870000, 0xF90000, 0x340000, 0x900000, 0x400000, 0x550000, 0x110000,
	0xBE0000, 0x320000, 0x970000, 0x130000, 0x430000, 0xFC0000, 0x9A0000, 0x480000, 0xA00000, 0x2A0000, 0x880000, 0x5F0000, 0x190000, 0x4B0000, 0x090000, 0xA10000,
	0x7E0000, 0xCD0000, 0xA40000, 0xD00000, 0x150000, 0x440000, 0xAF0000, 0x8C0000, 0xA50000, 0x840000, 0x500000, 0xBF0000, 0x660000, 0xD20000, 0xE80000, 0x8A0000,
	0xA20000, 0xD70000, 0x460000, 0x520000, 0x420000, 0xA80000, 0xDF0000, 0xB30000, 0x690000, 0x740000, 0xC50000, 0x510000, 0xEB0000, 0x230000, 0x290000, 0x210000,
	0xD40000, 0xEF0000, 0xD90000, 0xB40000, 0x3A0000, 0x620000, 0x280000, 0x750000, 0x910000, 0x140000, 0x100000, 0xEA0000, 0x770000, 0x6C0000, 0xDA0000, 0x1D0000
};

const uint32_t sub_4[SBLOCK_VAL_COUNT] = {
	0xB1000000, 0x94000000, 0xBA000000, 0xC8000000, 0x0A000000, 0x08000000, 0xF5000000, 0x3B000000, 0x36000000, 0x6D000000, 0x00000000, 0x8E000000, 0x58000000, 0x4A000000, 0x5D000000, 0xE4000000,
	0x85000000, 0x04000000, 0xFA000000, 0x9D000000, 0x1B000000, 0xB6000000, 0xC7000000, 0xAC000000, 0x25000000, 0x2E000000, 0x72000000, 0xC2000000, 0x02000000, 0xFD000000, 0xCE000000, 0x0D000000,
	0x5B000000, 0xE3000000, 0xD6000000, 0x12000000, 0x17000000, 0xB9000000, 0x61000000, 0x81000000, 0xFE000000, 0x67000000, 0x86000000, 0xAD000000, 0x71000000, 0x6B000000, 0x89000000, 0x0B000000,
	0x5C000000, 0xB0000000, 0xC0000000, 0xFF000000, 0x33000000, 0xC3000000, 0x56000000, 0xB8000000, 0x35000000, 0xC4000000, 0x05000000, 0xAE000000, 0xD8000000, 0xE0000000, 0x7F000000, 0x99000000,
	0xE1000000, 0x2B000000, 0xDC000000, 0x1A000000, 0xE2000000, 0x82000000, 0x57000000, 0xEC000000, 0x70000000, 0x3F000000, 0xCC000000, 0xF0000000, 0x95000000, 0xEE000000, 0x8D000000, 0xF1000000,
	0xC1000000, 0xAB000000, 0x76000000, 0x38000000, 0x9F000000, 0xE6000000, 0x78000000, 0xCA000000, 0xF7000000, 0xC6000000, 0xF8000000, 0x60000000, 0xD5000000, 0xBB000000, 0x9C000000, 0x4F000000,
	0xF3000000, 0x3C000000, 0x65000000, 0x7B000000, 0x63000000, 0x7C000000, 0x30000000, 0x6A000000, 0xDD000000, 0x4E000000, 0xA7000000, 0x79000000, 0x9E000000, 0xB2000000, 0x3D000000, 0x31000000,
	0x3E000000, 0x98000000, 0xB5000000, 0x6E000000, 0x27000000, 0xD3000000, 0xBC000000, 0xCF000000, 0x59000000, 0x1E000000, 0x18000000, 0x1F000000, 0x4C000000, 0x5A000000, 0xB7000000, 0x93000000,
	0xE9000000, 0xDE000000, 0xE7000000, 0x2C000000, 0x8F000000, 0x0C000000, 0x0F000000, 0xA6000000, 0x2D000000, 0xDB000000, 0x49000000, 0xF4000000, 0x6F000000, 0x73000000, 0x96000000, 0x47000000,
	0x06000000, 0x07000000, 0x53000000, 0x16000000, 0xED000000, 0x24000000, 0x7A000000, 0x37000000, 0x39000000, 0xCB000000, 0xA3000000, 0x83000000, 0x03000000, 0xA9000000, 0x8B000000, 0xF6000000,
	0x92000000, 0xBD000000, 0x9B000000, 0x1C000000, 0xE5000000, 0xD1000000, 0x41000000, 0x01000000, 0x54000000, 0x45000000, 0xFB000000, 0xC9000000, 0x5E000000, 0x4D000000, 0x0E000000, 0xF2000000,
	0x68000000, 0x20000000, 0x80000000, 0xAA000000, 0x22000000, 0x7D000000, 0x64000000, 0x2F000000, 0x26000000, 0x87000000, 0xF9000000, 0x34000000, 0x90000000, 0x40000000, 0x55000000, 0x11000000,
	0xBE000000, 0x32000000, 0x97000000, 0x13000000, 0x43000000, 0xFC000000, 0x9A000000, 0x48000000, 0xA0000000, 0x2A000000, 0x88000000, 0x5F000000, 0x19000000, 0x4B000000, 0x09000000, 0xA1000000,
	0x7E000000, 0xCD000000, 0xA4000000, 0xD0000000, 0x15000000, 0x44000000, 0xAF000000, 0x8C000000, 0xA5000000, 0x84000000, 0x50000000, 0xBF000000, 0x66000000, 0xD2000000, 0xE8000000, 0x8A000000,
	0xA2000000, 0xD7000000, 0x46000000, 0x52000000, 0x42000000, 0xA8000000, 0xDF000000, 0xB3000000, 0x69000000, 0x74000000, 0xC5000000, 0x51000000, 0xEB000000, 0x23000000, 0x29000000, 0x21000000,
	0xD4000000, 0xEF000000, 0xD9000000, 0xB4000000, 0x3A000000, 0x62000000, 0x28000000, 0x75000000, 0x91000000, 0x14000000, 0x10000000, 0xEA000000, 0x77000000, 0x6C000000, 0xDA000000, 0x1D000000
};

uint32_t Gn(const uint32_t a, const int r)
{
	return rotHi(sub_1[a & 0xFF] ^ sub_2[(a >> 8) & 0xFF] ^ sub_3[(a >> 16) & 0xFF] ^ sub_4[(a >> 24) & 0xFF], r);
}

// if round = 0 - no fault
void cryptWithFault(const uint32_t *in, const uint32_t *key, uint32_t *out, const int round, const int position)
{
	uint32_t a, b, c, d, a1, b1, c1, d1, e, x, i;
	uint32_t k[ROUNDKEY_NUM];
	for (i = 0; i < ROUNDKEY_NUM; ++i)
	{
		k[i] = toSTBint(key[i & (KEY_WORD_LEN - 1)]);
	}
	a = in[0];
	b = in[1];
	c = in[2];
	d = in[3];
	//roundDump(a, b, c, d);

	DUMP(a, b, c, d);

	i = 1;
	for (i = 1; i <= ROUND_NUM; ++i)
	{
		if (i == round)
		{
			//roundDump(a, b, c, d);
			if (position < 32)
			{
				a ^= 1 << position;
			}
			else if (position < 64)
			{
				b ^= 1 << (position & 0x1F);
			}
			else if (position < 96)
			{
				c ^= 1 << (position & 0x1F);
			}
			else if (position < 128)
			{
				d ^= 1 << (position & 0x1F);
			}
			//INFO("fault injected");
			//roundDump(a, b, c, d);
		}
		a1 = toSTBint(a);
		b1 = toSTBint(b);
		c1 = toSTBint(c);
		d1 = toSTBint(d);
		//1 step
		x = a1 + k[7 * i - 7];
		x = Gn(x, BLOCK_SHIFT_5);
		//x = toSTBint(x); if uncomment this you MUST XOR with b in next line
		b1 ^= x;
		b = toSTBint(b1);
		DUMP(a, b, c, d);

		//2 step
		x = d1 + k[7 * i - 6];
		x = Gn(x, BLOCK_SHIFT_21);
		//x =
		c1 ^= x;
		c = toSTBint(c1);
		DUMP(a, b, c, d);

		//3 step
		x = b1 + k[7 * i - 5];
		x = Gn(x, BLOCK_SHIFT_13);
		//x =
		a1 -= x;
		a = toSTBint(a1);
		DUMP(a, b, c, d);

		//4 step
		x = b1 + c1 + k[7 * i - 4];
		x = Gn(x, BLOCK_SHIFT_21);
		//x =
		e = x ^ i;
		DUMP(a, b, c, d);
		//printf("e = 0x%8x\n", toSTBint(e));

		//5 step
		b1 = b1 + e;
		b = toSTBint(b1);
		DUMP(a, b, c, d);

		//6 step
		c1 = c1 - e;
		c = toSTBint(c1);
		DUMP(a, b, c, d);

		//7 step
		x = c1 + k[7 * i - 3];
		x = Gn(x, BLOCK_SHIFT_13);
		// x =
		//if (i == 8)
		//printf("c1 = %08X k = %08X\n", c1, k[7 * i - 3]);
		d1 += x;
		d = toSTBint(d1);
		DUMP(a, b, c, d);

		//8 step
		x = a1 + k[7 * i - 2];
		x = Gn(x, BLOCK_SHIFT_21);
		// x =
		b1 ^= x;
		b = toSTBint(b1);
		DUMP(a, b, c, d);

		//9 step
		x = d1 + k[7 * i - 1];
		x = Gn(x, BLOCK_SHIFT_5);
		// x =
		c1 ^= x;
		c = toSTBint(c1);
		DUMP(a, b, c, d);

		//roundDump(a, b, c, d);
		//INFO("FINAL PERMUTATION");
		//10-12 step
		x = a;
		a = b;
		b = x;
		DUMP(a, b, c, d);
		x = c;
		c = d;
		d = x;
		DUMP(a, b, c, d);
		x = b;
		b = c;
		c = x;
		//roundDump(a, b, c, d);
	}
	out[0] = b;
	out[1] = d;
	out[2] = a;
	out[3] = c;
}

void crypt_yasv(const uint32_t *in, const uint32_t *key, uint32_t *out)
{
	uint32_t a, b, c, d, e, x, i;
	uint32_t k[ROUNDKEY_NUM];
	for (i = 0; i < ROUNDKEY_NUM; ++i)
	{
		k[i] = key[i & (KEY_WORD_LEN - 1)];
	}
	a = in[0];
	b = in[1];
	c = in[2];
	d = in[3];

	roundDump(a, b, c, d);

	for (i = 1; i <= ROUND_NUM; ++i)
	{
		//1 step
		x = a + k[7 * i - 7];
		x = Gn(x, BLOCK_SHIFT_5);
		b ^= x;
		DUMP(a, b, c, d);
		//2 step
		x = d + k[7 * i - 6];
		x = Gn(x, BLOCK_SHIFT_21);
		c ^= x;
		DUMP(a, b, c, d);

		//3 step
		x = b + k[7 * i - 5];
		x = Gn(x, BLOCK_SHIFT_13);
		a -= x;
		DUMP(a, b, c, d);

		//4 step
		x = b + c + k[7 * i - 4];
		x = Gn(x, BLOCK_SHIFT_21);
		e = x ^ i;
		DUMP(a, b, c, d);
		printf("e = 0x%8x\n", e);

		//5 step
		b = b + e;
		DUMP(a, b, c, d);

		//6 step
		c = c - e;
		DUMP(a, b, c, d);

		//7 step
		x = c + k[7 * i - 3];
		x = Gn(x, BLOCK_SHIFT_13);
		d += x;
		DUMP(a, b, c, d);

		//8 step
		x = a + k[7 * i - 2];
		x = Gn(x, BLOCK_SHIFT_21);
		b ^= x;
		DUMP(a, b, c, d);

		//9 step
		x = d + k[7 * i - 1];
		x = Gn(x, BLOCK_SHIFT_5);
		c ^= x;
		DUMP(a, b, c, d);

		//10-12 step
		x = a;
		a = b;
		b = x;
		DUMP(a, b, c, d);
		x = c;
		c = d;
		d = x;
		DUMP(a, b, c, d);
		x = b;
		b = c;
		c = x;
		roundDump(a, b, c, d);
	}
	out[0] = b;
	out[1] = d;
	out[2] = a;
	out[3] = c;
}
