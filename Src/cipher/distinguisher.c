#include "utils.h"
#include "stb_cipher.h"
#include "config.h"
#include "distinguisher.h"
#include <math.h>
#include <limits.h>

extern int plotting;
extern const uint32_t sub_1[SBLOCK_VAL_COUNT];
extern const uint32_t sub_2[SBLOCK_VAL_COUNT];
extern const uint32_t sub_3[SBLOCK_VAL_COUNT];
extern const uint32_t sub_4[SBLOCK_VAL_COUNT];

uint32_t texts[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_crypt[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_fault[MAX_TEXT_NUM * BLOCK_WORD_LEN];
static uint32_t key[8];

int maxTexts = 0;
int exitCode = 2;
static int position;
static int prevPos = 0;
static int _round;

static int countKeys = 0;
static int keyFlag = 0;

//static Results k_6[128][MAX_KEYS_NUM];
//static Results k_7[128][MAX_KEYS_NUM];
static Results k_4[128][MAX_KEYS_NUM];

void printTexts(uint32_t * texts)
{
	int i, j;
	for (i = 0; i < 10; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			printf("%08X ", texts[4 * i + j]);
		}
		printf("\n");
	}
}

void plotData(const double arr[], const uint32_t size, const uint32_t name)
{
	if (plotting)
	{
		FILE * temp = fopen("data.temp", "w");
		FILE * gnuplotPipe = popen("gnuplot -p", "w");

		char title[17];
		char * const_title = "set title";
		char * commandsForGnuplot[] = { "set boxwidth 1",
				"set xrange [-1:257] ", "plot 'data.temp' with boxes" };
		uint32_t i;

		for (i = 0; i < size; ++i)
		{
			fprintf(temp, "%d %f\n", i, arr[i]); //Write the data to a temporary file
		}
		sprintf(title, "%s \"%03d\"", const_title, name);
		fprintf(gnuplotPipe, "%s \n", title); //Send commands to gnuplot one by one.
		for (i = 0; i < 3; i++)
		{
			fprintf(gnuplotPipe, "%s \n", commandsForGnuplot[i]); //Send commands to gnuplot one by one.
		}
		fclose(temp);
		pclose(gnuplotPipe);
		system("rm -rf data.temp");
	}
}

static uint32_t countDk(double gi[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT],
		double *dk, const uint32_t n)
{
	uint32_t x, k, max = 0;
	const double mean_t = 1 / (double) SBLOCK_VAL_COUNT;
	double a;

	for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
	{
		dk[k] = 0;
		for (x = 0; x < SBLOCK_VAL_COUNT; ++x)
		{
			a = (gi[k][x] / n) - mean_t;
			dk[k] += a * a;
		}
		if (dk[k] > dk[max])
			max = k;
	}
	return max;
}

static void antiFinalPerm(uint32_t * out)
{
	uint32_t x;
	x = out[1];
	out[1] = out[0];
	out[0] = out[2];
	out[2] = out[3];
	out[3] = x;
}

static uint32_t carryCount(const uint32_t a, const uint32_t k,
		const uint32_t shift)
{
	uint32_t tuda = 32 - shift;
	uint32_t suda = tuda;
	return ((((a << tuda) >> suda) + k) >> shift) & 1;
}

static void waitInput()
{
	do
	{
		INFO(
				"=================================================================");
		printf("0 - exit;\n");
		printf("1 - next 10 text;\n");
		printf("2 - next 100 texts;\n");
		printf("3 - next 1000 texts;\n");
		printf("8 - next 10000 texts;\n");
		printf("4 - next octet;\n");
		printf("5 - close graphics;\n> ");
		scanf("%d", &exitCode);
		if (exitCode == 5)
			system("./kill_gnu.sh");
		INFO(
				"=================================================================");
	} while (exitCode == 5);
}

void generateText()
{
	int n = 4 * maxTexts;
	generateBytes(texts + n, BLOCK_BYTE_LEN);
	cryptWithFault(texts + n, key, pair_crypt + n, 0, 0);
	cryptWithFault(texts + n, key, pair_fault + n, _round, position);
	antiFinalPerm(pair_crypt + n);
	antiFinalPerm(pair_fault + n);
	++maxTexts;
}

void generateCutRoundsText()
{
	int n = 4 * maxTexts;
	generateBytes(texts + n, BLOCK_BYTE_LEN);
	cryptTwoRoundsWithFault(texts + n, key, pair_crypt + n, 0, 0);
	cryptTwoRoundsWithFault(texts + n, key, pair_fault + n, _round, position);
	antiFinalPerm(pair_crypt + n);
	antiFinalPerm(pair_fault + n);
	++maxTexts;
}

static uint32_t distinguishRoundKey_67(const uint32_t roundKey, const int inInd,
		const int outInd, const int shift)
{
	int n;
	uint32_t out, in, out1, in1, out_f, in_f, out_f1, in_f1, carry, carry_f, i;
	uint32_t k, k_d, index, octet;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];
	char keyInfo[21];
	char distKey[17];

	k_d = 0;
	carry = carry_f = 0;
	if (exitCode != 0)
		switchPlotting();
	sprintf(distKey, "key = 0x%08X", roundKey);
	WARNING(distKey);
	for (i = 0; i < ROUNDKEY_BYTE_LEN && exitCode != 0; ++i)
	{
		exitCode = 2;
		// initialize g with 0
		for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
		{
			for (n = 0; n < SBLOCK_VAL_COUNT; ++n)
			{
				g[k][n] = 0;
			}
		}
		for (n = 0; n < MAX_TEXT_NUM && exitCode != 4 && exitCode != 0; ++n)
		{
			// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
			if (n == maxTexts)
				generateText();
			in = pair_crypt[4 * n + inInd];
			out = pair_crypt[4 * n + outInd];
			in_f = pair_fault[4 * n + inInd];
			out_f = pair_fault[4 * n + outInd];
			in1 = toSTBint(in);
			out1 = toSTBint(out);
			in_f1 = toSTBint(in_f);
			out_f1 = toSTBint(out_f);

			if (i != 0)
			{
				carry = carryCount(in1, k_d, 8 * i);
				carry_f = carryCount(in_f1, k_d, 8 * i);
			}
			in1 = ((in1 >> (8 * i)) + carry) & 0xFF;
			in_f1 = ((in_f1 >> (8 * i)) + carry_f) & 0xFF;
			for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
			{
				index = (rotLo(out1 ^ out_f1, shift) >> (8 * i)) & 0xFF;
				index ^= sub_1[(in1 + k) & 0xFF] ^ sub_1[(in_f1 + k) & 0xFF];
				g[k][index]++;
			}
			//INFO("=================================================================");
			octet = countDk(g, dk, n + 1);
			if (exitCode == 1)
			{
				printf("0x%02X\t0x%02X (%d texts)\n", octet,
						(roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
				plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				//if ((n + 1) % 10 == 0)
				waitInput();
			}
			else if (exitCode == 2)
			{
				if ((n + 1) % 10 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 100 == 0)
					waitInput();
			}
			else if (exitCode == 3)
			{
				if ((n + 1) % 100 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 1000 == 0)
					waitInput();
			}
			else if (exitCode == 8)
			{
				if ((n + 1) % 1000 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 10000 == 0)
					waitInput();
			}
			else
			{
				exitCode = 0;
				INFO("exiting distiguisher ... ")
			}
		}
		system("./kill_gnu.sh");
		k_d ^= octet << (8 * i);
		sprintf(keyInfo, "key xor = 0x%08X", roundKey ^ toSTBint(k_d));
		DEBUG(keyInfo);
	}
	return toSTBint(k_d);
}

static void autoDistinguishRoundKey_67(const uint32_t roundKey, const int inInd,
		const int outInd, const int shift, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, carry, carry_f, i;
	uint32_t k, k_d, index, octet;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();
				//generateText();
				in = toSTBint(pair_crypt[4 * n + inInd]);
				out = toSTBint(pair_crypt[4 * n + outInd]);
				in_f = toSTBint(pair_fault[4 * n + inInd]);
				out_f = toSTBint(pair_fault[4 * n + outInd]);

				if (i != 0 && checked == 0)
				{
					carry = carryCount(in, k_d, 8 * i);
					carry_f = carryCount(in_f, k_d, 8 * i);
				}
				in = ((in >> (8 * i)) + carry) & 0xFF;
				in_f = ((in_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index = (rotLo(out ^ out_f, shift) >> (8 * i)) & 0xFF;
					index ^= sub_1[(in + k) & 0xFF] ^ sub_1[(in_f + k) & 0xFF];
					g[k][index]++;
				}
				//INFO("=================================================================");
				//printf("0x%02X\t0x%02X (%d texts)\n", octet, (roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
				octet = countDk(g, dk, n + 1);
				if (octet == ((roundKey >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static void insideRoundKey_5(const uint32_t i, const uint32_t * in,
		const uint32_t * in_f, uint32_t * k_d, const uint32_t check,
		const uint32_t gamma, const int * shift, const uint32_t globalCarry,
		const uint32_t * xor, const uint32_t * checkKey)
{
	uint32_t in1, in_f1, cut_check, carry, carry_f;
	uint32_t k;
	uint32_t a, b, c, index;
	carry = carry_f = 0;
	if (i < ROUNDKEY_BYTE_LEN)
	{
		if (i != 0)
		{
			carry = carryCount(*in, *k_d, 8 * i);
			carry_f = carryCount(*in_f, *k_d, 8 * i);
		}
		in1 = ((*in >> (8 * i)) + carry) & 0xFF;
		in_f1 = ((*in_f >> (8 * i)) + carry_f) & 0xFF;

		for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
		{
			c = 0;
			a = sub_1[(in1 + k) & 0xFF] ^ ((*xor >> (8 * i)) & 0xFF);
			b = sub_1[(in_f1 + k) & 0xFF] ^ ((*xor >> (8 * i)) & 0xFF);
			if (a < b + globalCarry)
				c = 1;
			index = (a - b - globalCarry) & 0xFF;
			cut_check = (check >> (8 * i)) & 0xFF;
			if (index == cut_check)
			{
				//printf("k = 0x%02X\n", k);
				(*k_d) ^= k << (8 * i);
				insideRoundKey_5(i + 1, in, in_f, k_d, check, gamma, shift, c, xor, checkKey);
				(*k_d) ^= k << (8 * i);
			}
		}
	}
	else
	{
		uint32_t g;
		a = *in + *k_d;
		b = *in_f + *k_d;
		a = sub_1[a & 0xFF] ^ sub_2[(a >> 8) & 0xFF] ^ sub_3[(a >> 16) & 0xFF]
				^ sub_4[(a >> 24) & 0xFF];
		b = sub_1[b & 0xFF] ^ sub_2[(b >> 8) & 0xFF] ^ sub_3[(b >> 16) & 0xFF]
				^ sub_4[(b >> 24) & 0xFF];
		a ^= *xor;
		b ^= *xor;
		if (a < b)
			c = 1;
		else
			c = 0;
		g = c << *shift;
		a = (a << *shift) >> *shift;
		b = (b << *shift) >> *shift;
		if (a < b)
			c = 1;
		else
			c = 0;
		g -= c;
		if (gamma == g)
		{
			++countKeys;
			//INFO("=========================================================");
			//printf("key xor = 0x%08X\n", *k_d ^ toSTBint(key[4]));
			if ((*k_d ^ toSTBint(*checkKey)) == 0)
			{
				++keyFlag;
				//ERROR("!!!");
			}
			//INFO("=========================================================");
		}
	}
}

static uint32_t distinguishRoundKey_5(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const int inInd, const int outInd,
		const int shift_1, const int shift_2)
{
	int n;
	uint32_t out, in, out_f, in_f, xor, j;
	uint32_t k_d;
	//uint32_t y, h1, h2;
	uint32_t check[4];
	uint32_t gamma[4];

	//sprintf(distKey, "key = 0x%08X", roundKey_2);
	//WARNING(distKey);
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (n = 0; n < MAX_TEXT_NUM; ++n)
	{
		if (n == maxTexts)
			//generateText();
			generateCutRoundsText();
		in = toSTBint(pair_crypt[4 * n + inInd]);
		out = toSTBint(pair_crypt[4 * n + outInd]);
		in_f = toSTBint(pair_fault[4 * n + inInd]);
		out_f = toSTBint(pair_fault[4 * n + outInd]);
		check[3] = in;
		//y = in;
		in = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
		check[0] = check[1] = check[2] = check[3] -= in_f;
		//y -= in_f;
		check[1] += 1 << shift_2;
		check[2] = check[1] - 1;
		check[3] -= 1;
		check[0] = rotLo(check[0], shift_2);
		check[1] = rotLo(check[1], shift_2);
		check[2] = rotLo(check[2], shift_2);
		check[3] = rotLo(check[3], shift_2);
		in_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
		xor = in ^ in_f;
		if ((xor & 0xFF) && ((xor >> 8) & 0xFF) && ((xor >> 16) & 0xFF)
				&& ((xor >> 24) & 0xFF))
		{
			break;
		}
	}
	/*h1 = in + toSTBint(roundKey_2);
	 h2 = in_f + toSTBint(roundKey_2);
	 h1 = sub_1[h1 & 0xFF] ^ sub_2[(h1 >> 8) & 0xFF] ^ sub_3[(h1 >> 16) & 0xFF] ^ sub_4[(h1 >> 24) & 0xFF];
	 h2 = sub_1[h2 & 0xFF] ^ sub_2[(h2 >> 8) & 0xFF] ^ sub_3[(h2 >> 16) & 0xFF] ^ sub_4[(h2 >> 24) & 0xFF];
	 y = rotHi(h1 - h2, shift_2) - y;
	 printf("0x%08X\n", y);*/
	xor = 0;
	gamma[0] = 0;
	gamma[1] = 1 << shift_2;
	gamma[2] = gamma[1] - 1;
	gamma[3] = -1;
	//printf("0x%08X 0x%08X\n", in, in_f);
	for (j = 0; j < 4; ++j)
	{
		k_d = 0;
		insideRoundKey_5(0, &in, &in_f, &k_d, check[j], gamma[j], &shift_2, 0, &xor, &roundKey_2);
	}
	return k_d;
}

static void autoDistinguishRoundKey_5_2(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const int shift_1, const int shift_2,
		int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, outSum, carry, carry_f, i;
	uint32_t k, k_d, index, octet;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	if (position != prevPos) {
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();

				outSum = in = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = toSTBint(pair_fault[4 * n + 1]);
				outSum += in_f;
				outSum = rotLo(outSum, shift_2);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				in = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
				in_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
				if (i != 0 && checked == 0)
				{
					carry = carryCount(in, k_d, 8 * i);
					carry_f = carryCount(in_f, k_d, 8 * i);
				}
				in = ((in >> (8 * i)) + carry) & 0xFF;
				in_f = ((in_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index = sub_1[(in + k) & 0xFF];
					index += sub_1[(in_f + k) & 0xFF];
					index = ((outSum >> (8 * i)) - index) & 0xFF;
					g[k][index]++;
				}
				octet = countDk(g, dk, n + 1);
				if (octet == ((roundKey_2 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static uint32_t distinguishRoundKey_4_1(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3, const int shift_1,
		const int shift_2, const int shift_3)
{
	int n;
	uint32_t out, in, out_f, in_f, sum, sum_f, outSum, carry, carry_f, i;
	uint32_t k, k_d, octet;
	uint8_t index;
	uint32_t xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];
	char keyInfo[21];
	char distKey[17];

	k_d = 0;
	carry = carry_f = 0;
	xor = rotLo(8, shift_3);

	if (exitCode != 0)
		switchPlotting();
	sprintf(distKey, "key = 0x%08X", roundKey_3);
	WARNING(distKey);

	for (i = 0; i < ROUNDKEY_BYTE_LEN && exitCode != 0; ++i)
	{
		exitCode = 2;
		// initialize g with 0
		memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
		for (n = 0; n < MAX_TEXT_NUM && exitCode != 4 && exitCode != 0; ++n)
		{
			// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
			if (n == maxTexts)
				//generateText();
				generateCutRoundsText();
			in = toSTBint(pair_crypt[4 * n + 2]);
			out = toSTBint(pair_crypt[4 * n]);
			in_f = toSTBint(pair_fault[4 * n + 2]);
			out_f = toSTBint(pair_fault[4 * n]);
			outSum = sum = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
			sum_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
			//printf("0x%08X 0x%08X\n", sum, sum_f);
			outSum += sum_f;
			outSum = rotLo(outSum, shift_3);

			in = toSTBint(pair_crypt[4 * n + 1]);
			out = toSTBint(pair_crypt[4 * n + 3]);
			in_f = toSTBint(pair_fault[4 * n + 1]);
			out_f = toSTBint(pair_fault[4 * n + 3]);
			sum += Gn(in + toSTBint(roundKey_2), shift_2) ^ out;
			sum_f += Gn(in_f + toSTBint(roundKey_2), shift_2) ^ out_f;
			//printf("0x%08X 0x%08X\n", sum, sum_f);
			if (i != 0)
			{
				carry = carryCount(sum, k_d, 8 * i);
				carry_f = carryCount(sum_f, k_d, 8 * i);
			}
			sum = ((sum >> (8 * i)) + carry) & 0xFF;
			sum_f = ((sum_f >> (8 * i)) + carry_f) & 0xFF;
			for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
			{
				index = sub_1[(sum + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
				index += sub_1[(sum_f + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
				//!!!! carry bit!!! for sub_1
				index = ((outSum >> (8 * i)) - index) & 0xFF;
				g[k][index]++;
			}
			//INFO("=================================================================");
			octet = countDk(g, dk, n + 1);
			if (exitCode == 1)
			{
				printf("0x%02X\t0x%02X (%d texts)\n", octet,
						(roundKey_3 >> (8 * (3 - i))) & 0xFF, n + 1);
				plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				//if ((n + 1) % 10 == 0)
				waitInput();
			}
			else if (exitCode == 2)
			{
				if ((n + 1) % 10 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey_3 >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 100 == 0)
					waitInput();
			}
			else if (exitCode == 3)
			{
				if ((n + 1) % 100 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey_3 >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 1000 == 0)
					waitInput();
			}
			else if (exitCode == 8)
			{
				if ((n + 1) % 1000 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet,
							(roundKey_3 >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 10000 == 0)
					waitInput();
			}
			else
			{
				exitCode = 0;
				INFO("exiting distiguisher ... ")
			}
		}
		system("./kill_gnu.sh");
		k_d ^= octet << (8 * i);
		sprintf(keyInfo, "key xor = 0x%08X", roundKey_3 ^ toSTBint(k_d));
		DEBUG(keyInfo);
	}
	return toSTBint(k_d);
}

static void autoDistinguishRoundKey_4_1(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3, const int shift_1,
		const int shift_2, const int shift_3, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, sum, sum_f, outSum, carry, carry_f, b_carry, i;
	uint32_t k, k_d, index, octet, xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	xor = rotLo(8, shift_3);
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					//generateText();
					generateCutRoundsText();
				in = toSTBint(pair_crypt[4 * n + 2]);
				out = toSTBint(pair_crypt[4 * n]);
				in_f = toSTBint(pair_fault[4 * n + 2]);
				out_f = toSTBint(pair_fault[4 * n]);
				outSum = sum = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
				sum_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
				outSum += sum_f;
				outSum = rotLo(outSum, shift_3);

				in = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = toSTBint(pair_fault[4 * n + 1]);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				sum += Gn(in + toSTBint(roundKey_2), shift_2) ^ out;
				sum_f += Gn(in_f + toSTBint(roundKey_2), shift_2) ^ out_f;

				b_carry = 0;
				if (i != 0)
				{
					int j;
					uint32_t in1, in1_f;
					for (j = 0; j < i; ++j)
					{
						in1 = ((sum >> (8 * j)) + carry) & 0xFF;
						in1_f = ((sum_f >> (8 * j)) + carry_f) & 0xFF;
						index = sub_1[(in1 + ((roundKey_3 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						index += sub_1[(in1_f	+ ((roundKey_3 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						if (((outSum >> (8 * j)) && 0xFF) < index + b_carry)
							b_carry = 1;
						else
							b_carry = 0;
					}
				}
				if (i != 0 && checked == 0)
				{
					carry = carryCount(sum, k_d, 8 * i);
					carry_f = carryCount(sum_f, k_d, 8 * i);
				}
				sum = ((sum >> (8 * i)) + carry) & 0xFF;
				sum_f = ((sum_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index =  sub_1[(sum + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
					index += sub_1[(sum_f + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
					//!!!! carry bit!!! for sub_1
					index = ((outSum >> (8 * i)) - index - b_carry) & 0xFF;
					g[k][index]++;
				}
				//INFO("=================================================================");
				octet = countDk(g, dk, n + 1);

				if (octet == ((roundKey_3 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static uint32_t distinguishRoundKey_4_2(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3)
{
	int n, shift;
	uint32_t out, in, out_f, in_f, sum, sum_f, xor, j;
	uint32_t k_d;
	uint32_t check[4];
	uint32_t gamma[4];

	for (n = 0; n < MAX_TEXT_NUM; ++n)
	{
		if (n == maxTexts)
			generateCutRoundsText();

		in = toSTBint(pair_crypt[4 * n + 2]);
		out = toSTBint(pair_crypt[4 * n]);
		in_f = toSTBint(pair_fault[4 * n + 2]);
		out_f = toSTBint(pair_fault[4 * n]);
		sum = Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
		sum_f = Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;

		in = toSTBint(pair_crypt[4 * n + 1]);
		out = toSTBint(pair_crypt[4 * n + 3]);
		in_f = toSTBint(pair_fault[4 * n + 1]);
		out_f = toSTBint(pair_fault[4 * n + 3]);
		in = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
		in_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;
		check[3] = in;
		check[0] = check[1] = check[2] = check[3] -= in_f;
		check[1] += 1 << BLOCK_SHIFT_21;
		check[2] = check[1] - 1;
		check[3] -= 1;
		check[0] = rotLo(check[0], BLOCK_SHIFT_21);
		check[1] = rotLo(check[1], BLOCK_SHIFT_21);
		check[2] = rotLo(check[2], BLOCK_SHIFT_21);
		check[3] = rotLo(check[3], BLOCK_SHIFT_21);
		sum += in;
		sum_f += in_f;
		xor = sum ^ sum_f;
		if ((xor & 0xFF) && ((xor >> 8) & 0xFF) && ((xor >> 16) & 0xFF)
				&& ((xor >> 24) & 0xFF))
		{
			break;
		}
	}

	xor = rotLo(8, BLOCK_SHIFT_21);
	gamma[0] = 0;
	gamma[1] = 1 << BLOCK_SHIFT_21;
	gamma[2] = gamma[1] - 1;
	gamma[3] = -1;
	shift = BLOCK_SHIFT_21;
	for (j = 0; j < 4; ++j)
	{
		k_d = 0;
		insideRoundKey_5(0, &sum_f, &sum, &k_d, check[j], gamma[j], &shift, 0, &xor, &roundKey_3);
	}
	return k_d;
}

static void autoDistinguishRoundKey_4_4(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, sum, sum_f, outSum, carry, carry_f, b_carry, i;
	uint32_t k, k_d, index, octet, xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	xor = rotLo(8, BLOCK_SHIFT_21);
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();

				in = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = toSTBint(pair_fault[4 * n + 1]);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				outSum = sum = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
				sum_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;
				outSum += sum_f;
				outSum = rotLo(outSum, BLOCK_SHIFT_21);

				in = toSTBint(pair_crypt[4 * n + 2]);
				out = toSTBint(pair_crypt[4 * n]);
				in_f = toSTBint(pair_fault[4 * n + 2]);
				out_f = toSTBint(pair_fault[4 * n]);
				sum += Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
				sum_f += Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;

				b_carry = 0;
				if (i != 0)
				{
					int j;
					uint32_t in1, in1_f;
					for (j = 0; j < i; ++j)
					{
						in1 = ((sum >> (8 * j)) + carry) & 0xFF;
						in1_f = ((sum_f >> (8 * j)) + carry_f) & 0xFF;
						index = sub_1[(in1 + ((roundKey_3 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						index += sub_1[(in1_f + ((roundKey_3 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						b_carry = (((outSum >> (8 * j)) & 0xFF) + index + b_carry) >> (8 * (j + 1));
					}
				}
				if (i != 0 && checked == 0)
				{
					carry = carryCount(sum, k_d, 8 * i);
					carry_f = carryCount(sum_f, k_d, 8 * i);
				}
				sum = ((sum >> (8 * i)) + carry) & 0xFF;
				sum_f = ((sum_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index =  sub_1[(sum + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
					index += sub_1[(sum_f + k) & 0xFF] ^ ((xor >> (8 * i)) & 0xFF);
					index = ((outSum >> (8 * i)) + index + b_carry) & 0xFF;
					g[k][index]++;
				}
				//INFO("=================================================================");
				octet = countDk(g, dk, n + 1);

				if (octet == ((roundKey_3 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static void autoDistinguishRoundKey_3(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3,
		const uint32_t roundKey_4, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, sum, sum_f, outSum, carry, carry_f, b_carry, i;
	uint32_t k, k_d, index, octet, xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	xor = 8;
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();

				in = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = toSTBint(pair_fault[4 * n + 1]);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				sum = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
				sum_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;

				in = toSTBint(pair_crypt[4 * n + 2]);
				out = toSTBint(pair_crypt[4 * n]);
				in_f = toSTBint(pair_fault[4 * n + 2]);
				out_f = toSTBint(pair_fault[4 * n]);
				outSum = in + in_f;
				outSum = rotLo(outSum, BLOCK_SHIFT_13);
				in = Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
				in_f = Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;
				sum += in;
				sum_f += in_f;

				in -= (Gn(sum + toSTBint(roundKey_3), BLOCK_SHIFT_21) ^ xor);
				in_f -= (Gn(sum_f + toSTBint(roundKey_3), BLOCK_SHIFT_21) ^ xor);
				/*printf("%08X %08X\n", in, in_f);
				getchar();
				getchar();*/

				b_carry = 0;
				if (i != 0)
				{
					int j;
					uint32_t in1, in1_f;
					for (j = 0; j < i; ++j)
					{
						in1 = ((in >> (8 * j)) + carry) & 0xFF;
						in1_f = ((in_f >> (8 * j)) + carry_f) & 0xFF;
						index = sub_1[(in1 + ((roundKey_4 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						index += sub_1[(in1_f	+ ((roundKey_4 >> (8 * (3 - j))) & 0xFF)) & 0xFF];
						b_carry = (((outSum >> (8 * j)) & 0xFF) + index + b_carry) >> (8 * (j + 1));
					}
				}
				if (i != 0 && checked == 0)
				{
					carry = carryCount(in, k_d, 8 * i);
					carry_f = carryCount(in_f, k_d, 8 * i);
				}
				in = ((in >> (8 * i)) + carry) & 0xFF;
				in_f = ((in_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index =  sub_1[(in + k) & 0xFF];
					index += sub_1[(in_f + k) & 0xFF];
					index = ((outSum >> (8 * i)) + index + b_carry) & 0xFF;
					g[k][index]++;
				}
				//INFO("=================================================================");
				octet = countDk(g, dk, n + 1);

				if (octet == ((roundKey_4 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static void autoDistinguishRoundKey_2_1(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3,
		const uint32_t roundKey_4, const uint32_t roundKey_5, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, out1, out1_f, sum, sum_f, carry, carry_f, i;
	uint32_t k, k_d, index, octet, xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	xor = 8;
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();

				in = toSTBint(pair_crypt[4 * n + 2]);
				out = toSTBint(pair_crypt[4 * n]);
				in_f = toSTBint(pair_fault[4 * n + 2]);
				out_f = toSTBint(pair_fault[4 * n]);
				sum = Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
				sum_f = Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;

				in = out1 = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = out1_f = toSTBint(pair_fault[4 * n + 1]);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				in = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
				in_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;
				sum += in;
				sum_f += in_f;

				out = in + (Gn(sum + toSTBint(roundKey_4), BLOCK_SHIFT_21) ^ xor);
				out_f = in_f + (Gn(sum_f + toSTBint(roundKey_4), BLOCK_SHIFT_21) ^ xor);
				//printf("out = 0x%08X 0x%08X\n", out, out_f);
				in = out1 - Gn(in + toSTBint(roundKey_3), BLOCK_SHIFT_13);
				in_f = out1_f - Gn(in_f + toSTBint(roundKey_3), BLOCK_SHIFT_13);
				/*printf("%08X %08X\n", in, in_f);
				 getchar();
				 getchar();*/

				if (i != 0 && checked == 0)
				{
					carry = carryCount(in, k_d, 8 * i);
					carry_f = carryCount(in_f, k_d, 8 * i);
				}
				in = ((in >> (8 * i)) + carry) & 0xFF;
				in_f = ((in_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index = (rotLo(out ^ out_f, BLOCK_SHIFT_21) >> (8 * i)) & 0xFF;
					index ^= sub_1[(in + k) & 0xFF] ^ sub_1[(in_f + k) & 0xFF];
					g[k][index]++;
				}
				octet = countDk(g, dk, n + 1);
				if (octet == ((roundKey_5 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

static void insideRoundKey_2(const uint32_t i, const uint32_t * in,
		const uint32_t * in_f, const uint32_t * sum,
		uint32_t * k_d, const uint32_t * checkKey)
{
	uint32_t in1, in_f1, sum1, carry, carry_f;
	uint32_t k;
	uint32_t index;
	carry = carry_f = 0;
	if (i < ROUNDKEY_BYTE_LEN)
	{
		if (i != 0)
		{
			carry = carryCount(*in, *k_d, 8 * i);
			carry_f = carryCount(*in_f, *k_d, 8 * i);
		}
		in1 = ((*in >> (8 * i)) + carry) & 0xFF;
		in_f1 = ((*in_f >> (8 * i)) + carry_f) & 0xFF;
		sum1 = (*sum >> (8 * i)) & 0xFF;

		for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
		{
			index = sub_1[(in1 + k) & 0xFF] ^ sub_1[(in_f1 + k) & 0xFF] ^ sum1;
			if (index == 0)
			{
				//printf("k = 0x%02X\n", k);
				(*k_d) ^= k << (8 * i);
				insideRoundKey_2(i + 1, in, in_f, sum, k_d, checkKey);
				(*k_d) ^= k << (8 * i);
			}
		}
	}
	else
	{
		++countKeys;
		if ((*k_d ^ toSTBint(*checkKey)) == 0)
		{
			++keyFlag;
		}
	}
}

static void distinguishRoundKey_2_2(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3,
		const uint32_t roundKey_4, const uint32_t roundKey_5)
{
	int n;
	uint32_t out, in, out_f, out1, out1_f, in_f, sum, sum_f, xor;
	uint32_t k_d;

	xor = 8;
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	maxTexts = 0;
	for (n = 0; n < MAX_TEXT_NUM; ++n)
	{
		if (n == maxTexts)
			//generateText();
			generateCutRoundsText();

		in = toSTBint(pair_crypt[4 * n + 2]);
		out = toSTBint(pair_crypt[4 * n]);
		in_f = toSTBint(pair_fault[4 * n + 2]);
		out_f = toSTBint(pair_fault[4 * n]);
		sum = Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
		sum_f = Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;

		in = out1 = toSTBint(pair_crypt[4 * n + 1]);
		out = toSTBint(pair_crypt[4 * n + 3]);
		in_f = out1_f = toSTBint(pair_fault[4 * n + 1]);
		out_f = toSTBint(pair_fault[4 * n + 3]);
		in = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
		in_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;
		sum += in;
		sum_f += in_f;

		out = in + (Gn(sum + toSTBint(roundKey_4), BLOCK_SHIFT_21) ^ xor);
		out_f = in_f + (Gn(sum_f + toSTBint(roundKey_4), BLOCK_SHIFT_21) ^ xor);
		//printf("out = 0x%08X 0x%08X\n", out, out_f);
		in = out1 - Gn(in + toSTBint(roundKey_3), BLOCK_SHIFT_13);
		in_f = out1_f - Gn(in_f + toSTBint(roundKey_3), BLOCK_SHIFT_13);
		//printf("in = 0x%08X 0x%08X\n", in, in_f);
		//getchar();
		//getchar();
		xor = in ^ in_f;
		if ((xor & 0xFF) && ((xor >> 8) & 0xFF) && ((xor >> 16) & 0xFF)
				&& ((xor >> 24) & 0xFF))
		{
			break;
		}
	}
	sum = out ^ out_f;
	sum = rotLo(sum, BLOCK_SHIFT_21);
	k_d = 0;
	insideRoundKey_2(0, &in, &in_f, &sum, &k_d, &roundKey_5);
}

static void autoDistinguishRoundKey_1(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3,
		const uint32_t roundKey_4, const uint32_t roundKey_5, int * r)
{
	int n, counter, checked;
	uint32_t out, in, out_f, in_f, sum, sum_f, carry, carry_f, i;
	uint32_t k, k_d, index, octet, xor;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	xor = 8;
	if (position != prevPos)
	{
		maxTexts = 0;
		prevPos = position;
	}
	for (i = 0; i < ROUNDKEY_BYTE_LEN; ++i)
	{
		do
		{
			counter = 0;
			memset(g, 0, SBLOCK_VAL_COUNT * SBLOCK_VAL_COUNT * sizeof(double));
			if (checked == 1)
			{
				carry = 0;
				carry_f = 0;
			}
			else if (checked == 2)
			{
				carry = 1;
				carry_f = 0;
			}
			else if (checked == 3)
			{
				carry = 0;
				carry_f = 1;
			}
			else if (checked == 4)
			{
				carry = 1;
				carry_f = 1;
			}
			for (n = 0; n < MAX_TEXT_NUM && counter != MAX_REPEAT_NUM; ++n)
			{
				// generation of texts and pairs of cipher text and fault cipher text if exitCode == 1;
				if (n == maxTexts)
					generateCutRoundsText();

				in = toSTBint(pair_crypt[4 * n + 1]);
				out = toSTBint(pair_crypt[4 * n + 3]);
				in_f = toSTBint(pair_fault[4 * n + 1]);
				out_f = toSTBint(pair_fault[4 * n + 3]);
				sum = Gn(in + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out;
				sum_f = Gn(in_f + toSTBint(roundKey_2), BLOCK_SHIFT_5) ^ out_f;

				in = toSTBint(pair_crypt[4 * n + 2]);
				out = toSTBint(pair_crypt[4 * n]);
				in_f = toSTBint(pair_fault[4 * n + 2]);
				out_f = toSTBint(pair_fault[4 * n]);
				out = Gn(in + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out;
				out_f = Gn(in_f + toSTBint(roundKey_1), BLOCK_SHIFT_21) ^ out_f;
				sum += out;
				sum_f += out_f;

				out -= (Gn(sum + toSTBint(roundKey_3), BLOCK_SHIFT_21) ^ xor);
				out_f -= (Gn(sum_f + toSTBint(roundKey_3), BLOCK_SHIFT_21) ^ xor);
				in += Gn(out + toSTBint(roundKey_4), BLOCK_SHIFT_13);
				in_f += Gn(out_f + toSTBint(roundKey_4), BLOCK_SHIFT_13);
				/*printf("in =  %08X %08X\n", in, in_f);
				printf("out = %08X %08X\n", out, out_f);
				getchar();
				getchar();*/

				if (i != 0 && checked == 0)
				{
					carry = carryCount(in, k_d, 8 * i);
					carry_f = carryCount(in_f, k_d, 8 * i);
				}
				in = ((in >> (8 * i)) + carry) & 0xFF;
				in_f = ((in_f >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index = (rotLo(out ^ out_f, BLOCK_SHIFT_5) >> (8 * i)) & 0xFF;
					index ^= sub_1[(in + k) & 0xFF] ^ sub_1[(in_f + k) & 0xFF];
					g[k][index]++;
				}
				//INFO("=================================================================");
				octet = countDk(g, dk, n + 1);

				if (octet == ((roundKey_5 >> (8 * (3 - i))) & 0xFF))
					++counter;
				else
					counter = 0;
			}
			if (n < MAX_TEXT_NUM || counter == MAX_REPEAT_NUM)
			{
				r[i] = n;
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				r[i] = -1;
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
}

void handDistinguisher()
{
	uint32_t key_d[KEY_WORD_LEN];
	generateBytes(key, KEY_BYTE_LEN);
	memset(key_d, 0, sizeof(key_d));
	_round = 8;
	position = 32;
	INFO("key = ");
	printf("0x%08X 0x%08X 0x%08X\n", key[6], key[7], key[4]);

	//key_d[3] = distinguishRoundKey_67(key[6], 2, 0, BLOCK_SHIFT_21);
	autoDistinguishRoundKey_3(key[6], key[7], key[4], key[3], k_4[position][0].bytes);
	//key_d[7] = distinguishRoundKey_67(key[7], 1, 3, BLOCK_SHIFT_5);
	//key_d[5] = distinguishRoundKey_5(key[7], key[5], 1, 3, BLOCK_SHIFT_5, BLOCK_SHIFT_13);
	//distinguishRoundKey_4_2(key[6], key[7], key[4], BLOCK_SHIFT_21, BLOCK_SHIFT_5, BLOCK_SHIFT_21);
	INFO("Total xor:")
	printf("0x%08X 0x%08X\n", key[6] ^ key_d[6], key[7] ^ key_d[7]);
	INFO("Total stat:");
	printf("\ttotal keys  = %d\n\tresult key  = %d\n\ttotal texts = %d\n",
			countKeys, keyFlag, maxTexts);
}

int resultKeys[96][MAX_KEYS_NUM];
int resultText[96][MAX_KEYS_NUM];

void autoDistinguisher_2()
{
	clock_t c;
	FILE *f_1, *f_2;
	int i, j;
	const int minPos = 32;
	const int maxPos = 48;

	_round = 8;
	f_1 = fopen("result_key_5_KeysNumber_32-48.csv", "w");
	f_2 = fopen("result_key_5_TextNumber_32-48.csv", "w");
	c = clock();
	for (i = 0; i < MAX_KEYS_NUM; ++i)
	{
		printf("i = %d\n", i);
		generateBytes(key, KEY_BYTE_LEN);
		for (position = minPos; position < maxPos; ++position)
		{
			distinguishRoundKey_5(key[7], key[5], 1, 3, BLOCK_SHIFT_5, BLOCK_SHIFT_13);
			//distinguishRoundKey_4_2(key[6], key[7], key[4]);
			//distinguishRoundKey_2_2(key[6], key[7], key[5], key[4], key[2]);
			resultText[position][i] = maxTexts;
			if (keyFlag == 1)
				resultKeys[position][i] = countKeys;
			else
				resultKeys[position][i] = -1;
			countKeys = 0;
			keyFlag = 0;
		}

	}
	for (i = minPos; i < position; ++i)
	{
		fprintf(f_1, "%3d", i);
		fprintf(f_2, "%3d", i);
		for (j = 0; j < MAX_KEYS_NUM; ++j)
		{
			fprintf(f_1, "; %d", resultKeys[i][j]);
			fprintf(f_2, "; %d", resultText[i][j]);
		}
		fprintf(f_1, "\n");
		fprintf(f_2, "\n");
	}
	/*for (position = minPos; position < maxPos; ++position)
	{
		fprintf(f_1, "%3d", position);
		fprintf(f_2, "%3d", position);
		for (i = 0; i < MAX_KEYS_NUM; ++i) {
			generateBytes(key, KEY_BYTE_LEN);
			distinguishRoundKey_5(key[7], key[5], 1, 3, BLOCK_SHIFT_5, BLOCK_SHIFT_13);
			//distinguishRoundKey_4_2(key[6], key[7], key[4]);
			//distinguishRoundKey_2_2(key[6], key[7], key[5], key[4], key[2]);
			fprintf(f_2, "; %d", maxTexts);
			if (keyFlag == 1)
				fprintf(f_1, "; %d", countKeys);
			else
				fprintf(f_1, "; %d", -1);
			countKeys = 0;
			keyFlag = 0;
			maxTexts = 0;
		}
		fprintf(f_1, "\n");
		fprintf(f_2, "\n");
	}
	printf("time = %ld\n", (clock() - c) / CLOCKS_PER_SEC);*/
	fclose(f_1);
	fclose(f_2);
}

void autoDistinguisher()
{
	clock_t c;
	int i, j, l;
	const int minPos = 88;
	const int maxPos = 96;
	prevPos = 0;
	//FILE * f_6;
	FILE * f_7;

	//f_6 = fopen("result_key_6.csv", "w");
	f_7 = fopen("result_key_3_7r.csv.88-96, "w");

	_round = 7;
	c = clock();
	for (i = 0; i < MAX_KEYS_NUM; ++i)
	{
		printf("i = %d\n", i);
		generateBytes(key, KEY_BYTE_LEN);
		for (position = minPos; position < maxPos; ++position)
		{
			//printf("position = %d\n", position);
			//autoDistinguishRoundKey_67(key[6], 2, 0, BLOCK_SHIFT_21, k_6[position][i].bytes);
			//autoDistinguishRoundKey_67(key[7], 1, 3, BLOCK_SHIFT_5, k_7[position][i].bytes);
			//autoDistinguishRoundKey_2_1(key[6], key[7], key[5], key[4], key[2], k_4[position][i].bytes);
			//autoDistinguishRoundKey_1(key[6], key[7], key[4], key[3], key[1], k_4[position][i].bytes);
			autoDistinguishRoundKey_3(key[6], key[7], key[4], key[3], k_4[position][i].bytes);
			//autoDistinguishRoundKey_5_2(key[7], key[6], BLOCK_SHIFT_5, BLOCK_SHIFT_13, k_4[position][i].bytes);
			//autoDistinguishRoundKey_4_1(key[6], key[7], key[4], BLOCK_SHIFT_21, BLOCK_SHIFT_5, BLOCK_SHIFT_21, k_4[position][i].bytes);
<<<<<<< HEAD
			autoDistinguishRoundKey_4_4(key[6], key[7], key[4], k_4[position][i].bytes);
=======
			//autoDistinguishRoundKey_4_4(key[6], key[7], key[4], BLOCK_SHIFT_21, BLOCK_SHIFT_5, BLOCK_SHIFT_21, k_4[position][i].bytes);
>>>>>>> one
		}
	}
	for (i = minPos; i < position; ++i)
	{
		for (l = 0; l < ROUNDKEY_BYTE_LEN; ++l)
		{
			//fprintf(f_6, "%3d", i);
			fprintf(f_7, "%3d", i);
			for (j = 0; j < MAX_KEYS_NUM; ++j)
			{
				//fprintf(f_6, "; %d", k_6[i][j].bytes[l]);
				//fprintf(f_7, "; %d", k_7[i][j].bytes[l]);
				fprintf(f_7, "; %d", k_4[i][j].bytes[l]);
			}
			//fprintf(f_6, "\n");
			fprintf(f_7, "\n");
		}
	}
	printf("time = %ld\n", (clock() - c) / CLOCKS_PER_SEC);
	//fclose(f_6);
	fclose(f_7);
}
