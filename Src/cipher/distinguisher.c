#include "utils.h"
#include "stb_cipher.h"
#include "config.h"
#include <math.h>

extern const uint32_t sub_1[SBLOCK_VAL_COUNT];

uint32_t texts[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_crypt[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_fault[MAX_TEXT_NUM * BLOCK_WORD_LEN];
int maxTexts = 0;
int exitCode = 2;

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
	FILE * temp = fopen("data.temp", "w");;
	FILE * gnuplotPipe = popen ("gnuplot -p", "w");

	char title[17];
	char * const_title = "set title";
	char * commandsForGnuplot[] = {"set boxwidth 1", "set xrange [-1:257] ", "plot 'data.temp' with boxes"};
	uint32_t i;

	for (i = 0; i < size; ++i)
	{
		fprintf(temp, "%d %f\n", i, arr[i]); //Write the data to a temporary file
	}
	sprintf(title, "%s \"%03d\"", const_title, name);
	fprintf(gnuplotPipe, "%s \n", title); //Send commands to gnuplot one by one.
	for (i=0; i < 3; i++)
    {
		fprintf(gnuplotPipe, "%s \n", commandsForGnuplot[i]); //Send commands to gnuplot one by one.
    }
    fclose(temp);
    pclose(gnuplotPipe);
    system("rm -rf data.temp");
}

static uint32_t countDk(double gi[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT], double *dk, const uint32_t n)
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
		//mean += dk[k];
		//s += dk[k] * dk[k];
		if (dk[k] > dk[max])
			max = k;
	}
	/*mean /= SBLOCK_VAL_COUNT;
	printf("mean = %f\n", mean);
	s -= mean * mean;
	printf("var = %f\n", s);
	printf("sigma = %f\n", sqrt(s));
	printf("3 sigma = %f\n", 3 * sqrt(s));
	printf("3 roof = %f\n", mean + 3 * sqrt(s));*/
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

static uint32_t carryCount(uint32_t a, uint32_t k, uint32_t shift)
{
	uint32_t tuda = 32 - shift;
	uint32_t suda = tuda;
	return ((((a << tuda) >> suda) + k) >> shift) & 1;
}

static void waitInput()
{
	do {
		INFO("=================================================================");
		printf("0 - exit;\n");
		printf("1 - next 10 text;\n");
		printf("2 - next 100 texts;\n");
		printf("3 - next 1000 texts;\n");
		printf("4 - next octet;\n");
		printf("5 - close graphics;\n> ");
		scanf("%d", &exitCode);
		if (exitCode == 5)
			system("./kill_gnu.sh");
		INFO("=================================================================");
	} while (exitCode == 5);
}

void generateText(const uint32_t *key, const int round, const int position)
{
	int n = 4 * maxTexts;
	generateBytes(texts + n, BLOCK_BYTE_LEN);
	cryptWithFault(texts + n, key, pair_crypt + n, 0, 0);
	cryptWithFault(texts + n, key, pair_fault + n, round, position);
	antiFinalPerm(pair_crypt + n);
	antiFinalPerm(pair_fault + n);
	++maxTexts;
}

static uint32_t distinguishRoundKey(const uint32_t key[], const int keyInd,
		const int inInd, const int outInd, const int shift, const int round,
		const int position)
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
	sprintf(distKey, "key = 0x%08X", key[keyInd]);
	WARNING(distKey);
	for (i = 0; i < ROUNDKEY_BIT_LEN / 8 && exitCode != 0; ++i)
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
				generateText(key, round, position);
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
				printf("0x%02X (< %d texts)\n", octet, n + 1);
				plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				//if ((n + 1) % 10 == 0)
					waitInput();
			}
			else if (exitCode == 2)
			{
				if ((n + 1) % 10 == 0)
				{
					printf("0x%02X (< %d texts)\n", octet, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 100 == 0)
					waitInput();
			}
			else if (exitCode == 3)
			{
				if ((n + 1) % 100 == 0)
				{
					printf("0x%02X (< %d texts)\n", octet, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 1000 == 0)
					waitInput();
			}
			else
			{
				INFO("exiting distiguisher ... ")
			}
		}
		system("./kill_gnu.sh");
		k_d ^= octet << (8 * i);
		sprintf(keyInfo, "key xor = 0x%08X", key[keyInd] ^ toSTBint(k_d));
		DEBUG(keyInfo);
	}
	return k_d;
}

static uint32_t distinguishSimpleRoundKey(const uint32_t key[],
		const int keyInd_1, const int keyInd_2, const int inInd,
		const int outInd, const int shift_1, const int shift_2)
{
	int n;
	uint32_t out, in, out_f, in_f, in1, in_f1, sum, cut_sum, carry, carry_f, i;
	uint32_t k, k_d, octet;
	uint16_t a, b, index;
	char keyInfo[21];
	char distKey[17];

	sprintf(distKey, "key = 0x%08X", key[keyInd_2]);
	WARNING(distKey);
	in = toSTBint(pair_crypt[inInd]);
	out = toSTBint(pair_crypt[outInd]);
	in_f = toSTBint(pair_fault[inInd]);
	out_f = toSTBint(pair_fault[outInd]);
	sum = in;
	in = Gn(in + toSTBint(key[keyInd_1]), shift_1) ^ out;
	sum -= in_f;
	in_f = Gn(in_f + toSTBint(key[keyInd_1]), shift_1) ^ out_f;
	//printf("0x%08X 0x%08X\n", in, in_f);
	sum = rotLo(sum, shift_2);

	k_d = 0;
	carry = carry_f = 0;
	for (i = 0; i < ROUNDKEY_BIT_LEN / 8; ++i)
	{
		if (i != 0)
		{
			carry = carryCount(in, k_d, 8 * i);
			carry_f = carryCount(in_f, k_d, 8 * i);
		}
		in1 = ((in >> (8 * i)) + carry) & 0xFF;
		in_f1 = ((in_f >> (8 * i)) + carry_f) & 0xFF;
		cut_sum = (sum >> (8 * i)) & 0xFF;
		for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
		{
			a = sub_1[(in1 + k) & 0xFF];
			b = sub_1[(in_f1 + k) & 0xFF];
			index = a - b;
			printf("index = 0x%X\n", index);
			a = (a << shift_2) >> shift_2;
			b = (b << shift_2) >> shift_2;
			index = ((index >> shift_2) ^ (index << (16 - shift_2)));
			index -= ((index >> 15) << shift_2) - ((a - b) >> (16 - shift_2));
			printf("sum = 0x%X index = 0x%X\n", cut_sum, index);
			if (index == cut_sum)
				break;
			waitInput();
		}
		printf("key = 0x%X\n", k);
		k_d ^= k << (8 * i);
		sprintf(keyInfo, "key xor = 0x%08X", key[keyInd_2] ^ toSTBint(k_d));
		DEBUG(keyInfo);
	}
	return k_d;
}

void handDistinguisher()
{
//	uint32_t key[8] = {0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6};
	uint32_t key[8];
	uint32_t key_d[8];
	generateBytes(key, KEY_BYTE_LEN);
	INFO("key = ");
	printf("0x%08X 0x%08X\n", key[6], key[7]);

	key_d[6] = distinguishRoundKey(key, 6, 2, 0, BLOCK_SHIFT_21, 8, 0);
	key_d[7] = distinguishRoundKey(key, 7, 1, 3, BLOCK_SHIFT_5, 8, 0);
	key_d[5] = distinguishSimpleRoundKey(key, 7, 5, 1, 3, BLOCK_SHIFT_5, BLOCK_SHIFT_13);
	INFO("Total xor:")
	printf("0x%08X 0x%08X\n", key[6] ^ key_d[6], key[7] ^ key_d[7]);
}
