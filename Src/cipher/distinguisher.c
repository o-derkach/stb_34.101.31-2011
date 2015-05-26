#include "utils.h"
#include "stb_cipher.h"
#include "config.h"
#include "distinguisher.h"
#include <math.h>

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
int globalPos;

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
		char * commandsForGnuplot[] = {"set boxwidth 1", "set xrange [-1:257] ", "plot 'data.temp' with boxes"};
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

static uint32_t carryCount(const uint32_t a, const uint32_t k, const uint32_t shift)
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
		printf("8 - next 10000 texts;\n");
		printf("4 - next octet;\n");
		printf("5 - close graphics;\n> ");
		scanf("%d", &exitCode);
		if (exitCode == 5)
			system("./kill_gnu.sh");
		INFO("=================================================================");
	} while (exitCode == 5);
}

void generateText(const int round, const int position)
{
	int n = 4 * maxTexts;
	generateBytes(texts + n, BLOCK_BYTE_LEN);
	cryptWithFault(texts + n, key, pair_crypt + n, 0, 0);
	cryptWithFault(texts + n, key, pair_fault + n, round, position);
	antiFinalPerm(pair_crypt + n);
	antiFinalPerm(pair_fault + n);
	++maxTexts;
}

static uint32_t distinguishRoundKey_67(const uint32_t roundKey,
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
	if (exitCode != 0)
		switchPlotting();
	sprintf(distKey, "key = 0x%08X", roundKey);
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
				generateText(round, position);
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
				printf("0x%02X\t0x%02X (%d texts)\n", octet, (roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
				plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				//if ((n + 1) % 10 == 0)
					waitInput();
			}
			else if (exitCode == 2)
			{
				if ((n + 1) % 10 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet, (roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
					plotData(dk, SBLOCK_VAL_COUNT, n + 1);
				}
				if ((n + 1) % 100 == 0)
					waitInput();
			}
			else if (exitCode == 3)
			{
				if ((n + 1) % 100 == 0)
				{
					printf("0x%02X\t0x%02X (%d texts)\n", octet, (roundKey >> (8 * (3 - i))) & 0xFF, n + 1);
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

static void autoDistinguishRoundKey_67(const uint32_t roundKey,
		const int inInd, const int outInd, const int shift, const int round,
		const int position, FILE *f)
{
	int n, counter, checked;
	uint32_t out, in, out1, in1, out_f, in_f, out_f1, in_f1, carry, carry_f, i;
	uint32_t k, k_d, index, octet;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	k_d = 0;
	carry = carry_f = 0;
	checked = 0;
	if (position != globalPos)
	{
		maxTexts = 0;
		globalPos = position;
	}
	fprintf(f, "%2d", position);
	for (i = 0; i < ROUNDKEY_BIT_LEN / 8; ++i)
	{
		do
		{
			counter = 0;
			for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
			{
				for (n = 0; n < SBLOCK_VAL_COUNT; ++n)
				{
					g[k][n] = 0;
				}
			}
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
					generateText(round, position);
				in = pair_crypt[4 * n + inInd];
				out = pair_crypt[4 * n + outInd];
				in_f = pair_fault[4 * n + inInd];
				out_f = pair_fault[4 * n + outInd];
				in1 = toSTBint(in);
				out1 = toSTBint(out);
				in_f1 = toSTBint(in_f);
				out_f1 = toSTBint(out_f);

				if (i != 0 && checked == 0)
				{
					carry = carryCount(in1, k_d, 8 * i);
					carry_f = carryCount(in_f1, k_d, 8 * i);
				}
				in1 = ((in1 >> (8 * i)) + carry) & 0xFF;
				in_f1 = ((in_f1 >> (8 * i)) + carry_f) & 0xFF;
				for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
				{
					index = (rotLo(out1 ^ out_f1, shift) >> (8 * i)) & 0xFF;
					index ^= sub_1[(in1 + k) & 0xFF]
							^ sub_1[(in_f1 + k) & 0xFF];
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
				fprintf(f, "\t%4d (%4d)", n, n - counter);
				k_d ^= octet << (8 * i);
				checked = 0;
				break;
			}
			else if (checked == 0 || checked == 1)
			{
				fprintf(f, "\t%4d (%4d)", n, n);
				checked = 4;
				break;
			}
			--checked;
		} while (checked != 0);
	}
	fprintf(f, "\n");
}

static int insideRoundKey_5(const uint32_t i, const uint32_t * in,
		const uint32_t * in_f, uint32_t * k_d, const uint32_t check,
		const uint32_t gamma, const int * shift, const uint32_t globalCarry)
{
	uint32_t in1, in_f1, cut_check, carry, carry_f;
	uint32_t k;
	uint32_t a, b, c, index;
	int res;
	carry = carry_f = 0;
	if (i < ROUNDKEY_BIT_LEN / 8)
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
			a = sub_1[(in1 + k) & 0xFF];
			b = sub_1[(in_f1 + k) & 0xFF];
			if (a < b + globalCarry)
				c = 1;
			index = (a - b - globalCarry) & 0xFF;
			cut_check = (check >> (8 * i)) & 0xFF;
			if (index == cut_check)
			{
				(*k_d) ^= k << (8 * i);
				printf("%02X\n", k);
				printf("%08X\n", *k_d);
				getchar();
				res = insideRoundKey_5(i + 1, in, in_f, k_d, check, gamma, shift, c);
				if (!res)
					(*k_d) ^= k << (8 * i);
				else
					return res;
			}
		}
		return 0;
	}
	else
	{
		uint32_t g;
		a = *in + *k_d;
		b = *in_f + *k_d;
		a = sub_1[a & 0xFF] ^ sub_2[(a >> 8) & 0xFF] ^ sub_3[(a >> 16) & 0xFF] ^ sub_4[(a >> 24) & 0xFF];
		b = sub_1[b & 0xFF] ^ sub_2[(b >> 8) & 0xFF] ^ sub_3[(b >> 16) & 0xFF] ^ sub_4[(b >> 24) & 0xFF];
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
			return 1;
		else
			return 0;
	}
}

static uint32_t distinguishRoundKey_5(const uint32_t roundKey_1, const uint32_t roundKey_2, const int inInd,
		const int outInd, const int shift_1, const int shift_2)
{
	uint32_t out, in, out_f, in_f, in1, in_f1, i, j;
	uint32_t k_d;
	uint32_t check[4];
	uint32_t gamma[4];
	char keyInfo[21];
	char distKey[17];

	sprintf(distKey, "key = 0x%08X", roundKey_2);
	WARNING(distKey);
	for (i = 0; i < maxTexts; ++i)
	{
		in = toSTBint(pair_crypt[4 * i + inInd]);
		out = toSTBint(pair_crypt[4 * i + outInd]);
		in_f = toSTBint(pair_fault[4 * i + inInd]);
		out_f = toSTBint(pair_fault[4 * i + outInd]);
		check[3] = in;
		in = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
		check[0] = check[1] = check[2] = check[3] -= in_f;
		//printf("0x%08X 0x%08X 0x%08X 0x%08X\n", check[0], check[1], check[2], check[3]);
		check[1] += 1 << shift_2;
		check[2] = check[1] - 1;
		check[3] -= 1;
		rotLo(check[0], shift_2);
		rotLo(check[1], shift_2);
		rotLo(check[2], shift_2);
		rotLo(check[3], shift_2);
		//printf("0x%08X 0x%08X 0x%08X 0x%08X\n", check[0], check[1], check[2], check[3]);
		in_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
		in1 = in & 0xFF;
		in_f1 = in_f & 0xFF;
		if (in1 != in_f1)
		{
			break;
		}
	}

	gamma[0] = 0;
	gamma[1] = 1 << shift_2;
	gamma[2] = gamma[1] - 1;
	gamma[3] = -1;
	printf("0x%08X 0x%08X\n", in, in_f);
	for (j = 0; j < 4; ++j)
	{
		INFO("next j");
		k_d = 0;
		if (insideRoundKey_5(0, &in, &in_f, &k_d, check[j], gamma[j], &shift_2, 0))
			break;
	}
	sprintf(keyInfo, "key xor = 0x%08X", roundKey_2 ^ toSTBint(k_d));
	DEBUG(keyInfo);
	return k_d;
}

static uint32_t distinguishRoundKey_4(const uint32_t roundKey_1,
		const uint32_t roundKey_2, const uint32_t roundKey_3, const int shift_1,
		const int shift_2, const int shift_3)
{
	uint32_t out, in, out_f, in_f, sum, sum_f, in1, in_f1, cut, carry, carry_f, i, j;
	uint32_t k, k_d, octet;
	uint8_t a, b, index;
	uint32_t check[4];
	char keyInfo[21];
	char distKey[17];

	sprintf(distKey, "key = 0x%08X", roundKey_3);
	WARNING(distKey);

	in = toSTBint(pair_crypt[2]);
	out = toSTBint(pair_crypt[0]);
	in_f = toSTBint(pair_fault[2]);
	out_f = toSTBint(pair_fault[0]);
	sum = Gn(in + toSTBint(roundKey_1), shift_1) ^ out;
	sum_f = Gn(in_f + toSTBint(roundKey_1), shift_1) ^ out_f;
	//printf("0x%08X 0x%08X\n", sum, sum_f);
	check[3] = sum_f;
	check[0] = check[1] = check[2] = check[3] -= sum;
	check[1] += 1 << shift_3;
	check[2] = check[1] - 1;
	check[3] -= 1;
	rotLo(check[0], shift_3);
	rotLo(check[1], shift_3);
	rotLo(check[2], shift_3);
	rotLo(check[3], shift_3);
	//printf("0x%08X 0x%08X 0x%08X 0x%08X\n", check[0], check[1], check[2], check[3]);
	in = toSTBint(pair_crypt[1]);
	out = toSTBint(pair_crypt[3]);
	in_f = toSTBint(pair_fault[1]);
	out_f = toSTBint(pair_fault[3]);
	sum += Gn(in + toSTBint(roundKey_2), shift_2) ^ out;
	sum_f += Gn(in_f + toSTBint(roundKey_2), shift_2) ^ out_f;

	k_d = 0;
	carry = carry_f = 0;
	printf("0x%08X 0x%08X\n", sum, sum_f);
	for (i = 0; i < ROUNDKEY_BIT_LEN / 8; ++i)
	{
		if (i != 0)
		{
			carry = carryCount(sum, k_d, 8 * i);
			carry_f = carryCount(sum_f, k_d, 8 * i);
		}
		in1 = ((sum >> (8 * i)) + carry) & 0xFF;
		in_f1 = ((sum_f >> (8 * i)) + carry_f) & 0xFF;
		printf("0x%08X 0x%08X\n", in1, in_f1);
		octet = 0;
		for (k = 0; k < SBLOCK_VAL_COUNT && octet == 0; ++k)
		{
			a = sub_1[(in1 + k) & 0xFF];
			b = sub_1[(in_f1 + k) & 0xFF];
			index = (b - a) & 0xFF;
			printf("index =%08X\n", index);
			printf("0x%08X 0x%08X 0x%08X 0x%08X\n", check[0], check[1], check[2], check[3]);
			for (j = 0; j < 4; ++j)
			{
				cut = (check[j] >> (8 * i)) & 0xFF;
				if (index == cut)
				{
					printf("key = 0x%02X\n", k);
					//octet = k;
					//break;
				}
			}
			getchar();
		}
		printf("key = 0x%02X\n", octet);
		k_d ^= octet << (8 * i);
		sprintf(keyInfo, "key xor = 0x%08X", roundKey_3 ^ toSTBint(k_d));
		DEBUG(keyInfo);
	}
	return k_d;
}

void handDistinguisher()
{
//	uint32_t key[8] = {0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6};
	//uint32_t key[8];
	uint32_t key_d[8];
	generateBytes(key, KEY_BYTE_LEN);
	INFO("key = ");
	printf("0x%08X 0x%08X\n", key[6], key[7]);

	//key_d[6] = distinguishRoundKey_67(key[6], 2, 0, BLOCK_SHIFT_21, 8, 0);
	key_d[7] = distinguishRoundKey_67(key[7], 1, 3, BLOCK_SHIFT_5, 8, 0);
	key_d[5] = distinguishRoundKey_5(key[7], key[5], 1, 3, BLOCK_SHIFT_5, BLOCK_SHIFT_13);
	//distinguishRoundKey_4(key[6], key[7], key[5], BLOCK_SHIFT_21, BLOCK_SHIFT_5, BLOCK_SHIFT_21);
	INFO("Total xor:")
	printf("0x%08X 0x%08X\n", key[6] ^ key_d[6], key[7] ^ key_d[7]);
}

void autoDistinguisher()
{
	clock_t c;
	int pos = 0;
	int number;
	char title_6[22];
	char title_7[22];
	char command_6[38];
	char command_7[38];
	globalPos = 0;
	FILE * f_6, *f_7;
	f_6 = fopen("number.txt", "r");
	fscanf(f_6, "%d", &number);
	fclose(f_6);
	++number;
	f_6 = fopen("number.txt", "w");
	fprintf(f_6, "%d\n", number);
	fclose(f_6);

	f_6 = fopen("result_6.txt", "w");
	f_7 = fopen("result_7.txt", "w");
	generateBytes(key, KEY_BYTE_LEN);

	fprintf(f_6, "====================\n");
	fprintf(f_6, "Distinguish key %d\n", 6);
	fprintf(f_6, "====================\n");
	fprintf(f_6, "pos\t%11d\t%11d\t%11d\t%11d\n", 4, 3, 2, 1);
	fprintf(f_7, "====================\n");
	fprintf(f_7, "Distinguish key %d\n", 7);
	fprintf(f_7, "====================\n");
	fprintf(f_7, "pos\t%11d\t%11d\t%11d\t%11d\n", 4, 3, 2, 1);
	c = clock();
	for (pos = 0; pos < 32; ++pos)
	{
		autoDistinguishRoundKey_67(key[6], 2, 0, BLOCK_SHIFT_21, 8, pos, f_6);
		autoDistinguishRoundKey_67(key[7], 1, 3, BLOCK_SHIFT_5, 8, pos, f_7);
	}
	fclose(f_6);
	fclose(f_7);
	sprintf(title_6, "result_%d_%ld_6.txt", number, (clock() - c) / CLOCKS_PER_SEC);
	sprintf(title_7, "result_%d_%ld_7.txt", number, (clock() - c) / CLOCKS_PER_SEC);
	INFO("your results is in");
	DEBUG(title_6);
	DEBUG(title_7);
	sprintf(command_6, "mv result_6.txt %s", title_6);
	sprintf(command_7, "mv result_7.txt %s", title_7);
	system(command_6);
	system(command_7);
}
