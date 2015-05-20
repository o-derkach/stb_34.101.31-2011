#include "utils.h"
#include "stb_cipher.h"
#include "config.h"
#include <math.h>

extern const uint32_t sub_1[SBLOCK_VAL_COUNT];

uint32_t texts[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_crypt[MAX_TEXT_NUM * BLOCK_WORD_LEN];
uint32_t pair_fault[MAX_TEXT_NUM * BLOCK_WORD_LEN];

void generateTexts(uint32_t *key)
{
	int n;
	for (n = 0; n < MAX_TEXT_NUM; ++n)
	{
		generateBytes(texts + 4 * n, BLOCK_BYTE_LEN);
		cryptWithFault(texts + 4 * n, key, pair_crypt + 4 * n, 0, 0);
		cryptWithFault(texts + 4 * n, key, pair_fault + 4 * n, 8, 0);
	}
}

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

	char title[16];
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
	return ((a + k) >> shift) & 1;
}

void handDistinguisher()
{
	int exitCode = 2;
	uint32_t a, b, c, d, a_f, b_f, c_f, d_f, carry, carry_f, i, n;
	uint32_t a1, b1, c1, d1, a_f1, b_f1, c_f1, d_f1, k, k1, index, octet;
	uint32_t k_56, k_55;
	uint32_t lastMaxTexts = 0;
	double g[SBLOCK_VAL_COUNT][SBLOCK_VAL_COUNT];
	double dk[SBLOCK_VAL_COUNT];

	uint32_t out[4] = {0, 0, 0, 0};
	uint32_t out_f[4] = {0, 0, 0, 0};
	uint32_t key[8] = {0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6};

	k_55 = k_56 = 0;
	carry = carry_f = 0;

	for (i = 0; i < ROUNDKEY_BIT_LEN / 8 && exitCode != 0; ++i)
	{
		for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
		{
			for (n = 0; n < SBLOCK_VAL_COUNT; ++n)
			{
				g[k][n] = 0;
			}
		}
		for (n = 0; n < MAX_TEXT_NUM && exitCode != 3 && exitCode != 0; ++n)
		{
			if (exitCode == 2)
				generateBytes(texts + 4 * n, BLOCK_BYTE_LEN);
			cryptWithFault(texts + 4 * n, key, out, 0, 0);
			antiFinalPerm(out);
			a = out[2];
			b = out[0];
			cryptWithFault(texts + 4 * n, key, out_f, 8, 0);
			antiFinalPerm(out_f);
			a_f = out_f[2];
			b_f = out_f[0];
			a1 = toSTBint(a);
			b1 = toSTBint(b);
			a_f1 = toSTBint(a_f);
			b_f1 = toSTBint(b_f);

			if (i != 0)
			{
				carry = carryCount(a1, k_55, 8 * i);
				carry_f = carryCount(a_f1, k_55, 8 * i);
			}
			a1 = ((a1 >> (8 * i)) + carry) & 0xFF;
			a_f1 = ((a_f1 >> (8 * i)) + carry_f) & 0xFF;
			for (k = 0; k < SBLOCK_VAL_COUNT; ++k)
			{
				index = (rotLo(b1 ^ b_f1, 21) >> (8 * i)) & 0xFF;
				index ^= sub_1[(a1 + k) & 0xFF] ^ sub_1[(a_f1 + k) & 0xFF];
				g[k][index]++;
			}
			//INFO("=================================================================");
			octet = countDk(g, dk, n + 1);
			if (n != 0 && n % 100 == 0)
			{
				printf("0x%02X\n", octet);
				plotData(dk, SBLOCK_VAL_COUNT, n + 1);
			}
			if (n != 0 && n % 1000 == 0)
			{
				printf("max texts = %d\n", lastMaxTexts);
				INFO("=================================================================");
				printf("0 - exit;\n");
				printf("1 - next texts;\n");
				printf("2 - generate more;\n");
				printf("3 - next octet;\n>");
				scanf("%d", &exitCode);
			}
		}
		if (exitCode == 3)
		{
			exitCode = 1;
			if (lastMaxTexts < n)
				lastMaxTexts = n;
		}
		system("./kill_gnu.sh");
		k_55 ^= octet << (8 * i);
		printf("origin = 0x%08X\n", key[6]);
		printf("distin = 0x%08X\n", k_55);
	}
}
