/*
 * Header for different additional includes, functions and constants
 */
#ifndef UTILS_H
#define UTILS_H

//Includes:
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

//Types:

//Constants:

//Functions:
#define ERROR(str) printf("\033[1;31m%s\033[0m\n", str);
#define INFO(str) printf("\033[1;32m%s\033[0m\n", str);
#define WARNING(str) printf("\033[1;33m%s\033[0m\n", str);
#define DEBUG(str) printf("\033[1;34m%s\033[0m\n", str);

void generateBytes(uint32_t *bytes, int byteLen);
void generateBits(uint32_t *bits, int bitLen);

uint32_t toSTBint(const uint32_t a);
uint32_t rotHi(const uint32_t a, const int r);

void roundDump(const uint32_t a, const uint32_t b, const uint32_t c, const uint32_t d);

#define DUMP(a, b, c, d) roundDump(a, b, c, d)
#undef DUMP
#define DUMP(a, b, c, d)

#endif //UTILS_H
