
#include"stdint.h"
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>

#include"time.h"
#include"SM4.h"

void SM4_AESNI(uint8_t* input, uint8_t* output, uint32_t sm4_key[32], int enc);
void SM4_AESNI8_ECB(uint8* plain, int length, uint8 Key[32], uint8* cipher);
void test_SM4_AESNI();
void benchmark_SM4_AESNI(int tstLen=63);