#pragma once
#include"SM3.h"
#include"time.h"
#include"stdio.h"
#include"string"
void test_LengthExtendAttack();
void benchmark_LEA(int tstLen=16);
int lengthExtendAttack(uint8 hashVal[32], uint64 mesLen_B, uint8* x, uint64 xLen_B, uint8 newHash[32]);