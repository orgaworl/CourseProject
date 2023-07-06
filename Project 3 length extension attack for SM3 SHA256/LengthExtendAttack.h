#pragma once
#include"SM3.h"
void testLengthExtendAttack();
int lengthExtendAttack(uint8 hashVal[32], uint64 mesLen_B, uint8* x, uint64 xLen_B, uint8 newHash[32]);