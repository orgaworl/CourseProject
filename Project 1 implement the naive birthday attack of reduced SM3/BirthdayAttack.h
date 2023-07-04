#pragma once
#include"SM3.h"

uint64 reducedSM3(uint8* plainText, long plainLength, int hashValueLength);
int birthdayAttack(uint64 hashValue,int hashValueLength);
void testBirthAttackOfSM3();