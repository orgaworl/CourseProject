#pragma once
#include"SM3.h"
#include"stdio.h"
#include <time.h>
#include<random>
int birthdayAttack(uint64 hashValue,int hashValueLength);
void test_BirthAttackOfSM3();