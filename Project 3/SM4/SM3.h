//SDU 202100460116@mail.sud.edu.cn 
//#include <iomanip>
#pragma once
#include"iostream"
#include <iomanip>
#include<ctime>
typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;
using namespace std;

void test_SM3();
void benchmark_SM3(int tstLen = 63);
uint32 loopLeftShift(uint32 x, int dis);
uint32** padding(uint8* plainText, long long plainLength, long long blockSize);
uint32*  messageExtend(uint32 mes[16]);
uint32*  compress(uint32 mes[16], uint32 linkVariable[8]);
int SM3Hash(uint8* plainText, long long plainLength,uint8 hashValue[32]);
uint64 reducedSM3(uint8* mes, long mesLen, int hashValLen);
