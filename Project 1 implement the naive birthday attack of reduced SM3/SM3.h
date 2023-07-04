//SDU 202100460116@mail.sud.edu.cn 
//#include <iomanip>
#pragma once
typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;
using namespace std;

void testSM3HashFunction();
uint32 loopLeftShift(uint32 x, int dis);
uint32** padding(uint8* plainText, long plainLength, int blockSize);
uint32*  messageExtend(uint32 mes[16]);
uint32*  compress(uint32* wordList, uint32 *linkVariable);
int SM3Hash(uint8* plainText, long plainLength,uint8 hashValue[32]);
