//SDU 202100460116@mail.sud.edu.cn 
//#include <iomanip>
typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
using namespace std;

void testSM3HashFunction();
void print_uint32Array(uint32* poi, int m);
void print_uint32Matrix(uint32** poi, int m, int n);
uint32 FF(uint32 X, uint32 Z, uint32 Y, int j);
uint32 GG(uint32 X, uint32 Y, uint32  Z, int j);
uint32 P0(uint32 X);
uint32 P1(uint32 X);
uint32 T(int j);


uint32 loopLeftShift(uint32 x, int dis);
uint32** padding(uint8* plainText, long plainLength, int blockSize);
uint32* messageExtend(uint32 mes[16]);
uint32* compress(uint32* wordList, uint32 linkVariable[8]);

uint8* SM3Hash(uint8* plainText, long plainLength);
