//SDU 202100460116@mail.sud.edu.cn 

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
using namespace std;



extern uint8  SM4SBox[256];
void printMatrix(uint8 matrix[4][4]);
void testSM4Function();


uint32* SM4KeyGenerate(uint32 key[4]);
uint8* SM4Encrypt(uint8 plaintext[16], uint8 K[16]);

//uint8** SM4RoundFunction(uint8**X,uint8*RoundKey);



