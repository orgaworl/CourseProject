
typedef unsigned char uint8;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;

using namespace std;

extern uint8 SBox[16][16];

uint8* ShiftRow(uint8 state[4][4]);
uint8* MixColumn(uint8 state[4][4]);
uint8* AddRoundKey(uint8 state[4][4], uint8* RoundKey[4]);
uint8* SubBytes(uint8 state[4][4], uint8 SBox[16][16]);
uint8** KeyGenerateOnce(uint8* key[4], uint8& KeyGenerateOrdinal);
void printMatrix(uint8 matrix[4][4]);
uint8* AES_encrypt(uint8 plain[17], uint8 key[17], int roundTimes=9, bool haveFinalRound=1,bool PRINTOUT=0);
void calMixColumnTable();
uint8* MixColumnT_table(uint8 state[4][4]);
void testAESFunction();