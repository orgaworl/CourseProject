//SDU 202100460116@mail.sud.edu.cn 

#include"AES.h"
#include<iostream>

using namespace std;
//typedef unsigned char uint8;
//typedef unsigned short int uint16_t;
//typedef unsigned int uint32_t;

//#define PrintPart
uint8 SBox[16][16] = {
	{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
	{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
	{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
	{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
	{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
	{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
	{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
	{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
	{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
	{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
	{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
	{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
	{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
	{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
	{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
	{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};
uint8 RCon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
uint8** MixColumnTable;

void printMatrix(uint8 matrix[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			printf("%02X ", matrix[i][j]);
		}
		cout << endl;
	}
	cout << endl;
}



void testAESFunction()
{
	uint8 plain[17] = "2021004601160000";
	uint8 key[17] = "2021004601160000";
	uint8* temppoi = AES_encrypt(plain, key, 9, 1, 1);
	for (int j = 0; j < 16; j++)
	{
		printf("%02x ", temppoi[j]);
		//cout <<hex<< temppoi[j] << hex << " ";
	}
	cout << endl;
}



uint8* AES_encrypt(uint8 plain[16],uint8 key[16],int roundTimes,bool haveFinalRound, bool PRINTOUT)
//uint8* AES_encrypt(uint8 state[4][4], uint8 roundKey0[4][4], int roundTimes, bool haveFinalRound, bool PRINTOUT)
{


	//0,数组矩阵化
	calMixColumnTable();
	uint8 KeyGenerateOrdinal = 0;
	uint8 roundKey0[4][4];
	uint8 state[4][4];
	
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[j][i]= plain[i * 4 + j];
			roundKey0[j][i] = key[i * 4 + j];
		}
	}
	uint8* RoundKey0[4] = { roundKey0[0],roundKey0[1],roundKey0[2], roundKey0[3]};
	uint8** CurRoundKey=RoundKey0;
	
	

	//1. 初始进行AddRoundKey
	AddRoundKey(state,CurRoundKey);
#if defined PrintPart
		cout << "Round0"<<endl;
		printMatrix(state);
#endif 





	//2. RoundTimes-1 轮
	for (int round = 1; round <= roundTimes; round++)
	{

		CurRoundKey= KeyGenerateOnce(CurRoundKey,KeyGenerateOrdinal);
#if defined PrintPart
			cout << "Round" << round << endl;
			cout << "Key:" << endl;
			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					printf("%02X ", CurRoundKey[i][j]);
				}
				cout << endl;
			}
#endif 

		
		SubBytes(state,SBox);
#if defined PrintPart
			cout << "SubBytes" << endl;
			printMatrix(state);
#endif 


		ShiftRow(state);
#if defined PrintPart
			cout << "ShiftRow" << endl;
			printMatrix(state);
#endif 


		MixColumnT_table(state);
#if defined PrintPart
			cout << "MixColumn" << endl;
			printMatrix(state);
#endif 


		AddRoundKey(state, CurRoundKey);
#if defined PrintPart
			cout << "AddRoundKey" << endl;
			printMatrix(state);
#endif 

	}


	//3. 最后一轮
	uint8* cipher = new uint8[16];
	if (haveFinalRound ==0)
	{
		for (int i = 0; i < 16; i++)
		{
			cipher[i] = state[i % 4][i / 4];
		}
		return  cipher;
	}


	
	CurRoundKey = KeyGenerateOnce(CurRoundKey, KeyGenerateOrdinal);
	SubBytes(state, SBox);
#if defined PrintPart
		cout << "Round" << 10 << endl;
		cout << "SubBytes" << endl;
		printMatrix(state);
#endif 


	ShiftRow(state);
#if defined PrintPart
		cout << "ShiftRow" << endl;
		printMatrix(state);
#endif 


	AddRoundKey(state, CurRoundKey);
#if defined PrintPart
		cout << "AddRoundKey" << endl;
		printMatrix(state);
#endif 



	//4. 将state矩阵中保存的数值转存
	
	for (int i = 0; i < 16; i++)
	{
		cipher[i] = state[i % 4][i / 4];
	}

	return cipher;
}


uint8** KeyGenerateOnce(uint8* key[4], uint8 &KeyGenerateOrdinal)
{
	
	//新的轮密钥放置在堆中
	uint8** roundKey = new uint8 * [4];
	for (int i = 0; i < 4; i++)
	{
		roundKey[i] = new uint8[4];
	}

	//1. 生成第0列
	for (int i = 0; i < 4; i++)
	{
		uint8 temp = key[(i + 1) % 4][3];
		uint8 m = temp >> 4;
		uint8 n = (temp << 4);
		n = n >> 4;
		roundKey[i][0] = SBox[m][n];
		roundKey[i][0] ^= key[i][0];

		if (i == 0)
		{
			roundKey[i][0] ^= RCon[KeyGenerateOrdinal];
			KeyGenerateOrdinal = (KeyGenerateOrdinal + 1) % 10;
		}
	}

	//2. 生成1-3列
	for (int row = 0; row < 4; row++)
	{
		for (int col = 1; col < 4; col++)
		{
			roundKey[row][col] = key[row][col] ^ roundKey[row][col - 1];
		}
	}
	return roundKey;
}


uint8 GF8Mul(uint8 a, uint8 b)
{
	if (a == 1) { return b; }
	uint8 result = b << 1;

	if (b >> 7 == 1)
	{
		result ^= 0b00011011;
	}
	if (a == 3)
	{
		result ^= b;
	}
	return result;
}
uint8* MixColumn(uint8 state[4][4])
{
	uint8 matrix[4][4] =
	{
		{2,3,1,1},
		{1,2,3,1},
		{1,1,2,3},
		{3,1,1,2}
	};
	uint8 tempResult[4];
	//为列
	for (int col = 0; col < 4; col++)
	{
		for (int row = 0; row < 4; row++)
		{
			tempResult[row] = GF8Mul(matrix[row][0], state[0][col]);
			for (int k=1;k<4;k++)
			{
				tempResult[row] ^= GF8Mul(matrix[row][k], state[k][col]);
			}

		}

		for (int row = 0; row < 4; row++)
		{
			state[row][col] = tempResult[row];
		}

	}


	return 0;
}
void calMixColumnTable()
{
	//初始化
	MixColumnTable = new uint8 * [256];
	for (unsigned int i = 0; i < 256; i++)
	{
		MixColumnTable[i] = new uint8[4];
		MixColumnTable[i][0] = GF8Mul(2, uint8(i));
		MixColumnTable[i][1] = GF8Mul(1, uint8(i));
		MixColumnTable[i][2] = GF8Mul(1, uint8(i));
		MixColumnTable[i][3] = GF8Mul(3, uint8(i));
	}



}
uint8* MixColumnT_table(uint8 state[4][4])
{
	

	uint8 tempResult[4] ;
	for (int col = 0; col < 4; col++)
	{
		for (int j = 0; j < 4; j ++ )
		{
			tempResult[j] = 0x00;
		}
		//每次进行一列的加
		for (int j = 0; j < 4; j++)
		{
			tempResult[0] ^= MixColumnTable[state[j][col]][(0+4-j)%4];
			tempResult[1] ^= MixColumnTable[state[j][col]][(1+4-j)%4];
			tempResult[2] ^= MixColumnTable[state[j][col]][(2+4-j)%4];
			tempResult[3] ^= MixColumnTable[state[j][col]][(3+4-j)%4];
		}
		for (int row = 0; row < 4; row++)
		{
			state[row][col] = tempResult[row];
		}

	}


	return 0;
}


uint8* ShiftRow(uint8 state[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < i; j++)
		{
			uint8 temp = state[i][0];
			for (int k = 0; k < 3; k++)
			{
				state[i][k] = state[i][k + 1];
			}
			state[i][3] = temp;
		}
	}
	return 0;
}


uint8* AddRoundKey(uint8 state[4][4], uint8* RoundKey[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] ^= RoundKey[i][j];
		}
	}
	return 0;
}


uint8* SubBytes(uint8 state[4][4], uint8 SBox[16][16])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			uint8 m = state[i][j] >> 4;
			uint8 n = state[i][j] << 4 ;
			n = n >> 4;
			state[i][j] = SBox[m][n];
		}
	}
	return 0;
}




