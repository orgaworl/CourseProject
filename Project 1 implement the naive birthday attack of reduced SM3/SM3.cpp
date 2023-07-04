//SDU 202100460116@mail.sud.edu.cn 
#include"SM3.h"
#include"iostream"
#include <iomanip>
#include<ctime>
using namespace std;

clock_t sT;
clock_t eT;
double T;
//#define maxLength 67108864
//uint8 input[maxLength];
//uint8 buf[maxLength];
void testSM3HashFunction()
{
	//test2:
	uint8 input[] = "202100460116";
	uint8 buf[32];

		sT = clock();
		for (int i = 0; i < 1000000; i++)
		{
			SM3Hash(input, strlen((const char*)input), buf);
		}
		eT = clock();
	
	printf("����: \"%s\"\n����: ",input);
	for (int j = 0; j < strlen((const char*)input); j++)
	{
		printf("%02x", input[j]);
	}
	printf("\nɢ��: ");
	for (int j=0;j<32;j++)
	{
		printf("%02x",buf[j]);
	}
	printf("\nTime Cost: %f s \n\n", ((double)eT - sT) / CLOCKS_PER_SEC);



	//test3: 
	//uint8 input[64];
	//for (int i=0;i<16;i++)
	//{
	//	input[4 * i] = 0x61;
	//	input[4 * i+1] = 0x62;
	//	input[4 * i+2] = 0x63;
	//	input[4 * i+3] = 0x64;
	//}
	//cipher=SM3Hash(input, 64);
	
	
	//test4:
	//int loopTimes = 100;
	//for (int i = 0; i < maxLength; i++)
	//{
	//	input[i] = rand();
	//}
	//SM3Hash(input, 1048576, buf);
	//SM3Hash(input, 1048576, buf);
	//for (int l = 1048576; l <= maxLength; l += 1048576)
	//{
	//	sT = clock();
	//	for (int i = 0; i < loopTimes; i++)
	//	{
	//		SM3Hash(input, l, buf);
	//	}
	//	eT = clock() ;
	//	T = ((double)eT - sT) / CLOCKS_PER_SEC;
	//	cout << T << " " << (double)l*loopTimes / T / 1048576 << endl;//MByte/s
	//}
	

	//test5 :
	//uint8 input[] = "202100460116";
	//uint64 hashValue;
	//hashValue=reducedSM3(input, strlen((const char*)input));


}



uint32 IV[8] = { 0x7380166f,0x4914b2b9 ,0x172442d7 ,0xda8a0600 ,0xa96f30bc ,0x163138aa ,0xe38dee4d ,0xb0fb0e4e };
int SM3Hash(uint8*plainText,long plainLength, uint8  hashValue[32])//[32]
{
	int blockSize = plainLength /64 + 1;
	if (plainLength * 8 % 512 >= 448) {blockSize++;}

	uint32* wordList;
	uint32* linkVariable=IV;
	uint32** messageBlock = padding(plainText,plainLength,blockSize);
	uint32* temp;
	for (int i=0;i<blockSize;i++)
	{
		temp = linkVariable;
		wordList = messageExtend(messageBlock[i]);
		linkVariable = compress(wordList,linkVariable);
		if (i != 0) { delete temp; }
	}
	for (int i = 0; i < 8; i++)
	{
		int i4 = i * 4;
		hashValue[i4    ] = linkVariable[i] >> 24;
		hashValue[i4 + 1] = linkVariable[i] >> 16;
		hashValue[i4 + 2] = linkVariable[i] >> 8;
		hashValue[i4 + 3] = linkVariable[i] ;
	}
	delete linkVariable;
	for (int i=0;i<blockSize;i++)
	{
		delete messageBlock[i];
	}
	delete messageBlock;
	return 1;
}

uint32 loopLeftShift(uint32 x, int dis)
{
	dis %= 32;
	if (dis == 0)
	{
		return x;
	}
	return ((x << dis) + (x >> (32 - dis)));
}

uint32** padding(uint8*plainText, long plainLength,int blockSize)
{
	//һά����ת ��ά����
	//lenght*8bit->blockSize * 16 *32bit
	////m*64*8bit -> blockSize * 16 *32bit

	int pos;
	uint32 temp1;
	uint32 temp2;
	uint32 temp3;
	uint32 temp4;


	//1. padding ǰ blockSize-1 ����
	uint32** mesBlock = new uint32 * [blockSize];
	for (int i = 0; i < blockSize-1; i++)
	{
		mesBlock[i] = new uint32[16]{0};
		pos = 64 * i;
		for (int j = 0; j < 16; j++)
		{
			temp1 = (plainText[pos] << 24);
			temp2 = (plainText[pos + 1] << 16);
			temp1 += temp2;
			temp3 = (plainText[pos + 2] << 8);
			temp4 = (plainText[pos + 3]);
			temp3 += temp4;
			mesBlock[i][j] = temp1 + temp3;
			pos += 4;
		}
	}
	

	//2. padding ���һ����
	mesBlock[blockSize - 1] = new uint32[16]{ 0 };
	int block8Num = plainLength % 64; //ʣ��8bit������
	int block32Num = block8Num / 4;//ʣ��32bit������

	//2.1 �����512bit�����ʣ�µ�32bit��
	pos = (64 * (blockSize - 1));
	for (int j=0;j<block32Num;j++)
	{
		temp1 = (plainText[pos] << 24);
		temp2 = (plainText[pos + 1] << 16);
		temp1 += temp2;
		temp3 = (plainText[pos + 2] << 8);
		temp4 = (plainText[pos + 3]);
		temp3 += temp4;
		mesBlock[blockSize - 1][j] = temp1 + temp3;
		pos += 4;
	}
	
	//2.2 ʣ�µļ���8bit�����ͬһ��32bit����
	block8Num = block8Num - 4 * block32Num;
	for (int k=0;k<block8Num;k++)
	{
		mesBlock[blockSize - 1][block32Num] += (plainText[pos + k] << (8 * (3 - k)));
	}
	
	//2.3 д1bit 0b1
	if (block8Num == 4)
	{
		//д����һ��32bit����
		mesBlock[blockSize - 1][block32Num+1] = 0x80000000;
	}
	else
	{
		//д����32bit����
		mesBlock[blockSize - 1][block32Num] += 0b10000000<<((3-block8Num)*8);
	}


	//2.4 д64bit����ֵ(ע����С��)
	uint32 temp32bit = ((long)(8 * plainLength) >> 31);
	temp32bit >>= 1;
	mesBlock[blockSize - 1][14] = temp32bit;
	mesBlock[blockSize - 1][15] = (8 *plainLength);
	return mesBlock;

}

uint32* messageExtend(uint32 mes[16])
{
	//64Byte (512bit)��Ϣ������չ
	uint32* wordList = new uint32[132];
	uint32 temp32bit1 = 0;
	uint32 temp32bit2 = 0;
	uint32 temp32bit3 = 0;

	//1. ����w_i(0<=i<=15)
	for (int i = 0; i < 16; i++)
	{
		wordList[i] = mes[i];
	}	
	//2. ����w_i(16<=i<=67)
	for (int i = 16; i < 68; i++)
	{
		temp32bit1 = wordList[i - 16] ^ wordList[i - 9];
		temp32bit2= ((wordList[i - 3] << 15) + (wordList[i - 3] >> 17));
		temp32bit1 ^= temp32bit2;
		temp32bit3 = temp32bit1 ^ ((temp32bit1 << 15) + (temp32bit1 >> 17)) ^ ((temp32bit1 << 23) + (temp32bit1 >> 9));//	P1
		temp32bit2 = ((wordList[i - 13] << 7) + (wordList[i - 13] >> 25))^ wordList[i - 6];
		wordList[i] = temp32bit2^temp32bit3;
	}
	//3. ����w_i^'(0<=i<=63)
	for (int i = 68; i < 132; i++)
	{
		wordList[i] = wordList[i - 68] ^ wordList[i - 64];
	}
	return wordList;
}

uint32* compress(uint32 *wordList,uint32 *linkVariable)
{
	//��68+64����Ϣ�ֺ�
	//�ϸ�ѹ�����������ֵ8*32bit
	//��Ϊ����,���ѹ��ֵ256bit=8*32bit

	//������64��,ÿ�δ���һ��word��linkVarliable


	uint32* poiSrc = new uint32[8];
	uint32* poiDes = new uint32[8];
	uint32* poiTemp;
	uint32* result=new uint32[8];


	uint32 SS1=0;
	uint32 SS2=0;
	uint32 TT1=0;
	uint32 TT2=0;
	uint32 A=0, B=0, C=0;
	uint32 E=0, F=0, G=0;


	for (int i = 0; i < 8; i++)
	{
		poiDes[i] = linkVariable[i];
	}


	//��33�ֳ���
	for (int i=0;i<64;i++)
	{
		//��ָ���������ָ��ָ���������
		poiTemp = poiDes;
		poiDes = poiSrc;
		poiSrc = poiTemp;


		//���㱾����������浽poiDesָ��Ķ�����
		A = poiSrc[0];
		E = poiSrc[4];




		uint32 temp1 = ((A << 12) + (A >> 20));
		uint32 temp2 ;
		if (i<16)
		{
			temp2 = loopLeftShift(0x79cc4519, i);
		}
		else
		{
			temp2= loopLeftShift(0x7a879d8a, i);
		}

		SS1 = temp1+ E + temp2;
		SS1 = ((SS1 << 7) + (SS1 >> 25));
		SS2 = SS1 ^ temp1;

		B = poiSrc[1];
		C = poiSrc[2];
		if (i<16){
			temp1 = A ^ B ^ C;
		}
		else { 
			temp1 = (A & B) | (B & C) | (A & C); 
		}
		TT1 = temp1 + poiSrc[3] + SS2 + wordList[i + 68];

		F = poiSrc[5];
		G = poiSrc[6];
		if (i < 16) {
			temp2 = E ^ F ^ G;
		}
		else {
			temp2 = (E & F) | ((~E) & G);
		}
		TT2 =temp2 + poiSrc[7] + SS1 + wordList[i];;


		poiDes[0] = TT1;
		poiDes[1] = A;
		poiDes[2] = ((B << 9) + (B >> 23));
		poiDes[3] = C;

		poiDes[4] = TT2 ^ ((TT2 << 9) + (TT2 >> 23)) ^ ((TT2 << 17) + (TT2 >> 15));//P0
		poiDes[5] = E;
		poiDes[6] = ((F << 19) + (F >> 13));
		poiDes[7] = G;
	}

	//��64���Ӻ����������������������Ϊ���
	for (int i=0;i<8;i++)
	{
		result[i] = linkVariable[i] ^ poiDes[i];
	}

	delete [8]poiSrc;
	delete [8]poiDes;
	delete wordList;
	return result;

}


