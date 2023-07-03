//SDU 202100460116@mail.sud.edu.cn 

#include"SM3.h"
#include"iostream"
#include <iomanip>
using namespace std;

void print_uint32Array(uint32* poi, int m)
{	for (int i = 0; i < m; i++)
	{
		cout << hex << setw(8) << setfill('0') << poi[i]<<" ";
		if (i % 8 == 7) { cout << endl; }
		
	}
	cout << endl;
}
void print_uint32Matrix(uint32** poi, int m, int n)
{
	for (int i = 0; i < m; i++)
	{
		for (int j = 0; j < n; j++)
		{
			cout << hex << setw(8) << setfill('0') << poi[i][j] << " ";
			if (j == 7)
			{
				cout << endl;
			}
		}
		cout << endl;
	}
}
uint32 loopLeftShift(uint32 x,int dis)
{

	dis %= 32;
	if (dis == 0)
	{
		return x;
	}
	return ((x << dis) + (x >> (32 - dis)));
}
void testSM3HashFunction()
{

	uint8* cipher;



	//test1:
	//uint8 input[] = "abc";
	//cipher = SM3Hash(input, sizeof(input) - 1);

	//test2:
	uint8 input[] = "202100460116";
	cipher = SM3Hash(input, sizeof(input)-1);


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


}



uint8* SM3Hash(uint8*plainText,long plainLength)
{
	int blockSize = (plainLength * 8) / 512 + 1;
	if (plainLength * 8 % 512 > 512 - 65) {blockSize++;}
	uint32* wordList;
	uint32 IV[] = { 0x7380166f,0x4914b2b9 ,0x172442d7 ,0xda8a0600 ,0xa96f30bc ,0x163138aa ,0xe38dee4d ,0xb0fb0e4e };
	uint32* linkVariable=IV;

	//1.�����ϢΪ������512bit
	uint32** messageBlock = padding(plainText,plainLength,blockSize);
	//print_uint32Matrix(messageBlock,blockSize,16);



	//��ÿ��512bit�������
	for (int i=0;i<blockSize;i++)
	{
		//2, ��չ
		wordList = messageExtend(messageBlock[i]);
		//cout << "��չ��:" << endl;
		//print_uint32Array(wordList, 132);

	
		//3, ѹ��
		linkVariable = compress(wordList,linkVariable);
		//cout << "ѹ����:" << endl;
		print_uint32Array(linkVariable,8);

	}


	//4. 256bitHashֵ,8*32bit ->32*8bit
	uint8* hashValue = new uint8[32];
	for (int i=0;i<32;i++)
	{
		hashValue[i] = linkVariable[i / 4]>>((3-i%4)*8);
	}
	return hashValue;
}




uint32 FF(uint32 X, uint32 Z, uint32 Y, int j)
{
	if (j < 16)
	{
		return X ^ Y ^ Z;
	}
	else
	{
		return (X & Y) | (X & Z) | (Y & Z);
	}
}

uint32 GG(uint32 X, uint32 Y, uint32  Z, int j)
{
	if (j < 16)
	{
		return X ^ Y ^ Z;
	}
	else
	{
		return (X & Y) | ((~X) & Z);
	}
}

uint32 P0(uint32 X)
{
	return X ^ ((X << 9) + (X >> 23)) ^ ((X << 17) + (X >> 15));
}

uint32 P1(uint32 X)
{
	return X ^ ((X << 15) + (X >> 17)) ^ ((X << 23) + (X >> 9));
}

uint32 T(int j)
{
	if (j<16)
	{
		return 0x79cc4519;
	}
	else
	{
		return 0x7a879d8a;
	}
}

uint32** padding(uint8*plainText, long plainLength,int blockSize)
{
	//һά����ת ��ά����
	//lenght*8bit->blockSize * 16 *32bit
	////m*64*8bit -> blockSize * 16 *32bit


	uint32** mesBlock = new uint32 * [blockSize];
	int pos = 0;

	//1. padding ǰ blockSize-1 ����
	for (int i = 0; i < blockSize-1; i++)
	{
		mesBlock[i] = new uint32[16]{0};
		for (int j = 0; j < 16; j++)
		{
			//16eles  <-  64eles
			//pos = (16 * i + j) * 4;
			pos =64*i+j* 4;
			mesBlock[i][j] = (plainText[pos] << 24) + (plainText[pos+1] << 16) + (plainText[pos+2] << 8) + (plainText[pos+3]);
		}
	}
	mesBlock[blockSize - 1] = new uint32[16]{0};





	//2. padding ���һ����

	int block8Num = plainLength % 64; //ʣ��8bit������
	int block32Num = block8Num / 4;//ʣ��32bit������



	//2.1 �����512bit�����ʣ�µ�32bit��
	for (int j=0;j<block32Num;j++)
	{
		pos = (16 * (blockSize-1) + j) * 4;
		mesBlock[blockSize - 1][j]= (plainText[pos] << 24) + (plainText[pos + 1] << 16) + (plainText[pos + 2] << 8) + (plainText[pos + 3]);
	}
	pos = (16 * (blockSize - 1) + block32Num) * 4;
	

	//2.2 ʣ�µļ���8bit�����ͬһ��32bit����
	block8Num = block8Num - 4 * block32Num;
	for (int k=0;k<block8Num;k++)
	{
		uint32 temp= (plainText[pos + k] << (8 * (3 - k)));
		mesBlock[blockSize - 1][block32Num] +=temp;
		//mesBlock[blockSize - 1][block32Num] += (  plainText[pos+k] <<  ( 8 * (3 - k))  );
	}
	

	//2.3 д1bit 0b1
	if (block8Num == 4)
	{
		//1д����һ��32bit����
		mesBlock[blockSize - 1][block32Num+1] = 0x80000000;
	}
	else
	{
		//1д����32bit����
		mesBlock[blockSize - 1][block32Num] += 0b10000000<<((3-block8Num)*8);
	}

	//2.4 д64bit����
	uint32 temp32bit = ((8 * plainLength) >> 31);
	temp32bit =temp32bit >> 1;                     //����ֱ������32bit(Ϊδ�������)
	mesBlock[blockSize - 1][14] = temp32bit;
	mesBlock[blockSize - 1][15] = (8 *plainLength);
	return mesBlock;

}


uint32* messageExtend(uint32 *mes)
{
	//64Byte (512bit)��Ϣ������չ
	uint32* wordList = new uint32[132];
	uint32 temp32bit = 0;

	//1. ����w_i(0<=i<=15)
	for (int i = 0; i < 16; i++)
	{
		wordList[i] = mes[i];
	}	
	//2. ����w_i(16<=i<=67)
	for (int i = 16; i < 68; i++)
	{
		temp32bit = wordList[i - 16] ^ wordList[i - 9] ^ loopLeftShift(wordList[i-3],15);
		wordList[i] = P1(temp32bit) ^ loopLeftShift(wordList[i-13],7) ^ wordList[i-6];

	}
	//3. ����w_i^'(0<=i<=63)
	for (int i = 68; i < 132; i++)
	{
		wordList[i] = wordList[i - 68] ^ wordList[i - 64];
	}


	//������ȫ����һ��int������(132��Ԫ��)
	return wordList;
}


uint32* compress(uint32 *wordList,uint32 linkVariable[8])
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
		uint32 test = loopLeftShift(A, 12);
		test = E;
		test = loopLeftShift(T(i), i);
		SS1 = (loopLeftShift(A, 12) + E + loopLeftShift(T(i), i));
		SS1 = loopLeftShift(SS1, 7);
		SS2 = SS1 ^ loopLeftShift(A, 12);

		B = poiSrc[1];
		C = poiSrc[2];
		TT1 = FF(A, B, C, i) + poiSrc[3] + SS2 + wordList[i + 68];

		F = poiSrc[5];
		G = poiSrc[6];
		TT2 = GG(E, F, G, i) + poiSrc[7] + SS1 + wordList[i];;

		poiDes[0] = TT1;//error
		poiDes[1] = A;
		poiDes[2] = loopLeftShift(B, 9);
		poiDes[3] = C;

		poiDes[4] = P0(TT2);//error
		poiDes[5] = E;
		poiDes[6] = loopLeftShift(F,19);
		poiDes[7] = G;
		//cout <<dec<< i <<": " << endl;
		//print_uint32Array(poiDes, 8);
	}

	//��64���Ӻ����������������������Ϊ���
	for (int i=0;i<8;i++)
	{
		result[i] = linkVariable[i] ^ poiDes[i];
	}
	delete [8]poiSrc;
	delete [8]poiDes;
	return result;

}
