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

	//1.填充消息为整数倍512bit
	uint32** messageBlock = padding(plainText,plainLength,blockSize);
	//print_uint32Matrix(messageBlock,blockSize,16);



	//对每个512bit分组进行
	for (int i=0;i<blockSize;i++)
	{
		//2, 拓展
		wordList = messageExtend(messageBlock[i]);
		//cout << "拓展后:" << endl;
		//print_uint32Array(wordList, 132);

	
		//3, 压缩
		linkVariable = compress(wordList,linkVariable);
		//cout << "压缩后:" << endl;
		print_uint32Array(linkVariable,8);

	}


	//4. 256bitHash值,8*32bit ->32*8bit
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
	//一维数组转 二维矩阵
	//lenght*8bit->blockSize * 16 *32bit
	////m*64*8bit -> blockSize * 16 *32bit


	uint32** mesBlock = new uint32 * [blockSize];
	int pos = 0;

	//1. padding 前 blockSize-1 个块
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





	//2. padding 最后一个块

	int block8Num = plainLength % 64; //剩余8bit块数量
	int block32Num = block8Num / 4;//剩余32bit块数量



	//2.1 向最后512bit中填充剩下的32bit块
	for (int j=0;j<block32Num;j++)
	{
		pos = (16 * (blockSize-1) + j) * 4;
		mesBlock[blockSize - 1][j]= (plainText[pos] << 24) + (plainText[pos + 1] << 16) + (plainText[pos + 2] << 8) + (plainText[pos + 3]);
	}
	pos = (16 * (blockSize - 1) + block32Num) * 4;
	

	//2.2 剩下的几个8bit块放入同一个32bit块中
	block8Num = block8Num - 4 * block32Num;
	for (int k=0;k<block8Num;k++)
	{
		uint32 temp= (plainText[pos + k] << (8 * (3 - k)));
		mesBlock[blockSize - 1][block32Num] +=temp;
		//mesBlock[blockSize - 1][block32Num] += (  plainText[pos+k] <<  ( 8 * (3 - k))  );
	}
	

	//2.3 写1bit 0b1
	if (block8Num == 4)
	{
		//1写到下一个32bit块中
		mesBlock[blockSize - 1][block32Num+1] = 0x80000000;
	}
	else
	{
		//1写到该32bit块中
		mesBlock[blockSize - 1][block32Num] += 0b10000000<<((3-block8Num)*8);
	}

	//2.4 写64bit长度
	uint32 temp32bit = ((8 * plainLength) >> 31);
	temp32bit =temp32bit >> 1;                     //不能直接右移32bit(为未定义操作)
	mesBlock[blockSize - 1][14] = temp32bit;
	mesBlock[blockSize - 1][15] = (8 *plainLength);
	return mesBlock;

}


uint32* messageExtend(uint32 *mes)
{
	//64Byte (512bit)消息进行拓展
	uint32* wordList = new uint32[132];
	uint32 temp32bit = 0;

	//1. 计算w_i(0<=i<=15)
	for (int i = 0; i < 16; i++)
	{
		wordList[i] = mes[i];
	}	
	//2. 计算w_i(16<=i<=67)
	for (int i = 16; i < 68; i++)
	{
		temp32bit = wordList[i - 16] ^ wordList[i - 9] ^ loopLeftShift(wordList[i-3],15);
		wordList[i] = P1(temp32bit) ^ loopLeftShift(wordList[i-13],7) ^ wordList[i-6];

	}
	//3. 计算w_i^'(0<=i<=63)
	for (int i = 68; i < 132; i++)
	{
		wordList[i] = wordList[i - 68] ^ wordList[i - 64];
	}


	//三部分全放入一个int数组中(132个元素)
	return wordList;
}


uint32* compress(uint32 *wordList,uint32 linkVariable[8])
{
	//将68+64个消息字和
	//上个压缩函数的输出值8*32bit
	//作为输入,输出压缩值256bit=8*32bit

	//共进行64次,每次传入一对word和linkVarliable



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


	//第33轮出错
	for (int i=0;i<64;i++)
	{
		//将指向本轮输出的指针指向上轮输出
		poiTemp = poiDes;
		poiDes = poiSrc;
		poiSrc = poiTemp;


		//计算本轮输出并保存到poiDes指向的堆数组
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

	//将64轮子函数的输出与最初输入异或作为结果
	for (int i=0;i<8;i++)
	{
		result[i] = linkVariable[i] ^ poiDes[i];
	}
	delete [8]poiSrc;
	delete [8]poiDes;
	return result;

}
