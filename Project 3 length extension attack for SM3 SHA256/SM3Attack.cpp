#pragma once
#include"LengthExtendAttack.h"
#include"stdio.h"
#include"string"

void testLengthExtendAttack()
{
	//1. 原消息M 进行Hash
	uint8 plain[300] = "Hello";
	uint8 HashVal[32];
	uint64 mesLen_B = strlen((const char*)plain);
	uint64 mesLen_b = 8*mesLen_B;
	SM3Hash(plain,mesLen_B , HashVal);


	printf("\n原消息值: ");
	for (int i = 0; i <mesLen_B; i++) { printf("%02x",plain[i]); }
	printf("\n散列值  : ");
	for (int j = 0; j < 32; j++){printf("%02x", HashVal[j]);}


	//2. 利用原消息Hash值进行长度拓展攻击
	uint8 x[] = ", Alice!";
	uint64 xLen_B = strlen((const char*)x);
	lengthExtendAttack(HashVal,mesLen_B,x,xLen_B,HashVal);
	printf("\n追加消息: ");
	for (int i=0;i<xLen_B;i++)
	{
		printf("%02x", x[i]);
	}
	printf("\n新散列值: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", HashVal[i]);
	}

	//3.1 构造z 验证攻击结果
	uint64 d = (447 - mesLen_b) % 512;//M默认以字节为单位
	int zLen_B = (65 + d)/8+xLen_B;//字节
	uint8* z = new uint8[zLen_B]{0};
	z[0] = 0b10000000;
	for (int i =0 ; i < 8; i++) {
		z[zLen_B - xLen_B - 8+i] = mesLen_b>>(8*(7-i));
	}
	for (int i=0;i<xLen_B;i++)
	{
		z[zLen_B-xLen_B+i] = x[i];
	}
	for (int i=0;i<zLen_B;i++)
	{
		plain[mesLen_B + i] = z[i];
	}plain[mesLen_B + zLen_B] = 0x00;


	//3.2 验证
	printf("\n合消息值: ");
	for (int i = 0; i < mesLen_B + zLen_B; i++) { printf("%02x", plain[i]); }

	SM3Hash(plain,(mesLen_B+zLen_B),HashVal);

	printf("\n散列值  : ");
	for (int j = 0; j < 32; j++) { printf("%02x", HashVal[j]); }
	printf("\n\n\n");
}


// mesLen_B&xLen_B 以字节为单位
int lengthExtendAttack(uint8 hashVal[32], uint64 mesLen_B, uint8* x, uint64 xLen_B,uint8 newHash[32])
{

	// 计算 x||pad 
	int blockSize = xLen_B / 64+1;
	int pos;
	//1. padding 前 blockSize-1 个块
	uint32** mesBlock = new uint32 * [blockSize] {0};
	for (int i = 0; i < blockSize - 1; i++){
		mesBlock[i] = new uint32[16];
		pos = 64 * i;
		for (int j = 0; j < 16; j++){
			mesBlock[i][j] = (x[pos] << 24) + (x[pos + 1] << 16) + (x[pos + 2] << 8) + (x[pos + 3]);
			pos += 4;
		}
	}
	//2. padding 最后一个块
	mesBlock[blockSize - 1] = new uint32[16]{0};
	int block8Num = xLen_B % 64; //剩余8bit块数量
	int block32Num = block8Num / 4;//剩余32bit块数量
	//2.1 向最后512bit中填充剩下的32bit块
	pos = (64 * (blockSize - 1));
	for (int j = 0; j < block32Num; j++){
		mesBlock[blockSize - 1][j] = (x[pos] << 24)+ (x[pos + 1] << 16)+ (x[pos + 2] << 8)+ (x[pos + 3]);
		pos += 4;
	}
	//2.2 剩下的几个8bit块放入同一个32bit块中
	block8Num = block8Num - 4 * block32Num;
	for (int k = 0; k < block8Num; k++){
		mesBlock[blockSize - 1][block32Num] += (x[pos + k] << (8 * (3 - k)));
	}
	//2.3 写1bit 0b1
	if (block8Num == 4){
		mesBlock[blockSize - 1][block32Num + 1] = 0x80000000;
	}
	else{
		mesBlock[blockSize - 1][block32Num] += 0b10000000 << ((3 - block8Num) * 8);
	}
	//2.4 写64bit长度值(注意大端小端)
	uint64 totalLen = 512*(mesLen_B/64+1) + xLen_B*8;
	uint32 temp32bit = ((long)totalLen) >> 31;
	temp32bit >>= 1;
	mesBlock[blockSize - 1][14] = temp32bit;
	mesBlock[blockSize - 1][15] = totalLen;



	//压缩函数
	uint32* linkVariable = new uint32[8];
	for (int i = 0; i < 8; i++)
	{   //大小端转换
		int i4 = i * 4;
		linkVariable[i] = (hashVal[i4] << 24) + (hashVal[i4+1] << 16) +( hashVal[i4+2] << 8) + hashVal[i4+3];
	}
	uint32* temp;
	for (int i=0;i<blockSize;i++)
	{
		temp = linkVariable;
		linkVariable = compress(mesBlock[i],linkVariable);
		delete temp;
	}
	

	//大小端转换
	//uint8* newHash = new uint8[32];
	for (int i = 0; i < 8; i++)
	{   
		int i4 = i * 4;
		newHash[i4] = linkVariable[i] >> 24;
		newHash[i4 + 1] = linkVariable[i] >> 16;
		newHash[i4 + 2] = linkVariable[i] >> 8;
		newHash[i4 + 3] = linkVariable[i];
	}
	delete []linkVariable;
	return 1;
}