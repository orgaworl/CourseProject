#include"stdio.h"
#include"BirthdayAttack.h"
#include"SM3.h"
#include <time.h>
#include<random>

//调用生日攻击,测试
void testBirthAttackOfSM3()
{
	uint8 plainTxet[] = "202100460116";
	int hashValueLength = 16;//设置Hash值长度
	uint64 HashValue = reducedSM3(plainTxet, strlen((const char*)plainTxet),hashValueLength);
	printf("Reduced SM3 Hash Value Length is %d \n",hashValueLength);
	printf("散列: %016llx\n",HashValue);
	clock_t sT = clock();
	birthdayAttack(HashValue,hashValueLength);
	clock_t eT = clock();
	printf("\nTime Cost: %f s \n\n",((double)eT-sT)/CLOCKS_PER_SEC);
}




uint64 reducedSM3(uint8* plainText, long plainLength, int hashValueLength)
{
	uint64 hashValue = 0;
	uint8 fullValue[32];
	int valueLength = hashValueLength;
	SM3Hash(plainText, plainLength, fullValue);
	for (int i = 0; i < 256 / valueLength; i++)
	{
		int i4 = 4 * i;
		uint64 temp = 0;
		for (int j = 0; j < valueLength / 8; j++)
		{
			temp += (uint64)fullValue[i4 + j] << (8 * (valueLength / 8 - 1 - j));
		}
		hashValue ^= temp;
	}
	//printf("%016llx\n", hashValue);
	return hashValue;
}
int birthdayAttack(uint64 hashValue,int hashValueLength)
{
	// **随机** 选择消息进行Hash,比较结果
	int testLength = 32;
	uint8 testMessage[128];
	uint64 collision = 0;
	int mark=1;
	srand((unsigned)time(NULL));
	while (mark)
	{
		for (int i=0;i<testLength;i++)
		{
			testMessage[i] = rand();
		}
		collision = reducedSM3(testMessage,testLength,hashValueLength);
		if (collision==hashValue)
		{
			mark = 0;
		}
	}
	printf("碰撞: ");
	for (int i=0;i<testLength;i++)
	{
		printf("%02x",testMessage[i]);
	}
	return 1;
}