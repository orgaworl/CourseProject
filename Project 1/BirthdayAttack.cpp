

#include"BirthdayAttack.h"
//调用生日攻击,测试
void test_BirthAttackOfSM3()
{
	printf("**************** SM3 生日攻击测试 ****************\n\n");
	uint8 mesTxet[] = "202100460116";
	printf("明文    : \"%s\"\n明文    : 0x", mesTxet);
	for (int j = 0; j < strlen((const char*)mesTxet); j++)
	{
		printf("%02x", mesTxet[j]);
	}
	int hashValLen = 2;//设置Hash值长度
	uint64 HashVal = reducedSM3(mesTxet, strlen((const char*)mesTxet),hashValLen);
	printf("\n简化长度: %d Byte\n",hashValLen);
	printf("简化散列: 0x%llx\n",HashVal);
	clock_t sT = clock();
	birthdayAttack(HashVal,hashValLen);
	clock_t eT = clock();
	printf("\n时间开销: %f S \n\n",((double)eT-sT)/CLOCKS_PER_SEC);
}


int birthdayAttack(uint64 hashVal,int hashValLen)
{
	// **随机** 选择消息进行Hash,比较结果
	int testLen = 32;
	uint8 testMessage[128];
	uint64 collision = 0;
	int mark=1;
	srand((unsigned)time(NULL));
	while (mark)
	{
		for (int i=0;i<testLen;i++)
		{
			testMessage[i] = rand();
		}
		collision = reducedSM3(testMessage,testLen,hashValLen);
		if (collision==hashVal)
		{
			mark = 0;
		}
	}
	printf("碰撞消息: 0x");
	for (int i=0;i<testLen;i++)
	{
		printf("%02x",testMessage[i]);
	}
	return 1;
}