

#include"BirthdayAttack.h"
//�������չ���,����
void test_BirthAttackOfSM3()
{
	printf("**************** SM3 ���չ������� ****************\n\n");
	uint8 mesTxet[] = "202100460116";
	printf("����    : \"%s\"\n����    : 0x", mesTxet);
	for (int j = 0; j < strlen((const char*)mesTxet); j++)
	{
		printf("%02x", mesTxet[j]);
	}
	int hashValLen = 2;//����Hashֵ����
	uint64 HashVal = reducedSM3(mesTxet, strlen((const char*)mesTxet),hashValLen);
	printf("\n�򻯳���: %d Byte\n",hashValLen);
	printf("��ɢ��: 0x%llx\n",HashVal);
	clock_t sT = clock();
	birthdayAttack(HashVal,hashValLen);
	clock_t eT = clock();
	printf("\nʱ�俪��: %f S \n\n",((double)eT-sT)/CLOCKS_PER_SEC);
}


int birthdayAttack(uint64 hashVal,int hashValLen)
{
	// **���** ѡ����Ϣ����Hash,�ȽϽ��
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
	printf("��ײ��Ϣ: 0x");
	for (int i=0;i<testLen;i++)
	{
		printf("%02x",testMessage[i]);
	}
	return 1;
}