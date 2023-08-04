
#include"LengthExtendAttack.h"

void test_LengthExtendAttack()
{
	printf("**************** SM3 ������չ��ȷ����֤ ****************\n");
	//1. ԭ��ϢM ����Hash
	uint8 plain[300] = "Hello";
	uint8 HashVal[32];
	uint64 mesLen_B = strlen((const char*)plain);
	uint64 mesLen_b = 8*mesLen_B;
	SM3Hash(plain,mesLen_B , HashVal);


	printf("\nԭ��Ϣֵ: 0x");
	for (int i = 0; i <mesLen_B; i++) { printf("%02x",plain[i]); }
	printf("\n��Ϣɢ��: 0x");
	for (int j = 0; j < 32; j++){printf("%02x", HashVal[j]);}


	//2. ����ԭ��ϢHashֵ���г�����չ����
	uint8 x[] = ", Alice!";
	uint64 xLen_B = strlen((const char*)x);


	clock_t sT = clock();
	lengthExtendAttack(HashVal, mesLen_B, x, xLen_B, HashVal);

	clock_t eT = clock();

	printf("\n׷����Ϣ: 0x");
	for (int i=0;i<xLen_B;i++)
	{
		printf("%02x", x[i]);
	}
	printf("\nα��ֵ  : 0x");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", HashVal[i]);
	}



	//3.1 ����z ��֤�������
	uint64 d = (447 - mesLen_b) % 512;//MĬ�����ֽ�Ϊ��λ
	int zLen_B = (65 + d)/8+xLen_B;//�ֽ�
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


	//3.2 ��֤
	printf("\n\n����Ϣֵ: 0x");
	for (int i = 0; i < mesLen_B + zLen_B; i++) { printf("%02x", plain[i]); }

	SM3Hash(plain,(mesLen_B+zLen_B),HashVal);

	printf("\nɢ��ֵ  : 0x");
	for (int j = 0; j < 32; j++) { printf("%02x", HashVal[j]); }
	

	

	double T = ((double)eT - sT) / CLOCKS_PER_SEC;
	printf("\n\n\n��ʱ: %ld clock", (eT - sT));
	printf("\n��ʱ: %5f S", T);
	printf("\n");
}


#define bufLen 1048576*16
uint8_t buf[bufLen];
void benchmark_LEA(int tstLen)
{
	printf("\n**************** SM3 ������չЧ�ʲ��� ****************\n");
	//1. ԭ��ϢM ����Hash
	uint8 plain[300] = "Hello";
	uint8 HashVal[32];
	uint64 mesLen_B = strlen((const char*)plain);
	SM3Hash(plain, mesLen_B, HashVal);


	//2. ����ԭ��ϢHashֵ���г�����չ����

	int loopTimes = 10;
	printf("  ����(MB) ��ʱ(S)    ������(MB/S)\n");
	for (int dataSize = 1; dataSize <= tstLen; dataSize += 1)
	{
		clock_t sT = clock();
		for (int i = 0; i < loopTimes; i++)
		{
			lengthExtendAttack(HashVal, mesLen_B, buf, 1048576 *dataSize, HashVal);
		}
		clock_t eT = clock();
		double T = ((double)eT - sT) / CLOCKS_PER_SEC / loopTimes;
		printf("    %02d     %05f    %05f\n", dataSize, T, dataSize / T);
	}
	printf("\n");
}

// mesLen_B&xLen_B ���ֽ�Ϊ��λ
int lengthExtendAttack(uint8 hashVal[32], uint64 mesLen_B, uint8* x, uint64 xLen_B,uint8 newHash[32])
{

	// ���� x||pad 
	int blockSize = xLen_B / 64+1;
	int pos;
	//1. padding ǰ blockSize-1 ����
	uint32** mesBlock = new uint32 * [blockSize] {0};
	for (int i = 0; i < blockSize - 1; i++){
		mesBlock[i] = new uint32[16];
		pos = 64 * i;
		for (int j = 0; j < 16; j++){
			mesBlock[i][j] = (x[pos] << 24) + (x[pos + 1] << 16) + (x[pos + 2] << 8) + (x[pos + 3]);
			pos += 4;
		}
	}
	//2. padding ���һ����
	mesBlock[blockSize - 1] = new uint32[16]{0};
	int block8Num = xLen_B % 64; //ʣ��8bit������
	int block32Num = block8Num / 4;//ʣ��32bit������
	//2.1 �����512bit�����ʣ�µ�32bit��
	pos = (64 * (blockSize - 1));
	for (int j = 0; j < block32Num; j++){
		mesBlock[blockSize - 1][j] = (x[pos] << 24)+ (x[pos + 1] << 16)+ (x[pos + 2] << 8)+ (x[pos + 3]);
		pos += 4;
	}
	//2.2 ʣ�µļ���8bit�����ͬһ��32bit����
	block8Num = block8Num - 4 * block32Num;
	for (int k = 0; k < block8Num; k++){
		mesBlock[blockSize - 1][block32Num] += (x[pos + k] << (8 * (3 - k)));
	}
	//2.3 д1bit 0b1
	if (block8Num == 4){
		mesBlock[blockSize - 1][block32Num + 1] = 0x80000000;
	}
	else{
		mesBlock[blockSize - 1][block32Num] += 0b10000000 << ((3 - block8Num) * 8);
	}
	//2.4 д64bit����ֵ(ע����С��)
	uint64 totalLen = 512*(mesLen_B/64+1) + xLen_B*8;
	uint32 temp32bit = ((long)totalLen) >> 31;
	temp32bit >>= 1;
	mesBlock[blockSize - 1][14] = temp32bit;
	mesBlock[blockSize - 1][15] = totalLen;



	//ѹ������
	uint32* linkVariable = new uint32[8];
	for (int i = 0; i < 8; i++)
	{   //��С��ת��
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
	

	//��С��ת��
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
