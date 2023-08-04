//orgaworl@outlook.com
#include"SM4.h"


#define maxLen 1048576*16
static uint8 input[maxLen];
static uint8 buf[maxLen];
void benchmark_SM4(int tstLen)
{
    printf("**************** SM4效率测试 ****************\n");
    int loopTimes = 10;
    for (int i = 0; i < maxLen; i++)
    {
        input[i] = rand();
    }
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                        0x1a, 0x2b, 0x3c, 0x4d,0x5e, 0x6f, 0x78, 0x9a };


    SM4Encrypt8ECB(input, 1048576, key, buf);
    printf("  长度(MB) 耗时(S)    吞吐量(MB/S)\n");
    for (int dataSize = 1; dataSize <= tstLen; dataSize += 1)
    {
        clock_t sT = clock();
        for (int i = 0; i < loopTimes; i++)
        {
            SM4Encrypt8ECB(input, dataSize*1048576, key, buf);
        }
        clock_t eT = clock();
        double T = ((double)eT - sT) / CLOCKS_PER_SEC / loopTimes;
        printf("    %2d     %05f    %05f\n", dataSize, T, dataSize / T);


        //double T = ((double)eT - sT) / CLOCKS_PER_SEC;
        //cout << T << " " << (double)l*loopTimes / T / 1048576 << endl;//MByte/s
    }
    printf("\n\n");

}



void test_SM4()
{
    printf("**************** SM4正确性验证 ****************\n");

    uint8_t cipher[16];
    uint8_t plain[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                          0x1a, 0x2b, 0x3c, 0x4d,0x5e, 0x6f, 0x78, 0x9a };
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                          0x1a, 0x2b, 0x3c, 0x4d,0x5e, 0x6f, 0x78, 0x9a };

    SM4Encrypt8(plain, key, cipher);
    printf("\n明文: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", plain[i]);
    }
    printf("\n密钥: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", key[i]);
    }
    printf("\n密文: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", cipher[i]);
    }
    printf("\n\n");

}


int SM4KeyGen8(uint8 key[16], uint32 RoundKeySet[36])//[4]
{
    uint32 key32[4];
    for (int i=0;i<4;i++)
    {
        int i4 = 4 * i;
        key32[i] = (key[i4] << 24) + (key[i4+1] << 16) + (key[i4+2] << 8) + (key[i4+3] << 24);
    }
    SM4KeyGen32(key32, RoundKeySet);
    return 0;
}

int SM4KeyGen32(uint32 key[4],uint32 RoundKeySet[36])//[4]
{
    RoundKeySet[0] = key[0] ^ FK[0];
    RoundKeySet[1] = key[1] ^ FK[1];
    RoundKeySet[2] = key[2] ^ FK[2];
    RoundKeySet[3] = key[3] ^ FK[3];
    uint32 temp32bit = 0;
    uint32 passSBOX = 0;
    uint32 passL = 0;
    uint8 ckSet[4] = { 0x00,0x07,0x0E,0x15 };  //0 7 14 21
    uint32 ck = 0;
    for (int i = 4; i < 36; i++)
    {

        ck = (ckSet[0] << 24) + (ckSet[1] << 16) + (ckSet[2] << 8) + ckSet[3];

        temp32bit = RoundKeySet[i - 1] ^ RoundKeySet[i - 2] ^ RoundKeySet[i - 3] ^ ck;


        //passSBOX = passSBox(temp32bit);
        passSBOX  = SM4SBox[(uint8)temp32bit];
        passSBOX += SM4SBox[uint8(temp32bit>> 8)]<< 8;
        passSBOX += SM4SBox[uint8(temp32bit>>16)]<<16;
        passSBOX += SM4SBox[uint8(temp32bit>>24)]<<24;


        passL = passSBOX;
        passL ^= ((passSBOX << 13) + (passSBOX >> 19));
        passL ^= ((passSBOX << 23) + (passSBOX >> 9));


        RoundKeySet[i] = RoundKeySet[i - 4] ^ passL;


        ckSet[0] += 28;
        ckSet[1] += 28;
        ckSet[2] += 28;
        ckSet[3] += 28;

    }

    return 0;
}

void SM4Encrypt8ECB(uint8*plain,int length,uint8 Key[16],uint8*cipher)
{
    int i;
    int limit = length - 16;
    for (i=0;i<limit;i+=16)
    {
        SM4Encrypt8(&plain[i],Key,&cipher[i]);
    }
    int lack = i+16-length;
    if (lack == 0) { lack = 16; }
    //填充
    for (int j=0;j<lack;j++)
    {
        plain[length + j] = lack;
    }
    SM4Encrypt8(&plain[i], Key, &cipher[i]);

}

void SM4Encrypt8(uint8 plain8[16], uint8 key8[16], uint8 cipher8[16])//[16]
{
    uint32 plain32[4];
    uint32 cipher32[4];
    uint32 key32[4];
    uint32 t32b1;
    uint32 t32b2;
    uint32 t32b3;
    uint32 t32b4;
    for (int i = 0; i < 4; i++)
    {
        int i4 = 4 * i;
        t32b1 = (plain8[i4] << 24);
        t32b2 = (plain8[i4 + 1] << 16);
        t32b3 = (plain8[i4 + 2] << 8);
        t32b4 = (plain8[i4 + 3]);
        t32b1 += t32b2;
        t32b3 += t32b4;
        plain32[i] = t32b1 + t32b3;

        t32b1 = (key8[i4] << 24);
        t32b2 = (key8[i4 + 1] << 16);
        t32b3 = (key8[i4 + 2] << 8);
        t32b4 = (key8[i4 + 3]);
        t32b1 += t32b2;
        t32b3 += t32b4;
        key32[i] = t32b1 + t32b3;
    }
    SM4Encrypt32(plain32,key32,cipher32);
    for (int i = 0; i < 4; i++)
    {
        int i4 = 4 * i;
        cipher8[i4]   = cipher32[i]>>24;
        cipher8[i4+1] = cipher32[i]>>16;
        cipher8[i4+2] = cipher32[i]>>8;
        cipher8[i4+3] = cipher32[i];
    }

}

void SM4Encrypt32(uint32 plain32[4], uint32 key32[4], uint32 cipher32[4])//[4]
{
    uint32 t32b1;
    uint32 t32b2;
    uint32 t32b3;
    uint32 t32b4;

    uint32 RoundKeySet[36];
    RoundKeySet[0] = key32[0] ^ FK[0];
    RoundKeySet[1] = key32[1] ^ FK[1];
    RoundKeySet[2] = key32[2] ^ FK[2];
    RoundKeySet[3] = key32[3] ^ FK[3];
    uint32 temp32bit = 0;
    uint32 passSB = 0;
    uint32 passL = 0;
    uint8 ckSet[4] = { 0x00,0x07,0x0E,0x15 };  //0 7 14 21
    uint32 ck = 0;
    for (int i = 4; i < 36; i++)
    {
        ck = (ckSet[0] << 24) + (ckSet[1] << 16) + (ckSet[2] << 8) + ckSet[3];
        temp32bit = RoundKeySet[i - 1] ^ RoundKeySet[i - 2] ^ RoundKeySet[i - 3] ^ ck;

        passSB  = SM4SBox[(uint8)temp32bit];
        passSB += SM4SBox[uint8(temp32bit>> 8)]<< 8;
        passSB += SM4SBox[uint8(temp32bit>>16)]<<16;
        passSB += SM4SBox[uint8(temp32bit>>24)]<<24;
        passL  =   passSB;
        passL ^= ((passSB << 13) + (passSB >> 19));
        passL ^= ((passSB << 23) + (passSB >> 9));

        RoundKeySet[i] = RoundKeySet[i - 4] ^ passL;

        ckSet[0] += 28;
        ckSet[1] += 28;
        ckSet[2] += 28;
        ckSet[3] += 28;
    }



    uint32 input = 0;
    passSB = 0;
    passL = 0;
    for (int i = 4; i < 36; i++)
    {
        uint32 X0 = plain32[0];
        input = plain32[1] ^ plain32[2] ^ plain32[3] ^ RoundKeySet[i];
        t32b1 = SM4SBox[(uint8)input];
        t32b2 = SM4SBox[uint8(input >> 8)] << 8;;
        t32b3 = SM4SBox[uint8(input >> 16)] << 16;
        t32b4 = SM4SBox[uint8(input >> 24)] << 24;
        t32b1 += t32b2;
        t32b3 += t32b4;
        passSB = t32b1 + t32b3;
        passL = passSB;
        t32b1 = (passSB << 2) + (passSB >> 30);
        t32b2 = (passSB << 10) + (passSB >> 22);
        t32b3 = (passSB << 18) + (passSB >> 14);
        t32b4 = (passSB << 24) + (passSB >> 8);
        t32b1 ^= t32b2;
        passL ^= t32b1;
        t32b3 ^= t32b4;
        passL ^= t32b3;
        X0 ^= passL;
        plain32[0] = plain32[1];
        plain32[1] = plain32[2];
        plain32[2] = plain32[3];
        plain32[3] = X0;
    }
    for (int i = 0; i < 4; i++)
    {
        cipher32[i] = plain32[3 - i];
    }
    //MjAyMTAwNDYwMTE2
}




//uint32 K[4] = { 0x01234567,0x89abcdef,0xfedcba98 ,0x76543210 };
//uint32 plain[4] = { 0x681edf34,0xd206965e,  0x86b3e94f, 0x536e4246 };
//uint32 correctCipher[4] = { 0xf324184f, 0x3c8892b7, 0x2bdc9d7c, 0x612919de };
//
//clock_t startT = clock();
//uint32 cipher[4];//结果输出位置
//clock_t endT = clock();
//cout << "耗时: " << (endT - startT) / CLOCKS_PER_SEC << " S";
//SM4Encrypt32(plain, K, cipher);
//
//for (int i = 0; i < 4; i++)
//{
//    if (cipher[i] != correctCipher[i])
//    {
//        printf("\nError");
//    }
//}
//printf("\n加密结果全部正确\n\n\n\n");



//void SM4EncryptPoi(uint8* plaintext, uint8* K, uint8* cipher)//[16]
//{
//    uint32 t32b1;
//    uint32 t32b2;
//    uint32 t32b3;
//    uint32 t32b4;
//    uint32 XSet[4];
//    uint32 key[4];
//    for (int i = 0; i < 4; i++)
//    {
//        int i4 = 4 * i;
//        t32b1 = (plaintext[i4] << 24);
//        t32b2 = (plaintext[i4 + 1] << 16);
//        t32b3 = (plaintext[i4 + 2] << 8);
//        t32b4 = (plaintext[i4 + 3]);
//        t32b1 += t32b2;
//        t32b3 += t32b4;
//        XSet[i] = t32b1 + t32b3;
//
//        t32b1 = (K[i4] << 24);
//        t32b2 = (K[i4 + 1] << 16);
//        t32b3 = (K[i4 + 2] << 8);
//        t32b4 = (K[i4 + 3]);
//        t32b1 += t32b2;
//        t32b3 += t32b4;
//        key[i] = t32b1 + t32b3;
//    }
//    uint32 RoundKeySet[36];
//    uint32 input = 0;
//    uint32 passSBOX = 0;
//    uint32 passL = 0;
//
//
//    SM4KeyGenerate(key,RoundKeySet);
//
//
//    input = 0;
//    uint32 passSB = 0;
//    passL = 0;
//    for (int i = 4; i < 36; i++)
//    {
//        uint32 X0 = XSet[0];
//        input = XSet[1] ^ XSet[2] ^ XSet[3] ^ RoundKeySet[i];
//        t32b1 = SM4SBox[(uint8)input];
//        t32b2 = SM4SBox[uint8(input >> 8)] << 8;;
//        t32b3 = SM4SBox[uint8(input >> 16)] << 16;
//        t32b4 = SM4SBox[uint8(input >> 24)] << 24;
//        t32b1 += t32b2;
//        t32b3 += t32b4;
//        passSB = t32b1 + t32b3;
//        passL = passSB;
//        t32b1= (passSB << 2) + (passSB >> 30);
//        t32b2= (passSB << 10) + (passSB >> 22);
//        t32b3= (passSB << 18) + (passSB >> 14);
//        t32b4= (passSB << 24) + (passSB >> 8);
//        t32b1 ^= t32b2;
//        passL ^= t32b1;
//        t32b3 ^= t32b4;
//        passL ^= t32b3;
//        X0 ^= passL;
//        XSet[0] = XSet[1];
//        XSet[1] = XSet[2];
//        XSet[2] = XSet[3];
//        XSet[3] = X0;
//    }
//    for (int i = 0; i < 16; i++)
//    {
//        cipher[i] = ((uint8*)&XSet[3 - (i / 4)]) [3-i%4];
//    }
//    //MjAyMTAwNDYwMTE2
//}


//void SM4Encrypt(uint8 plaintext[16], uint8 K[16], uint8 cipher[16])//[16]
//{
//
//    //0.预处理
//    //   明文16*8bit->4*32bit
//    //   根据K 计算k0-k3
//    uint32 XSet[4];
//    uint32 key_[4];
//    for (int i = 0; i < 4; i++)
//    {
//        int i4 = 4 * i;
//        XSet[i] =  (plaintext[i4] << 24);
//        XSet[i] += (plaintext[i4 + 1] << 16);
//        XSet[i] += (plaintext[i4 + 2] << 8); 
//        XSet[i] += (plaintext[i4 + 3]);
//        key_[i] =  (K[i4] << 24);
//        key_[i] += (K[i4 + 1] << 16);
//        key_[i] += (K[i4 + 2] << 8);
//        key_[i] += (K[i4 + 3]);
//    }
//    uint32 temp32bit = 0;
//    uint32 passSBOX = 0;
//    uint32 passL = 0;
//    uint32 RoundKeySet[36];
//
//
//
//    ////1. 生成轮密钥:  
//    SM4KeyGenerate(key_,RoundKeySet);
//    //uint32 *key = (uint32*)key_; 
//    //RoundKeySet[0] = key[0] ^ FK[0];
//    //RoundKeySet[1] = key[1] ^ FK[1];
//    //RoundKeySet[2] = key[2] ^ FK[2];
//    //RoundKeySet[3] = key[3] ^ FK[3];
//    //uint8 ckSet[4] = { 0x00,0x07,0x0E,0x15 };  //0 7 14 21
//    //uint32 ck = 0;
//    //for (int i = 4; i < 36; i++)
//    //{
//
//    //    ck = (ckSet[0] << 24) + (ckSet[1] << 16) + (ckSet[2] << 8) + ckSet[3];
//
//    //    temp32bit = RoundKeySet[i - 1] ^ RoundKeySet[i - 2] ^ RoundKeySet[i - 3] ^ ck;
//
//    //    passSBOX = passSBox(temp32bit);
//
//
//    //    passL = passSBOX;
//    //    passL ^= ((passSBOX << 13) + (passSBOX >> 19));
//    //    passL ^= ((passSBOX << 23) + (passSBOX >> 9));
//
//    //    RoundKeySet[i] = RoundKeySet[i - 4] ^ passL;
//
//    //    ckSet[0] += 28;
//    //    ckSet[1] += 28;
//    //    ckSet[2] += 28;
//    //    ckSet[3] += 28;
//
//    //}
//
//
//    //2. 进行32轮轮函数
//    temp32bit = 0;
//    uint32 passSB = 0;
//    passL = 0;
//    for (int i=4;i<36;i++)
//    {
//        //2.1 计算
//        uint32 X0 = XSet[0];
//
//        //S
//        temp32bit = XSet[1] ^ XSet[2] ^ XSet[3]^RoundKeySet[i];
//        passSB = passSBox(temp32bit);
//        //L
//        passL = passSB;
//        passL ^= (passSB << 2) + (passSB >> 30);
//        passL ^= (passSB << 10) + (passSB >> 22);
//        passL ^= (passSB << 18) + (passSB >> 14);
//        passL ^= (passSB << 24) + (passSB >> 8);
//        X0 ^= passL;
//        //2.2 移动位置(待优化)
//        XSet[0] = XSet[1];
//        XSet[1] = XSet[2];
//        XSet[2] = XSet[3];
//        XSet[3] = X0;
//    }
//    //3, 进行反序变化并将32bit转为8bit
//    for (int i=0;i<16;i++)
//    {
//        cipher[i] = XSet[3 - (i / 4)]>>((3-i%4)*8);
//    }
//    //MjAyMTAwNDYwMTE2
//}
//
//
////传入初始密钥,输出所有轮密钥
//int SM4KeyGenerate(uint32 key[4],uint32 RoundKeySet[36])//[4]
//{
//    RoundKeySet[0] = key[0] ^ FK[0];
//    RoundKeySet[1] = key[1] ^ FK[1];
//    RoundKeySet[2] = key[2] ^ FK[2];
//    RoundKeySet[3] = key[3] ^ FK[3];
//    uint32 temp32bit = 0;
//    uint32 passSBOX = 0;
//    uint32 passL = 0;
//    uint8 ckSet[4] = { 0x00,0x07,0x0E,0x15 };  //0 7 14 21
//    uint32 ck = 0;
//    for (int i = 4; i < 36; i++)
//    {
//
//        ck = (ckSet[0] << 24) + (ckSet[1] << 16) + (ckSet[2] << 8) + ckSet[3];
//
//        temp32bit = RoundKeySet[i - 1] ^ RoundKeySet[i - 2] ^ RoundKeySet[i - 3] ^ ck;
//
//
//        //passSBOX = passSBox(temp32bit);
//        passSBOX  = SM4SBox[(uint8)temp32bit];
//        passSBOX += SM4SBox[uint8(temp32bit>> 8)]<< 8;
//        passSBOX += SM4SBox[uint8(temp32bit>>16)]<<16;
//        passSBOX += SM4SBox[uint8(temp32bit>>24)]<<24;
//
//
//        passL = passSBOX;
//        passL ^= ((passSBOX << 13) + (passSBOX >> 19));
//        passL ^= ((passSBOX << 23) + (passSBOX >> 9));
//
//
//        RoundKeySet[i] = RoundKeySet[i - 4] ^ passL;
//
//
//        ckSet[0] += 28;
//        ckSet[1] += 28;
//        ckSet[2] += 28;
//        ckSet[3] += 28;
//
//    }
//
//    return 0;
//}
//
//uint32 passSBox(uint32 temp32bit)
//{
//    uint32 passSBOX = 0;
//    passSBOX = SM4SBox[(uint8)temp32bit];
//    passSBOX += SM4SBox[uint8(temp32bit >> 8)] << 8;
//    passSBOX += SM4SBox[uint8(temp32bit >> 16)] << 16;
//    passSBOX += SM4SBox[uint8(temp32bit >> 24)] << 24;
//
//    return passSBOX;
//}
//
//
//
