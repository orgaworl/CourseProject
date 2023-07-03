//orgaworl@outlook.com

#include"SM4.h"
#include"iostream"
using namespace std;





void testSM4Function()
{
    uint8_t PK[12] = { 50, 48, 50, 49, 48, 48, 52, 54, 48, 49, 49, 54, };
    uint8 plain[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98 ,0x76,0x54,0x32,0x10 };
    uint8 K[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98 ,0x76,0x54,0x32,0x10 };
    uint8* cipher=SM4Encrypt(plain, K);
    for (int i=0;i<16;i++)
    {
        printf("%02X ", cipher[i]);
    }
}





//SM4分组加密:
//input: uint8[16]明文数组(16字节) && uint8[16]初始密钥数组(16字节)
//output:堆区指针指向密文数据


uint8* SM4Encrypt(uint8 *plaintext,uint8 *K)//[16]
{

    //0.预处理
    //   明文16*8bit->4*32bit
    //   根据K 计算k0-k3
    uint32 XSet[4];
    uint32 key[4];
    uint32* RoundKeySet;
    for (int i = 0; i < 4; i++)
    {
        XSet[i] = (plaintext[4 * i] << 24) + (plaintext[4 * i + 1] << 16) + (plaintext[4 * i + 2] << 8) + (plaintext[4 * i + 3]);
        key[i] = (K[4 * i] << 24) + (K[4 * i + 1] << 16) + (K[4 * i + 2] << 8) + (K[4 * i + 3]);
    }


    //1. 生成轮密钥:  
    RoundKeySet = SM4KeyGenerate(key);
    //for (int i = 0; i < 36; i++)
    //{
    //    printf("%2d %08x\n",i, RoundKeySet[i]);
    //    
    //}
    

    //2. 进行32轮轮函数
    uint32 temp32bit = 0;
    uint32 passSB = 0;
    uint32 passL = 0;
    for (int i=4;i<36;i++)
    {
        //2.1 计算
        uint32 X0 = XSet[0];

        //S
        temp32bit = XSet[1] ^ XSet[2] ^ XSet[3]^RoundKeySet[i];
        passSB = passSBox(temp32bit);

        //L
        passL = passSB;
        passL ^= (passSB << 2) + (passSB >> 30);
        passL ^= (passSB << 10) + (passSB >> 22);
        passL ^= (passSB << 18) + (passSB >> 14);
        passL ^= (passSB << 24) + (passSB >> 8);
        X0 ^= passL;

        //2.2 移动位置(待优化)
        XSet[0] = XSet[1];
        XSet[1] = XSet[2];
        XSet[2] = XSet[3];
        XSet[3] = X0;
    }


    //3, 进行反序变化并将32bit转为8bit
    uint8* cipher = new uint8[16];
    for (int i=0;i<16;i++)
    {
        cipher[i] = XSet[3 - (i / 4)]>>((3-i%4)*8);
    }
    return cipher;//MjAyMTAwNDYwMTE2
}
uint32* SM4KeyGenerate(uint32 *key)//[4]
{

	//开辟36*1*32bit的堆区数组
	uint32* RoundKeySet=new uint32[36];
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
        
        ck = (ckSet[0] << 24) + (ckSet[1] << 16 )+ (ckSet[2] << 8) + ckSet[3];

        temp32bit = RoundKeySet[i - 1] ^ RoundKeySet[i - 2] ^ RoundKeySet[i - 3] ^ ck;


        passSBOX = passSBox(temp32bit);
        //passSBOX  = SM4SBox[(uint8)temp32bit];
        //passSBOX += SM4SBox[uint8(temp32bit>> 8)]<< 8;
        //passSBOX += SM4SBox[uint8(temp32bit>>16)]<<16;
        //passSBOX += SM4SBox[uint8(temp32bit>>24)]<<24;


        passL  = passSBOX ;
        passL ^= ((passSBOX << 13) + (passSBOX >> 19)) ;
        passL ^= ((passSBOX << 23) + (passSBOX >> 9));


        RoundKeySet[i] = RoundKeySet[i - 4] ^ passL;


        ckSet[0] += 28;
        ckSet[1] += 28;
        ckSet[2] += 28;
        ckSet[3] += 28;

    }

    return RoundKeySet;
}
uint32 passSBox(uint32 temp32bit)
{
    uint32 passSBOX = 0;
    passSBOX = SM4SBox[(uint8)temp32bit];
    passSBOX += SM4SBox[uint8(temp32bit >> 8)] << 8;
    passSBOX += SM4SBox[uint8(temp32bit >> 16)] << 16;
    passSBOX += SM4SBox[uint8(temp32bit >> 24)] << 24;

    return passSBOX;
}



