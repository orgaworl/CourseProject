#include"SM4_AESNI.h"


#define maxLen 67108864
uint8 input[maxLen];
uint8 output[maxLen];
void SM4_AESNI8_ECB(uint8* plain, uint8* cipher, int length, uint8 key[16])
{
    int i;
    int limit = length - 16;
    uint32_t sm4_key[36];
    SM4KeyGen8(key, sm4_key);
    for (i = 0; i < limit; i += 16)
    {
        SM4_AESNI(&plain[i], &cipher[i],sm4_key, 1);
    }

}


void test_SM4_AESNI()
{
    printf("**************** SM4_AESNI 正确性验证 ****************\n");
    uint8_t plain[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                          0x1a, 0x2b, 0x3c, 0x4d,0x5e, 0x6f, 0x78, 0x9a };
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                          0x1a, 0x2b, 0x3c, 0x4d,0x5e, 0x6f, 0x78, 0x9a };
    uint8_t cipher[128]{ 0 };
    uint32_t sm4_key[36];
    SM4KeyGen8(key, sm4_key);
    SM4_AESNI(plain, cipher, sm4_key, 1);


    printf("明文: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", plain[i]);
    }printf("\n");

    printf("密钥: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", key[i]);
    }printf("\n");

    printf("密文: 0x ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", cipher[i]);
    }printf("\n\n");

}



void benchmark_SM4_AESNI(int tstLen)
{
    printf("**************** SM4_AESNI 效率测试 ****************\n");
    for (int i = 0; i < maxLen; i++)
    {
        input[i] = rand();
    }
    int loopTimes = 10;
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,0xcd, 0xef,
                        0xfe, 0xdc, 0xba, 0x98,0x76, 0x54, 0x32, 0x10 };
    long dataSize;
    SM4_AESNI8_ECB(input, output, 10*1048576, key);//热身
    printf("  长度(MB) 耗时(S)    吞吐量(MB/S)\n");
    
    for (dataSize =1 ; dataSize <= tstLen; dataSize++)
    {
        if (dataSize > 16) { return; }
        clock_t sT = clock();
        for (int i = 0; i < loopTimes; i++)
        {
            SM4_AESNI8_ECB(input, output,dataSize* 1048576, key);
        }
        clock_t eT = clock();
        
        double T = ((double)eT - sT) / CLOCKS_PER_SEC/loopTimes;
        printf("    %2d     %05f    %05f\n", dataSize, T, dataSize / T);
    }

}



#define MM_PACK0_EPI32(a, b, c, d) _mm_unpacklo_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK1_EPI32(a, b, c, d) _mm_unpackhi_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK2_EPI32(a, b, c, d) _mm_unpacklo_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
#define MM_PACK3_EPI32(a, b, c, d) _mm_unpackhi_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
#define MM_XOR2(a, b) _mm_xor_si128(a, b)
#define MM_XOR3(a, b, c) MM_XOR2(a, MM_XOR2(b, c))
#define MM_XOR4(a, b, c, d) MM_XOR2(a, MM_XOR3(b, c, d))
#define MM_XOR5(a, b, c, d, e) MM_XOR2(a, MM_XOR4(b, c, d, e))
#define MM_XOR6(a, b, c, d, e, f) MM_XOR2(a, MM_XOR5(b, c, d, e, f))
#define MM_ROTL_EPI32(a, n) MM_XOR2(_mm_slli_epi32(a, n), _mm_srli_epi32(a, 32 - n))
static __m128i SM4_SBox(__m128i x);

void SM4_AESNI(uint8_t* input, uint8_t* output, uint32_t sm4_key[32], int enc) 
{
    __m128i vindex,X[4], tmp128[4];
    tmp128[0] = _mm_loadu_si128((const __m128i*)input + 0);
    tmp128[1] = _mm_loadu_si128((const __m128i*)input + 1);
    tmp128[2] = _mm_loadu_si128((const __m128i*)input + 2);
    tmp128[3] = _mm_loadu_si128((const __m128i*)input + 3);

    vindex =_mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

    X[0] = MM_PACK0_EPI32(tmp128[0], tmp128[1], tmp128[2], tmp128[3]);
    X[1] = MM_PACK1_EPI32(tmp128[0], tmp128[1], tmp128[2], tmp128[3]);
    X[2] = MM_PACK2_EPI32(tmp128[0], tmp128[1], tmp128[2], tmp128[3]);
    X[3] = MM_PACK3_EPI32(tmp128[0], tmp128[1], tmp128[2], tmp128[3]);

    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    for (int i = 0; i < 32; i++) {
        __m128i k =_mm_set1_epi32((enc == 0) ? sm4_key[i] : sm4_key[31 - i]);

        tmp128[0] = MM_XOR4(X[1], X[2], X[3], k);
        tmp128[0] = SM4_SBox(tmp128[0]);
        tmp128[0] = MM_XOR6(X[0], tmp128[0], MM_ROTL_EPI32(tmp128[0], 2),
                    MM_ROTL_EPI32(tmp128[0], 10), MM_ROTL_EPI32(tmp128[0], 18),
                    MM_ROTL_EPI32(tmp128[0], 24));
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = tmp128[0];
    }
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);
    _mm_storeu_si128((__m128i*)output + 0, MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 1, MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 2, MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 3, MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

static __m128i addTC(__m128i x) {
    __m128i TC = _mm_set1_epi8(0b00100011);
    return _mm_xor_si128(x, TC);
}

static __m128i addATAC(__m128i x) {
    __m128i ATAC = _mm_set1_epi8(0b00111011);
    return _mm_xor_si128(x, ATAC);
}



static __m128i mulMat(__m128i x, __m128i higherMask, __m128i lowerMask) {
    __m128i tmp1, tmp2;
    __m128i andMask = _mm_set1_epi32(0x0f0f0f0f);
    tmp2 = _mm_srli_epi16(x, 4);
    tmp1 = _mm_and_si128(x, andMask);
    tmp2 = _mm_and_si128(tmp2, andMask);
    tmp1 = _mm_shuffle_epi8(lowerMask, tmp1);
    tmp2 = _mm_shuffle_epi8(higherMask, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    return tmp1;
}

static __m128i mulMatATA(__m128i x) {
    __m128i higherMask =_mm_set_epi8(0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad, 0xb9, 0xaa,0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00);
    __m128i lowerMask =_mm_set_epi8(0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87, 0x5f, 0x3f,0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);
    return mulMat(x, higherMask, lowerMask);
}

static __m128i mulMatTA(__m128i x) {
    __m128i higherMask =_mm_set_epi8(0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40, 0x62, 0x18,0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);
    __m128i lowerMask =_mm_set_epi8(0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4, 0x36, 0xfc,0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00);
    return mulMat(x, higherMask, lowerMask);
}


static __m128i SM4_SBox(__m128i x) {
    __m128i MASK = _mm_set_epi8(0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08,0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);
    x = _mm_shuffle_epi8(x, MASK); 
    x = addTC(mulMatTA(x));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return addATAC(mulMatATA(x));
}


