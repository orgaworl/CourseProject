from gmssl import sm3
import binascii
import random
import time
def reducedSM3(mes,len):#传入字节码
    hashVal=sm3.sm3_hash(list(mes))
    hashVal=binascii.unhexlify(hashVal)
    #print(hashVal.hex())
    if(32%len!=0): 
        return -1
    result=0
    for i in range(32//len):
        part=hashVal[i*len:(i+1)*len]
        #print(part.hex())
        part=int(part.hex(),16)
        result=(result^part)
        #print(hex(result))
    return result.to_bytes(len,'big')
def isDP(D):
    return 1 if int(D[0:1].hex(),16)&0xF0==0x00 else 0
def f(x,len):
    return reducedSM3(x,len)#

def calCollision(A,B,len):
    SP1=A if A[0]>B[0] else B
    SP2=B if A[0]>B[0] else A
    t1=SP1[0]
    t2=SP2[0]
    SP1=SP1[1]
    SP2=SP2[1]
    
    # temp1=SP1
    # for i in range(t1+1):
    #     temp1=f(temp1,len)
    #     print(temp1.hex())
    # print()
    # temp2=SP2
    # for i in range(t2+1):
    #     temp2=f(temp2,len)
    #     print(temp2.hex())
    # print()
    
    #使得两点到DP的距离相同
    for i in range(t1-t2):
        SP1=f(SP1,len)
    #同步前进,直到相同
    for i in range(t2):
        temp1=f(SP1,len)
        temp2=f(SP2,len)
        if(temp1==temp2):
            #找到碰撞
            # print(f"简化后散列值长度:{len}Byte")
            # print(f"散列值: 0x{temp1.hex()}")
            # print(f"碰撞值: 0x{SP1.hex()}")
            # print(f"碰撞值: 0x{SP2.hex()}")
            return [temp1,SP1,SP2]
        else:
            SP1=temp1
            SP2=temp2
    return 0


def RhoMethod(hashLen):
    #以字节为单位
    DP=dict()
    while(True):
        SP=random.randbytes(32)
        Next=SP
        times=0
        while(True):
            Next=f(Next,hashLen)
            times+=1
            if isDP(Next):
                val=DP.get(Next)
                if(val==None):#未找到碰撞
                    DP[Next]=(times,SP)
                else:#找到碰撞
                    return calCollision(val,(times,SP),hashLen)
                break

def test_RhoMethod(redLen=2):
    print("**************** Rho Method正确性验证 ****************")
    sT=time.time()
    result=RhoMethod(redLen)
    eT=time.time()
    print(f"简化后散列值长度:{redLen} Byte")
    print(f"散列值: 0x{result[0].hex()}")
    print(f"碰撞值: 0x{result[1].hex()}")
    print(f"碰撞值: 0x{result[2].hex()}")
    print(f"耗时  : {(eT-sT)*1000} ms")
    
#r=reducedSM3("202100460116".encode('utf8'),2)
def benchmark_RhoMethod(loopTimes=13):
    print("**************** Rho Method效率测试 ****************")
    print(" 长度(Byte) 耗时(ms)   散列值       碰撞");
    for redLen in [1,2,4,8,16]:
        sT=time.time()
        for i in range(loopTimes):
            result=RhoMethod(redLen)
        eT=time.time()
        print(f"    {redLen}       {(eT-sT)*1000/loopTimes:.6}    {result[0].hex()}     ({result[1].hex()}, {result[2].hex()})")

print("\n")
test_RhoMethod()
print("\n")
benchmark_RhoMethod(1)
print("\n")