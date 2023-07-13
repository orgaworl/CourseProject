import sys
sys.path.append('E:\FileSourceCode\projectSourceCode\创新创业\CourseProject\Project19 forge a signature to pretend that you are Satoshi') # 表示将当前程序运行目录即root添加到path里面进行查找
#sys.path.append('..\Project19 forge a signature to pretend that you are Satoshi')

from forgeSign import point, EllipticCurve,secp256k1
from Crypto.Util import number
import math
import gmpy2
import random
from Crypto.Hash import SHA256

class Schnorr:
    curve=0
    SK=0 #d
    PK=0 #P
    def __init__(self,curve):
        self.curve=curve
    def keyGen(self):
        self.SK=number.getPrime(math.floor(math.log(self.curve.n,2)))
        self.PK=self.curve.G*self.SK
        return self.PK
    
    def Sign(self,M):
        k=number.getPrime(math.floor(math.log(self.curve.n,2)))
        R=self.curve.G*k
        e=SHA256.new(R.hexVal()+M).hexdigest()
        e=int(e,16)
        s=gmpy2.mod(k+e*self.SK,self.curve.n)
        return [R,s]
        
    
    def Verify(self,M,Sign,PK):
        e=SHA256.new(Sign[0].hexVal()+M).hexdigest()
        e=int(e,16)
        LeftR=secp256k1.G*Sign[1]
        RightR=Sign[0]+PK*e
        if(LeftR==RightR):
            print("Verify Sucess")
            return 1
        return 0
    def BatchVerify(self,MList,SignList,PKList):
        n=len(MList)
        if(n!=len(SignList) or n!=len(PKList)):
            print("Error")
            return 0
        aList=[random.randint(1,2**10) for i in range(n)]
        L1=SignList[0][1]+sum([SignList[i][1]*aList[i] for i in range(1,n)])
        L1=self.curve.G*L1
        R1=SignList[0][0]
        for i in range(1,n):
            R1+=SignList[i][0]*aList[i]
        eList=[SHA256.new(SignList[i][0].hexVal()+MList[i]).hexdigest() for i in range(n)]
        eList=[int(eList[i],16) for i in range(len(eList))]
        R2=PKList[0]*eList[0]
        for i in range(1,n):
            R2+=PKList[i]*(eList[i]*aList[i])
        if(L1==R1+R2):
            print("Batch Verify All Sucess")
            return 1
        return 0
    
def testSchnorr():
    M=b'Hello!'
    obj=Schnorr(secp256k1)
    PK=obj.keyGen()
    print(f"PK is\n{PK}\n")
    print(f'M is: {M}\n')
    Sign=obj.Sign(M)
    print(f'Signature is:\n{Sign[0]}\n{Sign[1]}\n')
    obj.Verify(M,Sign,PK)
    
def testBatch():
    ML=[b'Hello,world.',b'A fox jumps over the lazy dog',b'Cryptograph']
    obj=Schnorr(secp256k1)
    PKL=list()
    SIGNL=list()
    mesNum=len(ML)
    for i in range(mesNum):
        PKL.append(obj.keyGen())
        SIGNL.append(obj.Sign(ML[i]))
        print(f'M is: {ML[i]}')
        print(f"PK is\n{PKL[i]}")
        print(f'Signature is:\n{SIGNL[i][0]}\n{SIGNL[i][1]}\n')
    obj.BatchVerify(ML,SIGNL,PKL)
    
print()
#testSchnorr()
print()
testBatch()
print()