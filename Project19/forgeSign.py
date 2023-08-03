import sys
sys.path.append('.')
from ECC import point, EllipticCurve,secp256k1

from Crypto.Hash import SHA256
from Crypto.Util import *
from sympy import legendre_symbol,sqrt_mod
import math
import gmpy2
import random
import time

class ECDSA_SIGN:
    SK=0
    PK=0
    curve=0
    def __init__(self,curve):
        self.curve=curve
        SK=0
        PK=curve.G
        
    def keyGen(self):
        self.SK=number.getPrime(math.floor(math.log(self.curve.n,2)))
        self.PK=self.curve.G*self.SK
        return (self.PK)
        
    def Sign(self,M):
        k=number.getPrime(math.floor(math.log(self.curve.n,2)))
        R=self.curve.G*k
        #print(f"true R is\n{R}")
        #print(f"y^2 =\n{hex(gmpy2.powmod(R.y,2,self.curve.p))}")
        r=gmpy2.mod(R.x,self.curve.n)
        e=SHA256.new(M).hexdigest()
        e=int(e,16)
        s=(gmpy2.invert(k,self.curve.n)*(e+self.SK*r)  )
        s=gmpy2.mod(s,self.curve.n)
        app=R.y&0xFF
        return [r,s,app]
        
    
    def Verify(self,M,Sign,PK):
        e=SHA256.new(M).hexdigest()
        e=int(e,16)
        w=gmpy2.invert(Sign[1],PK.curve.n)
        
        R_=PK.curve.G*(e*w)+PK*(Sign[0]*w)
        r_=R_.x
        if(r_==Sign[0]):
            return True
        return False
        
        


def testECDSA(M="HELLO"):
    M=M.encode()
    print("**************** ECDSA正确性验证 ****************")
    obj=ECDSA_SIGN(curve=secp256k1)
    PK=obj.keyGen()
    print(f"PK   :\n{PK}")
    print(f"Message:  {M}")
    Sign=obj.Sign(M)
    print(f"Sign :\n({hex(Sign[0])},\n {hex(Sign[1])})")
    if(obj.Verify(M,Sign,PK)):
        print("\nVerify: Sucess\n")
    else:
        print("\nVerify: Fail\n")
    
def forgeSignature(P):
    
    G=secp256k1.G
    n=secp256k1.n
    u=number.getPrime(math.floor(math.log(n,2)))
    v=number.getPrime(math.floor(math.log(n,2)))
    R=G*u+P*v
    r=gmpy2.mod(R.x,n)
    e=gmpy2.mod(r*u*gmpy2.invert(v,n),n)
    s=gmpy2.mod(r*gmpy2.invert(v,n),n)
    # print("e:",e)
    # print("r:",r)
    # print("s:",s)
    return (e,(r,s))
    
def testForge(P):
    print("**************** 伪造签名 ****************")
    print(f"PK is:\n{P}")
    e,sign=forgeSignature(P)
    print(f"for e :\n{e}\nSignature is:\n({sign[0]},\n{sign[1]})\n")
    
def benchmark_forge(testTimes=7,loopTimes=50):
    print("**************** 伪造效率测试 ****************")
    G=secp256k1.G
    T=0
    for i in range(testTimes):
        randNum=random.randint(1,testTimes)
        P=G*randNum
        sT=time.time()
        for j in range(loopTimes):
            e,sign=forgeSignature(P)
        eT=time.time()
        #print(f"Time Cost: {(eT-sT)*1000}ms")
        curT=(eT-sT)*1000/loopTimes
        print(f"{i+1:>3} {curT:.6}")
        T+=curT
    T/=testTimes
    print(f"伪造签名平均耗时: {T}ms")
    
    
testECDSA("202100460116")
testForge(secp256k1.G*13)
benchmark_forge()