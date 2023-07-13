import gmpy2
from Crypto.Hash import SHA256
from Crypto.Util import *
import math
p  = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F 
a  = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000 
b  = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007 
n  = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141 
h  = 0x1
xG = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798 
yG = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8

def mpz_to_bytes(mpz_num):
    return int(mpz_num).to_bytes((mpz_num.bit_length() + 7) // 8, 'big')

class EllipticCurve:
    def __init__(self,p,a,b,n,h,xG,yG):
        self.p=p
        self.a=a
        self.b=b
        self.n=n
        self.h=h
        self.G=point(xG,yG)
        self.xG=xG
        self.yG=yG
        self.G.setCurve(self)
        
class point:
    curve=0
    x=0
    y=0
    
    def __init__(self,xG=0,yG=0):
        self.x=xG
        self.y=yG
    def setCurve(self,curve):
        self.curve=curve
        
    def __str__(self):
        return f"({hex(self.x)},\n{hex(self.y)})"
 
    
    def __eq__(self,other):
        return (self.x==other.x) and (self.y==other.y)
    

    def __add__(self,other):
        p=self.curve.p
        if(self==other):
            lam=(3*self.x**2+self.curve.a)*gmpy2.invert(2*self.y,p)  
        else:
            lam=gmpy2.mod(other.y-self.y,p)*gmpy2.invert(other.x-self.x,p)
        x=gmpy2.mod(gmpy2.powmod(lam,2,p)-self.x-other.x,p)
        y=gmpy2.mod(lam*(self.x-x)-self.y,p)
        p3=point(x,y)
        p3.setCurve(self.curve)
        return p3
        
    def __mul__(self,k):
        k=gmpy2.mod(k,self.curve.n)
        bitList=[]
        while(k!=0):
            bitList.append(k&0x1)
            k=k>>1
        bitList.reverse()
        bitList.pop(0)
        basic=self
        p3=self
        for i in range(len(bitList)):
            p3=p3+p3
            if(bitList[i]):
                p3=p3+basic
        return p3
    def hexVal(self):
        
        return b'\x04'+mpz_to_bytes(self.x)+mpz_to_bytes(self.y)
    


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
        r=gmpy2.mod(R.x,self.curve.n)
        e=SHA256.new(M).hexdigest()
        e=int(e,16)
        s=(gmpy2.invert(k,n)*(e+self.SK*r)  )
        s=gmpy2.mod(s,self.curve.n)
        return [r,s]
        
    
    def Verify(self,M,Sign,PK):
        e=SHA256.new(M).hexdigest()
        e=int(e,16)
        w=gmpy2.invert(Sign[1],PK.curve.n)
        
        R_=PK.curve.G*(e*w)+PK*(Sign[0]*w)
        r_=R_.x
        if(r_==Sign[0]):
            print("Verify Sucess")
            return 1
        return 0
        
        
secp256k1=EllipticCurve(p,a,b,n,h,xG,yG)

def testECDSA():
    
    obj=ECDSA_SIGN(curve=secp256k1)
    PK=obj.keyGen()
    print(f"PK is:\n{PK}\n")
    M="HELLO".encode()
    print(f"Message is:\n{M}\n")
    Sign=obj.Sign(M)
    print(f"Sign is:\n({Sign[0]},\n{Sign[1]})\n")
    obj.Verify(M,Sign,PK)
    
def forgeSignature(P):
    
    G=secp256k1.G
    
    u=number.getPrime(math.floor(math.log(n,2)))
    v=number.getPrime(math.floor(math.log(n,2)))
    R=G*u+P*v
    r=gmpy2.mod(R.x,n)
    e=gmpy2.mod(r*u*gmpy2.invert(v,n),n)
    s=gmpy2.mod(r*gmpy2.invert(v,n),n)
    print("e:",e)
    print("r:",r)
    print("s:",s)
    return (e,(r,s))
    
def testForge():
    G=secp256k1.G
    P=G*123
    print(f"G is:\n{G}\nP is:\n{P}\n")
    e,sign=forgeSignature(P)
    print(f"for e :\n{e}\nSignature is:\n({sign[0]},\n{sign[1]})")


# testECDSA()
# print()
# testForge()
