from Crypto.Hash import SHA256
from Crypto.Util import *
from sympy import legendre_symbol,sqrt_mod
import math
import gmpy2

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
    def subins(self,x):
        result=gmpy2.powmod(x,3,self.p)
        result+=gmpy2.mod(self.a*gmpy2.powmod(x,2,self.p),self.p)
        result=gmpy2.mod(result+self.b,self.p)
        return sqrt_mod(result,self.p,1)
        # result= sqrt_mod(result,self.p) #默认正值
        # return [result,-result]
        
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
        return f"({hex(self.x)},\n {hex(self.y)})"
    
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
        
    def __sub__(self,other):
        other.y=-other.y
        return self+other

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

secp256k1=EllipticCurve(p,a,b,n,h,xG,yG)