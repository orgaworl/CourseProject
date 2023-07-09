import gmpy2
from Crypto.Util import *
import math
p  = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F 
a  = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000 
b  = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007 
n  = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141 
h  = 0x1
xG = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798 
yG = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8

class EllipticCurve:
    def __init__(self,p,a,b,n,h,xG,yG):
        self.p=p
        self.a=a
        self.b=b
        self.n=n
        self.h=h
        self.xG=xG
        self.yG=yG
        
class point:
    def __init__(self,curve):
        self.curve=curve
        self.x=curve.xG
        self.y=curve.yG
        
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
        p3=point(self.curve)
        p3.x=gmpy2.mod(gmpy2.powmod(lam,2,p)-self.x-other.x,p)
        p3.y=gmpy2.mod(lam*(self.x-p3.x)-self.y,p)
        p3.curve=self.curve 
        return p3
        
    def __mul__(self,k):
        k=gmpy2.mod(k,self.curve.n)
        bitList=[]
        while(k!=0):
            bitList.append(k&0x1)
            k=k>>1
        bitList.reverse()
        bitList.pop(0)
        G=self
        p3=self
        for i in range(len(bitList)):
            p3=p3+p3
            if(bitList[i]):
                p3=p3+G
        return p3

        
def forgeSignature(P):
    curve=EllipticCurve(p,a,b,n,h,xG,yG)
    G=point(curve)
    
    u=number.getPrime(math.floor(math.log(n,2)))
    v=number.getPrime(math.floor(math.log(n,2)))
    R=G*u+P*v
    r=gmpy2.mod(R.x,n)
    e=gmpy2.mod(r*u*gmpy2.invert(v,n),n)
    s=gmpy2.mod(r*gmpy2.invert(v,n),n)
    print("e:",e)
    print("r:",r)
    print("s:",s)
    return [e,(r,s)]
    
    
    
# def mul(a,k):
#     bitList=[]
#     while(k!=0):
#         bitList.append(k&0x1)
#         k=k>>1
#     bitList.reverse()
#     bitList.pop(0)
#     G=a
#     for i in range(len(bitList)):
#         a=a+a
#         if(bitList[i]):
#             a=a+G
#     return a
# print(mul(12,7))

curve=EllipticCurve(p,a,b,n,h,xG,yG)
G=point(curve)
P=G*999
print(P)
forgeSignature(P)



