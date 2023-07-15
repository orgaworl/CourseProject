import sys
sys.path.append('E:\FileSourceCode\projectSourceCode\创新创业\CourseProject\Project19 forge a signature to pretend that you are Satoshi') # 表示将当前程序运行目录即root添加到path里面进行查找
#sys.path.append('..\Project19 forge a signature to pretend that you are Satoshi')

from forgeSign import point, EllipticCurve,secp256k1,ECDSA_SIGN,sqrt_mod
from Crypto.Util import number
import math
import gmpy2
import random
from Crypto.Hash import SHA256


def deducePK(curve,M,SIGN):
    x=SIGN[0]
    y=curve.subins(x)
    if(y==None):
        print("ERROR")
        return 0
    print(f"y =\n{y}")
    if(SIGN[2]&y[0]==SIGN[2]):
        y=y[0]
    else:
        y=y[1]
    print(f"select y:\n{y}\n")
    R=point(x,y)
    R.setCurve(curve)
    print(f"deduced R is\n{R}")
    e=SHA256.new(M).hexdigest()
    e=int(e,16)
    s=SIGN[1]
    P=(R*s-curve.G*e)*gmpy2.invert(x,curve.n)
    return P
        
        
def test_deduce():
    M=b'HELLO'
    obj=ECDSA_SIGN(secp256k1)
    PK=obj.keyGen()
    print(f"true PK is:\n{PK}")
    SIGN=obj.Sign(M)
    
    PK_=deducePK(secp256k1,M,SIGN)
    print(f"deduced PK is:\n{PK_}")
    if(PK==PK_):
        print("\nCHECK: PK IS SAME")



test_deduce()
print("\n\n")