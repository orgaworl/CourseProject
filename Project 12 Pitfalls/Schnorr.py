from ecdsa import ellipticcurve, ecdsa
import random
import hashlib

G = ecdsa.generator_secp256k1


def Schnorr_KeyGen():
    d = random.randint(2 ** 160, 2 ** 161)
    P = d * G
    return d, P


def Schnorr_Sign(M, d, k):
    R = k * G
    e = hashlib.sha256((str(R.x()) + str(R.y()) + M).encode())
    e = int(e.hexdigest(), 16)
    s = (k + e * d) % G.order()
    return R, s


def Schnorr_Verify(M, R, s, P):
    e = hashlib.sha256((str(R.x()) + str(R.y()) + M).encode())
    e = int(e.hexdigest(), 16)
    return s * G == R + e * P


def Schnorr_leaking_k(M, R, s, k):
    e = hashlib.sha256((str(R.x()) + str(R.y()) + M).encode())
    e = int(e.hexdigest(), 16)
    d = (ecdsa.numbertheory.inverse_mod(e, G.order()) * (s - k)) % G.order()
    return d


def Schnorr_reusing_k(M1, M2, R1, R2, s1, s2):
    e1 = hashlib.sha256((str(R1.x()) + str(R1.y()) + M1).encode())
    e1 = int(e1.hexdigest(), 16)
    e2 = hashlib.sha256((str(R2.x()) + str(R2.y()) + M2).encode())
    e2 = int(e2.hexdigest(), 16)
    d = ((s1 - s2) * ecdsa.numbertheory.inverse_mod((e1 - e2), G.order())) % G.order()
    return d


def Schnorr_same_k(M1, M2, R1, R2, s1, s2, d1):
    e1 = hashlib.sha256((str(R1.x()) + str(R1.y()) + M1).encode())
    e1 = int(e1.hexdigest(), 16)
    e2 = hashlib.sha256((str(R2.x()) + str(R2.y()) + M2).encode())
    e2 = int(e2.hexdigest(), 16)
    d2 = (ecdsa.numbertheory.inverse_mod(e2, G.order()) * (e1 * d1 - (s1 - s2))) % G.order()
    return d2

def Schnorr_same_dk(M,R,s):
    e = hashlib.sha256((str(R.x()) + str(R.y()) + M).encode())
    e = int(e.hexdigest(), 16)
    d = (ecdsa.numbertheory.inverse_mod((e+1),G.order())*s)%G.order()
    return d



M = 'test'
M2 = 'sunshine rainbow pony'
k = random.randint(2 ** 160, 2 ** 161)
d, P = Schnorr_KeyGen()
dd,PP = Schnorr_KeyGen()
print('d is:', d)
print('d2 is',dd)
R, s = Schnorr_Sign(M, d, k)
RR,ss = Schnorr_Sign(M2,dd,k)
SR,Ss = Schnorr_Sign(M,d,d)
R2, s2 = Schnorr_Sign(M2, d, k)
print(Schnorr_Verify(M, R, s, P))
d_ = Schnorr_leaking_k(M, R, s, k)
print('leaking k :', d_)
d2 = Schnorr_reusing_k(M, M2, R, R2, s, s2)
print('reusing k :', d2)
dd = Schnorr_same_k(M,M2,R,RR,s,ss,d)
print('same k :',dd)
Sd = Schnorr_same_dk(M,SR,Ss)
print('same dk :',Sd)