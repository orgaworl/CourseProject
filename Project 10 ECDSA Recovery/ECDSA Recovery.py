from ecdsa import ellipticcurve, ecdsa
import random
import hashlib

secp_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
secp_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
secp_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = ellipticcurve.PointJacobi(ecdsa.curve_secp256k1, secp_Gx, secp_Gy, 1, secp_r)


def mod_inverse(a0, m):
    gcd, x, y = extended_gcd(a0, m)
    if gcd != 1:
        raise ValueError("模逆不存在")
    return x % m


# 用于生成模逆

def extended_gcd(a1, b0):
    if a1 == 0:
        return b0, 0, 1
    gcd, x, y = extended_gcd(b0 % a1, a1)
    return gcd, y - (b0 // a1) * x, x


def Recover(r, s, m):
    Hash = hashlib.sha256(m.encode())
    Hash = int(Hash.hexdigest(), 16)
    e = Hash
    x = r
    curve = ecdsa.curve_secp256k1
    n = ecdsa.generator_secp256k1.order()


    y2 = (pow(x, 3, curve.p()) + (curve.a() * x) + curve.b()) % curve.p()
    #print(y2)#y^2  = x^3 + 7

    y = ecdsa.numbertheory.square_root_mod_prime(y2, curve.p())
    #print(y)#sqrt(y^2)

    u_1 = (-ecdsa.numbertheory.inverse_mod(r, n) * e) % n
    u_2 = (ecdsa.numbertheory.inverse_mod(r, n) * s) % n

    R_1 = ellipticcurve.PointJacobi(curve, x, y, 1)
    P_1 = u_1*G + u_2 *R_1
    print('第一个恢复公钥：',P_1)


    R_2 = ellipticcurve.PointJacobi(curve, x, -y, 1)
    P_2 = u_1*G + u_2 *R_2
    print('第二个恢复公钥：',P_2)


def Sign(sk, m):
    Hash = hashlib.sha256(m.encode())
    Hash = int(Hash.hexdigest(), 16)
    e = Hash
    n = ecdsa.generator_secp256k1.order()
    k = random.randint(2 ** 160, 2 ** 161)
    R = k * G
    r = pow(R.x(), 1, n)
    s = pow(ecdsa.numbertheory.inverse_mod(k, n) * (e + r * sk), 1, n)
    return r, s


sk = random.randint(2 ** 160, 2 ** 161)
pk = sk * G
print("PK:", pk)
M = 'Sunshine Rainbow Pony'

r, s = Sign(sk, M)
print('r:',r)
print('s:',s)
Recover(r, s, M)
# PK = ecdsa.Public_key(ecdsa.generator_secp256k1, sk * ecdsa.generator_secp256k1)
# SK = ecdsa.Private_key(PK, sk)
# print('私钥：', sk)
# # print(PK.point)
# print('公钥:', PK.point)
# # print(SK)

# Hash = hashlib.sha256(M.encode())
# Hash = int(Hash.hexdigest(), 16)

# k = random.randint(2 ** 160, 2 ** 256)

# Sig = SK.sign(Hash, k)
# print('签名：', Sig)
# r = Sig.r
# s = Sig.s
# Recover(r, s, Hash)
# PK1, PK2 = Sig.recover_public_keys(Hash, ecdsa.generator_secp256k1)
# print(PK1.point)
# print(PK2.point)
