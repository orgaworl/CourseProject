from ecdsa import ellipticcurve, ecdsa
from gmssl import sm2, sm3, func
import base64
import binascii
import random
import time
import math

SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 定义椭圆曲线参数
p = SM2_P
a = SM2_A
b = SM2_B
n = SM2_N
Gx = SM2_Gx
Gy = SM2_Gy
curve_sm2 = ellipticcurve.CurveFp(p, a, b)

# 定义生成器点G
G = ellipticcurve.Point(curve_sm2, Gx, Gy, n)


def SM2_Key_Generate():
    d = random.randint(2 ^ 160, SM2_N - 1)
    public_key = d * G
    secret_key = d
    pair = [secret_key, public_key]
    return pair


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


# print(G)


def sm2_sig(message, sk, k):
    message = message.encode()
    message = list(message)
    # print(message)
    e = sm3.sm3_hash(message)  # 获取消息hash值
    e = int(e, 16)

    c = k * G
    r = pow(e + c.x(), 1, SM2_N)
    mid = mod_inverse((1 + sk), SM2_N)
    s = pow(mid * (k - r * sk), 1, SM2_N)

    while r == 0 or (r + k) == SM2_N or s == 0:
        k = random.randint(1, SM2_N - 1)
        c = k * G
        r = pow(e + c.x(), 1, SM2_N)
        mid = mod_inverse((1 + sk), SM2_N)
        s = pow(mid * (k - r * sk), 1, SM2_N)

    sig = [r, s]
    return sig


# sm2签名

def sm2_ver(message, r, s, pk):
    message = message.encode()
    message = list(message)
    e = sm3.sm3_hash(message)  # 获取消息hash值

    e = int(e, 16)
    t = pow((r + s), 1, SM2_N)
    mid = s * G + t * pk
    R = pow(e + mid.x(), 1, SM2_N)
    if R == r:
        return 1
    else:
        return 0


def sm2_leaking_k(r, s, k):
    d = ((k - s) * ecdsa.numbertheory.inverse_mod(r + s, G.order())) % G.order()
    return d


def sm2_reusing_k(r1, r2, s1, s2):
    d = (ecdsa.numbertheory.inverse_mod((r1 - r2 + s1 - s2), G.order()) * (s2 - s1)) % G.order()
    return d


def sm2_same_k(r1, r2, s1, s2, d1):
    d2 = (((r1 + s1) * d1 + (s1 - s2)) * ecdsa.numbertheory.inverse_mod((r2 + s2), G.order())) % G.order()
    return d2


def sm2_same_d_k(r, s):
    d = ((-s) * ecdsa.numbertheory.inverse_mod(r + s - 1, G.order()))%G.order()
    return d


message = 'sm2'
m = 'sm3'
k = random.randint(1, SM2_N - 1)

t0 = time.time()
d, P = SM2_Key_Generate()
d2, P2 = SM2_Key_Generate()
print(d)
print(d2)

r, s = sm2_sig(message, d, k)
r2, s2 = sm2_sig(m, d, k)
r22, s22 = sm2_sig(m, d2, k)
rr,ss = sm2_sig(m,d,d)

d_ = sm2_leaking_k(r, s, k)
print('leaking k:', d_)
dd = sm2_reusing_k(r, r2, s, s2)
print('reusing k:', dd)
d_2 = sm2_same_k(r, r22, s, s22, d)
print('using same k:', d_2)
# sm2 签名验证
d__ = sm2_same_d_k(rr,ss)
print('same d&k:',d__)
#
# private = str(hex(sig[0]))[2:]
# public = str(hex(sig[1]))[2:]
#
# sm2_crypt = sm2.CryptSM2(public_key=public, private_key=private)
# data = b"111"
# sign = sm2_crypt.sign_with_sm3(data)
# assert sm2_crypt.verify_with_sm3(sign, data)
