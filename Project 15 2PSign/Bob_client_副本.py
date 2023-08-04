#!/usr/bin/env python3
import socket
import pickle
# from gmssl import sm2,sm3,func
from ecdsa import numbertheory, ellipticcurve
import random
import time


def mod_inverse(a0, m):
    gcd, x, y = extended_gcd(a0, m)
    if gcd != 1:
        raise ValueError("模逆不存在")
    return x % m


def s_12_b(P_1):
    d_2 = random.randint(1, SM2_N)
    P = mod_inverse(d_2, SM2_N) * P_1 + (-1) * G
    return P, d_2


def s_4_b(e, Q_1, d_2):
    k_2 = random.randint(1, SM2_N)
    Q_2 = k_2 * G

    k_3 = random.randint(1, SM2_N)
    Q_3 = k_3 * Q_1 + Q_2

    r = pow(Q_3.x() + e, 1, SM2_N)
    s_2 = pow(d_2 * k_3, 1, SM2_N)
    s_3 = pow(d_2 * (r + k_2), 1, SM2_N)

    return r, s_2, s_3


# 用于生成模逆

def extended_gcd(a1, b0):
    if a1 == 0:
        return b0, 0, 1
    gcd, x, y = extended_gcd(b0 % a1, a1)
    return gcd, y - (b0 // a1) * x, x


SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 定义椭圆曲线参数

curve_sm2 = ellipticcurve.CurveFp(SM2_P, SM2_A, SM2_B)

# 定义生成器点G
G = ellipticcurve.Point(curve_sm2, SM2_Gx, SM2_Gy, SM2_N)

s = socket.socket()
host = socket.gethostname()
port = 9999
s.connect((host, port))
print(s.recv(1024))
p1 = s.recv(1024)
p1 = pickle.loads(p1)

print('P1 is :', p1)
print('Now generate P')
P, d2 = s_12_b(p1)

Q1 = s.recv(366)
Q1 = pickle.loads(Q1)
print('Q1 is :\n', Q1)

e = s.recv(100)
print(type(e))

print('e is :\n', int(e.decode()))

e = int(e)

print('Now generate r')
r, s2, s3 = s_4_b(e, Q1, d2)
print('Here is r:\n', r)
print('Here is s2:\n', s2)
print('Here is s3:\n', s3)
print(len(str(r)),len(str(s2)),len(str(s3)))


seq = str(len(str(r)))+str(len(str(s2)))+str(len(str(s3)))+str(r)+str(s2)+str(s3)


s.send(seq.encode())


s.close()
