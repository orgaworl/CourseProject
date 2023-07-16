#!/usr/bin/env python3
import socket
import pickle
from gmssl import sm2, sm3, func
from ecdsa import numbertheory, ellipticcurve
import random


def s_1_a():
    d_1 = random.randint(1, SM2_N)
    P_1 = mod_inverse(d_1, SM2_N) * G
    return P_1, d_1


def s_2_a(M):
    Z = 'identifier-'
    M_ = Z + M

    e = sm3.sm3_hash(list(M_.encode()))
    print(e)

    e = int(e, 16)  # 获取消息hash值
    k_1 = random.randint(1, SM2_N)
    Q_1 = k_1 * G
    return e, Q_1, k_1


def mod_inverse(a0, m):
    gcd, x, y = extended_gcd(a0, m)
    if gcd != 1:
        raise ValueError("模逆不存在")
    return x % m


def s_5_a(r, s_2, s_3, d_1, k_1):
    s = pow((d_1 * k_1) * s_2 + d_1 * s_3 - r, 1, SM2_N)
    if s == 0 or s == SM2_N - r:
        print("Fail to generate")
    else:
        return [r, s]


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
s.bind((host, port))

s.listen(5)
p1, d1 = s_1_a()

c, addr = s.accept()
print('连接地址为：', addr)
c.send(b'Here is pk')

serialized_point = pickle.dumps(p1)
c.send((serialized_point))
M = 'Sunshine Rainbow Pony SM2'

e, Q1, k1 = s_2_a(M)

serialized_Q1 = pickle.dumps(Q1)
c.send(serialized_Q1)
print(len(serialized_Q1))
print('Here is Q1:\n', Q1)

# serialized_e = pickle.dumps(e)
# c.send(serialized_e)
send_e = str(e)
c.send(send_e.encode())
print('Here is e:\n', e)
print(len(send_e.encode()))

seq = c.recv(256).decode()
len = []
len.append(int(seq[0:2]))
len.append(int(seq[2:4]))
len.append(int(seq[4:6]))
r = int(seq[6:6+len[0]])
s2 = int(seq[6+len[0]:6+len[0]+len[1]])
s3 = int(seq[6+len[0]+len[1]:6+len[0]+len[1]+len[2]])




print('Here is r:\n', r)

print('Here is s2:\n', s2)

print('Here is s3:\n', s3)
#
print('Now generate s')
#
s = s_5_a(r, s2, s3, d1, k1)
print('Here is s:\n',s)

c.close()
