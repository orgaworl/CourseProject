from gmssl import sm2, sm3, func
from ecdsa import numbertheory, ellipticcurve
import random
import binascii


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


def s_1_a():
    d_1 = random.randint(1, SM2_N)
    P_1 = mod_inverse(d_1, SM2_N) * G
    return P_1, d_1


def s_1_b(P_1):
    d_2 = random.randint(1, SM2_N)
    P = mod_inverse(d_2, SM2_N) * P_1 + (-1) * G
    return P, d_2

def s_2_a(C,d_1):
    if C[0]:
        T_1 = mod_inverse(d_1,SM2_N)*C[0]
        return T_1


def s_3_b(T_1,d_2):
    T_2 = mod_inverse(d_2,SM2_N)*T_1
    return T_2


def s_4_a(T_2,C):
    kdf = T_2 + (-1)*C[0]
    KDF = str(hex(kdf.x()))[2:]+str(hex(kdf.y()))[2:]

    t = sm3.sm3_kdf(KDF.encode(),256)
    M_ = C[1]^int(t,16)
    data = str(hex(M_))[2:].encode()
    data_1 = binascii.a2b_hex(data)


    HASH = str(hex(kdf.x()))[2:] + str(data) + str(hex(kdf.y()))[2:]
    u = int(sm3.sm3_hash(list(HASH.encode())),16)
    print(u)


    if(u == C[2]):
        print('yes')
        print('datax = ',data_1)

def encrypt(message):
    k = random.randint(1, SM2_N)
    C_1 = k * G
    kP = k * P
    KDF = str(hex(kP.x()))[2:] + str(hex(kP.y()))[2:]

    t = sm3.sm3_kdf(KDF.encode(), 256)
    M = binascii.b2a_hex(message)


    HASH = str(hex(kP.x()))[2:] + str(M) + str(hex(kP.y()))[2:]

    M = int(M, 16)
    C_2 = M ^ int(t, 16)
    C_3 = int(sm3.sm3_hash(list(HASH.encode())),16)
    print(C_3)

    return [C_1, C_2, C_3]


P_1, d_1 = s_1_a()
P, d_2 = s_1_b(P_1)
C = encrypt(b'eeee')
T_1 = s_2_a(C,d_1)
T_2 = s_3_b(T_1,d_2)
s_4_a(T_2,C)


test = pow((mod_inverse(d_1 * d_2, SM2_N) - 1), 1, SM2_N)

data = b'eeee'
data1 = binascii.b2a_hex(data)
data2 = binascii.a2b_hex(data1)
# print(data1)
# print(data1.decode())
# print(int(data1.decode(),16))
# print(hex(int(data1.decode(),16)))
x = str(hex(int(data1.decode(), 16)))[2:].encode()

#print(encrypt(b'eeee'))
#print(data2)
