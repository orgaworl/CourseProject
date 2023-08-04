from gmssl import sm2,sm3,func
from ecdsa import numbertheory, ellipticcurve
import random


# private_key = 'B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
# public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
# sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
# # 数据和加密后数据为bytes类型
# data = b"111"
# enc_data = sm2_crypt.encrypt(data)
# print(enc_data)
# dec_data =sm2_crypt.decrypt(enc_data)
# print(dec_data)
# assert dec_data == data
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
    d_1 = random.randint(1,SM2_N)
    P_1 = mod_inverse(d_1,SM2_N)*G
    return P_1,d_1

def s_12_b(P_1):
    d_2 = random.randint(1,SM2_N)
    P = mod_inverse(d_2,SM2_N)*P_1 + (-1)*G
    return P,d_2

def s_2_a(M):
    Z = 'identifier-'
    M_ = Z+M

    e = sm3.sm3_hash(list(M_.encode()))
    print(e)

    e = int(e,16)# 获取消息hash值
    k_1 = random.randint(1,SM2_N)
    Q_1 = k_1*G
    return e,Q_1,k_1

def s_4_b(e,Q_1,d_2):
    k_2 = random.randint(1,SM2_N)
    Q_2 = k_2*G

    k_3 = random.randint(1,SM2_N)
    Q_3 = k_3*Q_1 + Q_2

    r = pow(Q_3.x()+e,1,SM2_N)
    s_2 = pow(d_2*k_3,1,SM2_N)
    s_3 = pow(d_2*(r+k_2),1,SM2_N)

    return r,s_2,s_3


def s_5_a(r,s_2,s_3,d_1,k_1):
    s = pow((d_1*k_1)*s_2+d_1*s_3-r,1,SM2_N)
    if s==0 or s == SM2_N - r:
        print("Fail to generate")
    else:
        return [r,s]

def sm2_ver(message, r, s, pk):
    Z = 'identifier-'
    M_ = Z + message

    e = sm3.sm3_hash(list(M_.encode()))
    print(e)# 获取消息hash值

    e = int(e, 16)
    t = pow((r + s), 1, SM2_N)
    mid = s * G + t * pk
    R = pow(e + mid.x(), 1, SM2_N)
    print(r)
    print(R)
    if R == r:
        return 1
    else:
        return 0




P_1 , d_1 = s_1_a()

P, d_2 = s_12_b(P_1)

test = pow((mod_inverse(d_1*d_2,SM2_N)-1),1,SM2_N)*G

print(P)
print(test)

e, Q_1, k_1 = s_2_a('sm22p')

r, s_2, s_3 = s_4_b(e,Q_1,d_2)

sig = s_5_a(r,s_2,s_3,d_1,k_1)

print(sig)

out = sm2_ver('sm22p',sig[0],sig[1],P)

print(out)