from ecdsa import ellipticcurve, ecdsa
import random
import hashlib

SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 定义椭圆曲线参数

curve_sm2 = ellipticcurve.CurveFp(SM2_P, SM2_A, SM2_B)

# 定义生成器点G
G1 = ecdsa.generator_secp256k1
G2 = ellipticcurve.Point(curve_sm2, SM2_Gx, SM2_Gy, SM2_N)


def extended_gcd(a1, b0):
    if a1 == 0:
        return b0, 0, 1
    gcd, x, y = extended_gcd(b0 % a1, a1)
    return gcd, y - (b0 // a1) * x, x


def key_generate(generater):
    d = random.randint(2 * 160, 2 ** 161)
    P = d * generater
    return d, P


def ecdsa_sign(m, d, k):
    R = k * G1
    e = hashlib.sha256(m.encode())
    r = R.x() % G1.order()
    s = ((int(e.hexdigest(), 16) + r * d) * ecdsa.numbertheory.inverse_mod(k, G1.order())) % G1.order()
    return k, r, s


def ecdsa_verify(m, r, s, P):
    e = hashlib.sha256(m.encode())
    e = int(e.hexdigest(), 16)
    w = ecdsa.numbertheory.inverse_mod(s, G1.order())
    Q = e * w * G1 + r * w * P
    if Q.x() == r:
        return True
    else:
        return False


def ecdsa_leaking_k(k, r, s, m):
    e = hashlib.sha256(m.encode())
    d = (ecdsa.numbertheory.inverse_mod(r, G1.order()) * (s * k - int(e.hexdigest(), 16))) % G1.order()
    return d


def ecdsa_reusing_k(r1, r2, s1, s2, m1, m2):
    e1 = hashlib.sha256(m1.encode())
    e2 = hashlib.sha256(m2.encode())
    e1 = int(e1.hexdigest(), 16)
    e2 = int(e2.hexdigest(), 16)
    d = (ecdsa.numbertheory.inverse_mod(s2 * r1 - s1 * r2, G1.order()) * (s1 * e2 - s2 * e1)) % G1.order()
    return d


def ecdsa_using_same_k(r, r_, s, s_, m, m_, d):  # sk对应的是r，s，m
    e = hashlib.sha256(m.encode())
    e_ = hashlib.sha256(m_.encode())
    e = int(e.hexdigest(), 16)
    e_ = int(e_.hexdigest(), 16)
    d_ = (((s_ * e - s * e_) + s_ * r * d) * (ecdsa.numbertheory.inverse_mod(s * r_, G1.order()))) % G1.order()
    return d_


def ecdsa_same_d_k(r, s, m):
    e = hashlib.sha256(m.encode())
    e = int(e.hexdigest(), 16)
    d = (e * ecdsa.numbertheory.inverse_mod(s - r, G1.order())) % G1.order()
    return d


def ecdsa_split(r, s):
    return r, -s


def forge(r, s, P, G):
    n = G.order()
    u = random.randint(1, n)
    v = random.randint(1, n)
    R_ = G.mul_add(u, P, v)
    r_ = pow(R_.x(), 1, n)
    v_inverse = ecdsa.numbertheory.inverse_mod(v, n)
    e_ = pow(r_ * u * v_inverse, 1, n)
    s_ = pow(r_ * v_inverse, 1, n)
    return [r_, s_], e_


k = random.randint(2 ** 160, 2 ** 161)
print('k is:', k)

d, P = key_generate(G1)
d_, P_ = key_generate(G1)
print('d is:', d)
print('d_ is:', d_)

m = 'ecdsa'
m2 = 'sunshine'
k, r, s = ecdsa_sign(m, d, k)
d2 = ecdsa_leaking_k(k, r, s, m)
print('leaking k forged d is:', d2)

k2, r2, s2 = ecdsa_sign(m2, d, k)
d3 = ecdsa_reusing_k(r, r2, s, s2, m, m2)
print('reusing k forged d is:', d3)

k_, r_, s_ = ecdsa_sign(m2, d_, k)
d_ = ecdsa_using_same_k(r, r_, s, s_, m, m2, d)
print('using same k forged d is:', d_)

rr, ss = ecdsa_split(r, s)
x = ecdsa_verify(m, r, s, P)
y = ecdsa_verify(m, rr, ss, P)
print(x == y)

_k,_r,_s = ecdsa_sign(m,d,d)
d4 = ecdsa_same_d_k(_r,_s,m)
print(d4)