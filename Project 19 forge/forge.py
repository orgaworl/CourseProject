# from ecdsa import SigningKey, VerifyingKey, curves,util
#
# # 生成密钥对
# private_key = SigningKey.generate(curve=curves.SECP256k1)
# public_key = private_key.verifying_key
#
# # 要签名的数据
# data = b"Hello, World!"
#
# # 使用私钥进行签名
# signature = private_key.sign(data)
#
# sig = private_key.sign_digest(b'123456789')
# i = public_key.verify_digest(sig, b'123456789')
#
# print('sig = ', sig.hex())
#
# r,s = util.sigdecode_string(sig,private_key.privkey.order)
# print('yes = ', i)
# print('[r,s]=', [r,s])
#
# #
# # # 使用公钥验证签名
# # is_valid = public_key.verify(signature, data)
# #
# # print("私钥:", private_key.to_string().hex())
# # print("公钥:", public_key.to_string().hex())
# # print("签名:", signature.hex())
# # print("验证结果:", is_valid)
#
# P = int(public_key.to_string().hex(), 16)
# G = curves.NIST192p.generator
# p = private_key.privkey*G
# print('p=', p)
# print('P =', hex(P))
# print('G =', G)
#


from ecdsa import ellipticcurve, ecdsa
import random
import hashlib

s = ecdsa.curve_secp256k1
secp_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
secp_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
secp_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = ellipticcurve.PointJacobi(s, secp_Gx, secp_Gy, 1, secp_r)


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


def keyGen(sk):
    P = G.mul_add(sk, 0, 0)
    return P


def sign(m, G, n, d):  # m要求是字节类型byte
    k = random.randint(1, n)
    R = G.mul_add(k, 0, 0)
    r = 0
    while r == 0:
        r = pow(R.x(), 1, n)
    e = int(hashlib.sha256(m).hexdigest(), 16)
    s = pow(mod_inverse(k, n) * (e + d * r), 1, n)
    return [r, s]


def verify(m, r, s, P, G):
    e = int(hashlib.sha256(m).hexdigest(), 16)
    w = mod_inverse(s, G.order())
    S = G.mul_add(e * w, P, r * w)
    if (S.x() == r):
        return 1
    else:
        return 0


def forge(r, s, P, G):
    n = G.order()
    u = random.randint(1, n)
    v = random.randint(1, n)
    R_ = G.mul_add(u, P, v)
    r_ = pow(R_.x(), 1, n)
    v_inverse = mod_inverse(v, n)
    e_ = pow(r_ * u * v_inverse, 1, n)
    s_ = pow(r_ * v_inverse, 1, n)
    return [r_, s_], e_


def forge_verify(e, r, s, P, G):
    w = mod_inverse(s, G.order())
    S = G.mul_add(e * w, P, r * w)
    if S.x() == r:
        return 1
    else:
        return 0


#
# a = b'123456'
# s = hashlib.sha256(a)
# print(s)
#
# print(G)
sk = random.randint(int(G.order() / 4), G.order())
print('secret key is :', hex(sk))
pk = keyGen(sk)
print('public key is :', pk)
m = b'ecdsa signature'
sig = sign(m, G, G.order(), sk)
print('signature is :', sig)
out = verify(m, sig[0], sig[1], pk, G)
print('Check is :', out)

print('---------------')
sig_,e_ = forge(sig[0], sig[1], pk, G)
print('forged signature is :', sig_)
print('forged hash value is :',e_)
#out_ = verify(m, sig_[0], sig_[1], pk, G)
out_ = forge_verify(e_,sig_[0],sig_[1],pk,G)
print(out_)
