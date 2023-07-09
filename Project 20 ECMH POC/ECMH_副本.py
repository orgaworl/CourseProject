from ecdsa import ellipticcurve, ecdsa
import random


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


class Set:
    map_rule = list(range(10))

    # 集合定义
    def __init__(self, G=ecdsa.generator_secp256k1):
        self.G = G
        self.number_count = list(range(11))
        for i in range(11):
            self.number_count[i] = 0
        for i in range(10):
            self.map_rule[i] = mod_inverse(i + 2, self.G.order())
            # print(self.map_rule[i])

    def parse_message(self, message):
        if message == '{}':
            return
        for i in message:
            self.number_count[int(i)] += 1
            self.number_count[10] += 1

    def map_hash(self):
        if self.number_count[10] == 0:
            return self.G
        else:
            hash_out = self.G * 0
            # print('out=',hash_out)
            for i in range(10):
                if self.number_count[i]:
                    a = pow(self.number_count[i] * self.map_rule[i], 1, self.G.order())
                    # print('a=', a)
                    hash_out += a * self.G

            return hash_out

    def iso_add(self, item, number, mode):
        # 1 is add, 0 is minus
        if mode == 1:
            self.number_count[item] += number
            self.number_count[10] += number
        if mode == 0:
            if number > self.number_count[item]:
                return
            self.number_count[item] -= number
            self.number_count[10] -= number

        return self.map_hash()

    def parse_iso_add(self, message):
        for i in message:
            self.number_count[int(i)] += 1
            self.number_count[10] += 1


# s = ecdsa.curve_secp256k1
# secp_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
# secp_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# secp_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#
# G = ellipticcurve.PointJacobi(s, secp_Gx, secp_Gy, 1, secp_r)

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

a = Set(G)
b = Set(G)
ge = a.G.order()

a.parse_message('12345')
hash_a = a.map_hash()
print(hash_a)
b.parse_message('112345')
hash_b = b.map_hash()
print(hash_b)
# test = G*0
# print('test is',test)
# x = pow(2*a.map_rule[1],1,G.order())
# print('x=',x)
# test += x*G
# print(test)
o = b.iso_add(1, 1, 0)
print(o)
