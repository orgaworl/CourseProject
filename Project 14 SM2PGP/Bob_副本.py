import base64
from ecdsa import ellipticcurve, ecdsa, numbertheory
from gmssl import sm3
import binascii
from cryptography.fernet import Fernet
import random
import socket
import pickle

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

w = int(256 / 2 - 1)

h = 1  # sm2推荐余因子1


def pk_get(loc, pk):
    print('发送公钥：', pk)
    serial_pk = pickle.dumps(pk)
    loc.send(serial_pk)
    PA = loc.recv(1024)
    PA = pickle.loads(PA)
    print('收到公钥：', PA)
    return PA


def Z_get(ID, pk):
    entlen = len(ID)
    ENTL = str(entlen)
    has = ENTL + ID + str(SM2_A) + str(SM2_B) + str(G.x()) + str(G.y()) + str(pk.x()) + str(pk.y())
    has = list(has.encode())
    Z = sm3.sm3_hash(has)
    # print('Z is :',Z)
    return Z


def SM2_Key_Generate():
    d = random.randint(2 ** 160, 2 ** 193)
    public_key = d * G
    secret_key = d
    # pair = [secret_key, public_key]
    return secret_key, public_key

def encrypt(message,pk):
    k = random.randint(1, SM2_N)
    C_1 = k * G
    kP = k * pk
    KDF = str(hex(kP.x()))[2:] + str(hex(kP.y()))[2:]

    t = sm3.sm3_kdf(KDF.encode(), 64)
    M = binascii.b2a_hex(message)
    HASH = str(hex(kP.x()))[2:] + str(M) + str(hex(kP.y()))[2:]
    M = int(M, 16)
    C_2 = M ^ int(t, 16)
    C_3 = int(sm3.sm3_hash(list(HASH.encode())),16)
    #print(C_3)
    return [C_1, C_2, C_3]

def decrypt(C_1,C_2,C_3,sk):
    x,y = C_1.x(),C_1.y()
    cx,cy = (sk*C_1).x(),(sk*C_1).y()
    kdf = str(hex(cx))[2:]+str(hex(cy))[2:]
    KDF = sm3.sm3_kdf(kdf.encode(),64)
    M = C_2^int(KDF,16)
    data = str(hex(M))[2:].encode()
    data_1 = binascii.a2b_hex(data)
    print(data_1)
    return data_1



def key_exchange(soc):
    print('Begin to key exchange')
    op = '1'
    b.send(op.encode())

    P_1 = soc.recv(1024)
    #print(P_1)
    P_1 = pickle.loads(P_1)

    d_2 = random.randint(2 ** 160, 2 ** 193)
    P_2 = (d_2 * G)
    x2 = P_2.x()

    x_2 = 2 ** w + (x2 & (2 ** w - 1))
    tB = (dB + x_2 * d_2) % SM2_N
    # 验证是否满足椭圆曲线方程

    x1 = P_1.x()
    x_1 = 2 ** w + (x1 & (2 ** w - 1))

    V = (h * tB) * (PA + x_1 * P_1)
    xv, yv = V.x(), V.y()
    z = str(hex(xv))[2:] + str(hex(yv))[2:] + ZA + ZB
    K_B = sm3.sm3_kdf(z.encode(), 16)
    # SB 可选就不生成了，少掉两根头发
    serial_P_2 = pickle.dumps(P_2)
    soc.send(serial_P_2)
    print('协商结果：',K_B)
    return K_B

def send_data(data, sk, soc):
    print('Begin to send data')
    cipher = Fernet(sk)
    en_data = cipher.encrypt(data.encode())
    print(en_data)
    soc.send(en_data)
def receive_data(sk, soc):
    print('Begin to receive data')
    cipher = Fernet(sk)
    en_data = soc.recv(1024)
    de_data = cipher.decrypt(en_data)
    #print(de_data)
    return de_data


IDB = str(hex(random.randint(2**64,2**65)))
b = socket.socket()
host = socket.gethostname()
port = 9966
b.connect((host, port))

IDA = b.recv(1024).decode()
b.send(IDB.encode())

dB, PB = SM2_Key_Generate()
print('生成私钥：', dB)
print('生成公钥：', PB)
PA = pk_get(b, PB)

ZA = Z_get(IDA, PA)
ZB = Z_get(IDB, PB)
KB = 0
session = 0


while True:
    op = input('请输入你要执行的操作：')
    if op == '0':
        print('Operation is 0')
        b.send(op.encode())
        break
    elif op == '1':
        print('Operation is 1')
        KB = key_exchange(b)
        C_1 = b.recv(1024)
        C_1 = pickle.loads(C_1)
        print('receive C_1:',C_1)
        C_2 = int(b.recv(160).decode())
        print('receive C_2:',C_2)
        #C_3 = int(b.recv(1024).decode())
        #print('receive C_3:',C_3)
        KA = decrypt(C_1,C_2,0,dB).decode()
        if KA == KB:
            print("OK")
            b.send('1'.encode())
            session = base64.b64encode(KB.encode())



    elif op == '2':
        print('Operation is 2')
        b.send('2'.encode())
        data = receive_data(session,b)
        print('收到数据：',data.decode())

    elif op == '3':
        print('Operation is 3')
        b.send('3'.encode())
        data = input('请输入要发送的数据：')
        send_data(data, session, b)


b.close()
