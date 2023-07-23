import hashlib
import random
import SM2Sign
import time
import socket
import pickle


def Prover(born, s, sigc):
    d_0 = 2000 - born
    S = int(s, 16)
    #p_0 = pow(int(hashlib.sha256(s.encode()).hexdigest(), 16), 1, 2 ** 1024)
    p_1 = hashlib.sha256(s.encode())

    for i in range(d_0-1):
        p_1 = hashlib.sha256(p_1.hexdigest().encode())
    #p_1 = pow(p_0, d_0, 2 ** 1024)
    return  p_1


s = socket.socket()
host = socket.gethostname()
port = 8888
s.connect((host, port))
# print(s.recv(10).decode())
pk = 0
sig = 0
secret = 0
id = 'Prover'
born = 0
p_0, p_1 = 0, 0
# s.send(id.encode())
# s.send(str(born).encode())
while 1:
    op = input('请输入你下一步的操作')
    if op == '0':
        print('连接结束')
        break
    if op == '1':
        born = input('申请验证，请输入你的出生年份')
        seq = (id + op + born)
        print(seq)
        s.send(seq.encode())
        # sigc = s.recv(1024)
        # print(sigc)

        secret = s.recv(1024).decode()
        print('收到秘密为：', secret)
        pk = s.recv(363)
        # print(pk)
        pk = pickle.loads(pk)
        print('收到公钥为：', pk)

        seq = s.recv(160).decode()
        # print(seq)
        leng = int(seq[:2])
        # print(len)
        sig = [int(seq[2:2 + leng]), int(seq[2 + leng:])]
        print('收到签名为：', sig)

    if op == '2':
        seq = (id + op)
        print(seq)
        s.send(seq.encode())
        p_1 = Prover(int(born), secret, sig)
        print('计算Hash：')
        print(p_1.hexdigest())
        hash_seq = p_1.hexdigest()
        print(hash_seq)
        s.send(hash_seq.encode())

s.close()
