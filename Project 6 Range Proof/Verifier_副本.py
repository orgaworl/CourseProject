import hashlib
import random
import SM2Sign

import socket
import pickle

def Verifier(p_1,sigc,pk):
    d_1 = 2100 - 2000
    c_ = hashlib.sha256(p_1.encode())
    for i in range(d_1-1):
        c_ = hashlib.sha256(c_.hexdigest().encode())
    #c_ =( pow(p_0,d_1,2**1024)*p_1) % (2**1024)
    #print(c_)
    sigc_ = SM2Sign.sm2_ver(c_.hexdigest(),sigc[0],sigc[1],pk)
    print(sigc_)


s = socket.socket()
host = socket.gethostname()
port = 8888
s.connect((host, port))
pk = 0
sig = 0
id = 'Verifier'
hash = 0
while 1:
    ov = input('请输入你下一步的操作')
    if ov == '0':
        print('连接结束')
        break
    if ov == '1':

        print('请求当前验证公钥和签名')
        seq = (id + ov)
        print(seq)
        s.send(seq.encode())
        pk = s.recv(363)
        pk = pickle.loads(pk)
        print('收到公钥为：', pk)

        seq = s.recv(170).decode()
        leng = int(seq[:2])
        sig = [int(seq[2:2 + leng]), int(seq[2 + leng:])]
        print('收到签名为：',sig)
    if ov =='2':
        print('请求hash')
        seq = (id + ov)
        print(seq)
        s.send(seq.encode())
        hash_seq = s.recv(1024).decode()
        print(hash_seq)
        hash = hash_seq
        print('收到Hash：', hash)

    if ov =='3':
        print('验证计算')
        Verifier(hash,sig,pk)
