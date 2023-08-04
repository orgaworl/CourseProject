import hashlib
import random
import SM2Sign
import socket
import pickle
import threading


def Trusted_Issuer(born):
    sk = str(hex(random.randint(2 ** 256, 2 ** 257)))
    sk, pk = SM2Sign.SM2_Key_Generate()
    seed = random.randint(2 ** 128, 2 ** 129)
    seed = str(seed).encode()
    s = hashlib.sha512(seed)
    k = 2100 - born
    c = s
    for i in range(k):
        c = hashlib.sha256(c.hexdigest().encode())
    #c = pow(int(hashlib.sha256(s.hexdigest().encode()).hexdigest(), 16), k, 2 ** 1024)
    sigc = SM2Sign.sm2_sig(c.hexdigest(), sk)
    return s, sigc, pk


def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            # 处理接收到的数据
            judge(data, client_socket)
        except:
            break

    # 关闭客户端连接
    client_socket.close()

def judge(message,socket):

    global pk,s,sigc,hash,hash_seq
    print('消息：',message.decode())
    P = message.decode().find('Prover')
    V = message.decode().find('Verifier')

    if P != -1:
        op = ''
        op = message.decode()[P+6]
        print('Prover执行的操作为：',op)
        if op == '1':
            born = int(message.decode()[P+7:])
            s , sigc, pk = Trusted_Issuer(born)

            print('生成秘密：',s.hexdigest())
            clients[0].send(s.hexdigest().encode())
            print('生成公钥：',pk)

            serialized_point = pickle.dumps(pk)
            clients[0].send(serialized_point)
            print('生成签名：',sigc)

            seq = str(sigc[0]) + str(sigc[1])
            seq = str(len(str(sigc[0]))) + seq
            print(seq)
            clients[0].send(seq.encode())
        if op == '2':
            print('接收hash')
            hash_seq = clients[0].recv(1024).decode()
            print(hash_seq)
            hash = int(hash_seq,16)
            print('收到Hash：',hash)

    elif V!= -1:
        ov = ''
        ov = message.decode()[V+8]
        print('Verifier执行的操作为：',ov)
        if ov=='1':
            print('Verifier请求公钥签名')
            serialized_point = pickle.dumps(pk)
            clients[1].send(serialized_point)

            seq = str(sigc[0]) + str(sigc[1])
            seq = str(len(str(sigc[0]))) + seq
            print(seq)
            clients[1].send(seq.encode())
        if ov=='2':
            print('Verifier请求Hash')
            clients[1].send(hash_seq.encode())

    return


# 创建TCP套接字
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 绑定服务器的地址和端口
server_address = ('', 8888)
server_socket.bind(server_address)

# 监听连接
server_socket.listen(2)
print('服务器启动，等待客户端连接...')
clients = []
host = socket.gethostname()
while True:
    try:
        # 接受客户端连接
        client_socket, client_address = server_socket.accept()
        print(f'客户端 {client_address} 连接成功。')
        # 将客户端加入列表
        clients.append(client_socket)

        # 启动线程处理客户端连接
        t = threading.Thread(target=handle_client, args=(client_socket,))
        t.start()
    except KeyboardInterrupt:
        break

# 关闭服务器套接字
server_socket.close()
