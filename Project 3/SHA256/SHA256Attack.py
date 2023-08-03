
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def LRS(x, n):
    x = (x >> n) | (x << 32 - n)
    return x

def extend(M):
    W = [0] * 64
    for t in range(0, 16):
        W[t] = M[t * 4:t * 4 + 4]
        W[t] = int(W[t].hex(), 16)
    for t in range(16, 64):
        S1 = LRS(W[t - 2], 17) ^ LRS(W[t - 2], 19) ^ (W[t - 2]>>10)
        S0 = LRS(W[t - 15], 7) ^ LRS(W[t - 15], 18) ^ (W[t - 15] >> 3)
        W[t] = (S1+W[t-7]+S0+W[t-16]) & 0xFFFFFFFF
    return W

def compress(link,W):
    a = link[0]
    b = link[1]
    c = link[2]
    d = link[3]
    e = link[4]
    f = link[5]
    g = link[6]
    h = link[7]
    for t in range(0, 64):
        S1 = LRS(e, 6) ^ LRS(e, 11) ^ LRS(e, 25)
        Ch = (e & f) ^ ((~e) & g)
        S0 = LRS(a, 2) ^ LRS(a, 13) ^ LRS(a, 22)
        Maj = (a & b) ^ (a & c) ^ (b & c)
        T1 = h + S1 + Ch + K[t] + W[t]
        T2 = S0 + Maj
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    link[0] = a + link[0] & 0xFFFFFFFF
    link[1] = b + link[1] & 0xFFFFFFFF
    link[2] = c + link[2] & 0xFFFFFFFF
    link[3] = d + link[3] & 0xFFFFFFFF
    link[4] = e + link[4] & 0xFFFFFFFF
    link[5] = f + link[5] & 0xFFFFFFFF
    link[6] = g + link[6] & 0xFFFFFFFF
    link[7] = h + link[7] & 0xFFFFFFFF
    return link
    

def SHA256(mes):
    mesB = mes.encode('utf8')
    print("原消息  : ",mes)
    print("原消息值: ",mesB.hex())
    M = mesB + b'\x80' + b'\x00'*((64-len(mesB)-1-8)) + (len(mesB)*8).to_bytes(8, byteorder='big')
    link = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19]
    for i in range(len(M)//64):
        W=extend(M[64*i:64*(i+1)])
        link=compress(link,W)

    sha256 = ''
    for sha in link:
        sha256 = sha256 + sha.to_bytes(4, byteorder='big').hex()
    print("散列值  : ",sha256)
    return link


def AttackSHA256(hashVal,mesLen,x):
    blockNum=len(x)//64+1
    xLen=len(x)
    L=64*(mesLen//64+1)+xLen
    end=(L*8).to_bytes(8, byteorder='big')
    xB=x.encode('utf8')
    print("追加消息: ",x)
    print("追加值  : ",xB.hex())
    mes=xB+b'\x80' +b'\x00'*((64-L-1-8)%64)+ end
    link=hashVal
    for i in range(blockNum):
        W=extend(mes[64*i:64*(i+1)])
        link=compress(link,W)
    sha256 = ''
    for sha in link:
        sha256 = sha256 + sha.to_bytes(4, byteorder='big').hex()
    print("新散列值: ",sha256)
    return link
    
    
print()
hashVal=SHA256("Hello")
AttackSHA256(hashVal,5,", Bob!")
print()