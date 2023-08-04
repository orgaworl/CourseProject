import hashlib
import time

class Node:
    def __init__(self):
        self.data = ""
        self.hash = []
        self.left = None
        self.right = None
        self.parent = None
        self.next = None

def calculateHash(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.digest()

def buildMerkleTree(data):
    nodes = []

    prevNode = None
    for d in data:
        node = Node()
        node.data = d
        node.hash = calculateHash(d)
        node.left = None
        node.right = None
        node.parent = None
        node.next = None

        if prevNode is not None:
            prevNode.next = node

        nodes.append(node)
        prevNode = node

    while len(nodes) > 1:
        newNodes = []
        for i in range(0, len(nodes), 2):
            newNode = Node()
            newNode.left = nodes[i]
            newNode.left.parent = newNode

            if i + 1 < len(nodes):
                newNode.right = nodes[i + 1]
                newNode.right.parent = newNode
                concatHash = newNode.left.hash + newNode.right.hash
                newNode.hash = calculateHash(str(concatHash))
            else:
                newNode.hash = nodes[i].hash

            newNodes.append(newNode)
        nodes = newNodes

    nodes[0].parent = None
    return nodes[0]

def printMerkleTree(root, level=0):
    if root is None:
        return

    for i in range(level):
        print("  ", end="")

    print("+--", end="")
    for c in root.hash:
        print(format(c, '02x'), end="")
    print(" (" + root.data + ")")

    printMerkleTree(root.left, level + 1)
    printMerkleTree(root.right, level + 1)

def generatePath(root, hash):
    node = root
    while node.left:
        node = node.left

    while node.hash != hash:
        node = node.next
        if not node:
            return -1
    
    path = []
    while node.parent:
        tmp = node
        node = node.parent
        if node.left.hash != tmp.hash:
            path.append(node.left.hash)
        else:
            path.append(node.right.hash)
    
    return path

def verify(root, hash, path):
    size = len(path)
    tmp = hash

    for i in range(size):
        concatHash = tmp + path[i]
        tmp = calculateHash(str(concatHash))

    if tmp == root.hash:
        print("verify success!")
    else:
        print("verify fail!")




data = [str(i) for i in range(10)]

start = time.time()

root = buildMerkleTree(data)

end = time.time()
duration = (end - start) * 1000
print("Execution time:", duration, "milliseconds")

printMerkleTree(root)

h = calculateHash(str(0))

print(''.join('{:02x}'.format(c) for c in h))

path = generatePath(root, h)

for i in path:
    print(''.join('{:02x}'.format(c) for c in i))

t0 = time.time()
verify(root, h, path)
t1 = time.time()

