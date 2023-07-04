# AES

### 介绍

AES（Advanced Encryption Standard）是一种对称加密算法，也是目前最常用的加密算法之一。
AES 算法具有安全性高、加密速度快、实现简单、可靠性高等优点。

AES 算法的密钥长度有多种，可以是 128 位、192 位或 256 位，其中 128 位密钥是最常用的，不同长度的密钥加密的轮数也是不一样的.  
AES 算法的加密过程包括四个步骤：字节替换、行移位、列混淆和轮密钥加。

### 实现

#### SubBytes查找表实现

SubBytes过程中需要先在$GF(2^8)$域上求逆,再进行GF(2)上仿射变换. 为简化实现, 可提前储存好所有的输入输出结果形成$16\times 16$的固定查找表. 

SubBytes步骤中存在16个可并行的S-Box, 对每个Sbox输入8bit, 查表后输出8bit对应的运算结果.



#### MixRow域上运算实现

$$
\{02\}_{16}\times\{b_7b_6b_5b_4b_3b_2b_1b_0\}_2=
\begin{cases}
\{b_6b_5b_4b_3b_2b_1b_00\}_2\ & if\ b_7=0\\
\{b_6b_5b_4b_3b_2b_1b_00\}_2\oplus {00011011}_2 & if\ b_7=1\\
\end{cases}

$$

$$
\{03\}_{16}\times\{b_7b_6b_5b_4b_3b_2b_1b_0\}_2=\{02\}_{16}\times\{b_7b_6b_5b_4b_3b_2b_1b_0\}_2\oplus \{b_7b_6b_5b_4b_3b_2b_1b_0\}_2
$$

# SM4

### 介绍

SM4是由国家密码管理局于2012年3月21日发布的分组密码, 对标AES分组密码。分组长度与密钥长度均为128bit（即16Byte）

### 实现



### 效率测试与对比

测量SM4在不同实现方式下的加密数据的时间开销, 据此计算出其吞吐率.

本文对比了C语言实现与openssl、gmssl等库实现, 可观察到C实现的吞吐量介于openssl和gmssl之间,与openssl还有较大的差距.



<img title="时间开销" src=".\\pic\\timecost.png" alt="时间开销" style="zoom:25%;">

<img title="吞吐量" src=".\\pic\\throughput.png" alt="效率对比" style="zoom:25%;" data-align="inline">
