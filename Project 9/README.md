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

****

# SM4

### 介绍

SM4是由国家密码管理局于2012年3月21日发布的分组密码, 对标AES分组密码。分组长度与密钥长度均为128bit（即16Byte）

### 算法

SM4分组长度为128字节, 明文经过32次轮函数和1次反序变换得到密文.

$\textbf{轮函数} F(X_i^0,X_{i}^1,X_{i}^2,X_{i}^3,{rk}_i) $

$$
F:\left\{
\begin{aligned}
  &X_{i+1}^0=X_{i}^1\\
  &X_{i+1}^1=X_{i}^2\\
  &X_{i+1}^2=X_{i}^3\\
  &X_{i+1}^3=X_i^0\oplus L\circ S(X_{i}^1 \oplus X_{i}^2 \oplus X_{i}^3 \oplus{rk}_i)\\
\end{aligned}
\right.

$$

$\textbf{反序变化R}:$

$$
R(X_{32}^0,X_{32}^1,X_{32}^2,X_{32}^3)=(X_{32}^3,X_{32}^2,X_{32}^1,X_{32}^0)

$$

其中:
    $\textbf{线性变换L:}$

$$
L(B) = B \oplus (B<<<2)\oplus (B<<<10) \oplus(B<<<18)\oplus(B<<<24). 
$$

    $\textbf{非线性变化S:}$

$$
S_{s}(x)=A_{s} \cdot I_{s}\left(A_{s} x+C_{s}\right)+C_{s}
$$







### 效率测试与对比

测量SM4在不同实现方式下的加密数据的时间开销, 据此计算出其吞吐率.

本文对比了C语言实现与openssl、gmssl等库实现, 可观察到C实现的吞吐量介于openssl和gmssl之间,与openssl还有较大的差距.



<img title="时间开销" src=".\\pic\\timecost.png" alt="时间开销" style="zoom:25%;">

<img title="吞吐量" src=".\\pic\\throughput.png" alt="效率对比" style="zoom:25%;" data-align="inline">

**** 

# SM4_AESNI

## SIMD

SIMD(**Single Instruction Multiple Data**)即单指令流多数据流，是一种采用一个控制器来控制多个处理器，同时对一组数据中的每一个分别执行相同的操作从而实现空间上的并行性的技术。SIMD使得一个指令能够同时处理多个数据,大大提高了程序运行速度.



自1997 年Intel 推出了第一个 SIMD 指令集 MMX 以来，二十多年间，SIMD指令集不断推陈出新，取得极大成功。

英特尔指令集扩展是可在多个数据对象上执行相同操作时可提高性能的附加指令。

指令集扩展可包括：

* 单指令多数据 （SIMD）
* 英特尔 Streaming SIMD 扩展（英特尔 SSE、英特尔 SSE2、英特尔 SSE3 和英特尔 SSE4）
* 英特尔 Advanced Vector Extensions（英特尔 AVX、英特尔 AVX2和英特尔 AVX-512）
  
  

作为国际上最常用的分组加密算法, AES算法作为指令集被集成进intel CPU中. 该指令集从硬件上对AES算法进行了优化, 使用该指令集能极大提升运算效率.



我国提出的SM4分组加密可利用intel AES指令集进行加速.



****

## SM4_AESNI

AES的S盒是定义在  $G F\left(2^{8}\right)$  (不可约多项式  $x^{8}+x^{4}+x^{3}+x+1$  )，其表达式为  $S(x)=A x^{-1}+c$  ，具体如下:

$$
\left(\begin{array}{l}
s_{7} \\
s_{6} \\
s_{5} \\
s_{4} \\
s_{3} \\
s_{2} \\
s_{1} \\
s_{0}
\end{array}\right)=\left(\begin{array}{llllllll}
1 & 1 & 1 & 1 & 1 & 0 & 0 & 0 \\
0 & 1 & 1 & 1 & 1 & 1 & 0 & 0 \\
0 & 0 & 1 & 1 & 1 & 1 & 1 & 0 \\
0 & 0 & 0 & 1 & 1 & 1 & 1 & 1 \\
1 & 0 & 0 & 0 & 1 & 1 & 1 & 1 \\
1 & 1 & 0 & 0 & 0 & 1 & 1 & 1 \\
1 & 1 & 1 & 0 & 0 & 0 & 1 & 1 \\
1 & 1 & 1 & 1 & 0 & 0 & 0 & 1
\end{array}\right) \cdot\left(\begin{array}{l}
x_{7} \\
x_{6} \\
x_{5} \\
x_{4} \\
x_{3} \\
x_{2} \\
x_{1} \\
x_{0}
\end{array}\right)+\left(\begin{array}{l}
0 \\
1 \\
1 \\
0 \\
0 \\
0 \\
1 \\
1
\end{array}\right)

$$

SM4 S盒和AES不同,定义在$GF(2^8)$, 使用不可约多项式为$x^3+x^7+x^6+x^5+x^4+x^2+1$, 表达式为 $S(x)=A(Ax+c)^{-1}+c$ , 其中:

$$
\begin{aligned}\\A&=\begin{pmatrix}1&1&0&1&0&0&1&1\\1&1&1&0&1&0&0&1\\1&1&1&1&0&1&0\\0&1&1&1&0&1&0\\0&0&1&1&1&0&1\\0&0&0&1&1&1&0\\1&0&0&1&1&1&1\\0&0&0&1&1&1&1\\1&0&1&0&0&1&1\end{pmatrix},c=\begin{pmatrix}1\\1\\0\\1\\1\\1\\0\\1\\1\end{pmatrix}\end{aligned}
$$

在复合域$GF(2^8)$上，AES 和 SM4 的求逆运算过程相同，而除此之外，其他操作都是线性的仿射变换,因此可通过 AES 的 S 盒计算 SM4 的 S 盒输出,即

$$
\mathrm{S}_{\mathrm{sm} 4}(\mathrm{x})=\mathrm{L}\left(\mathrm{S}_{\mathrm{aes}}\left(\mathrm{Mx}+\mathrm{C}_{1}\right)\right)+\mathrm{C}_{2}  ，

$$

假设复合域求逆运算为 $ \mathrm{f} $ ，则

$$
\begin{aligned}
&S_{a e s}(x)=A_{\text {aes }} X_{\text {aes }} f\left(X_{\text {aes }}^{-1} x\right)+0x63 \\
&\Rightarrow f\left(X_{\text {aes }}^{-1} x\right)=X_{\text {aes }}^{-1} A_{\text {aes }}^{-1}\left(S_{\text {aes}}(x)+0x63\right) \\
&\Rightarrow f(x)=X_{\text {aes }}^{-1} A_{\text {aes }}^{-1}\left(S_{\text {aes }}\left(X_{\text {aes }} x\right)+0x 63\right)\\
\end{aligned}

$$

由此得出：

$$
\begin{array}{l}
\mathrm{S}_{\mathrm{sm} 4}(\mathrm{x})=\mathrm{A}_{\mathrm{sm} 4} \mathrm{X}_{\mathrm{sm} 4} \mathrm{f}\left(\mathrm{X}_{\mathrm{sm} 4}^{-1}\left(\mathrm{~A}_{\mathrm{sm} 4} \mathrm{X}+0 \mathrm{xd} 3\right)\right)+0 \mathrm{xd} 3 \Rightarrow \\
\mathrm{S}_{\mathrm{sm} 4}(\mathrm{x})=\mathrm{A}_{\mathrm{sm} 4} \mathrm{X}_{\mathrm{sm} 4} \mathrm{X}_{\mathrm{aes}}^{-1} \mathrm{~A}_{\mathrm{aes}}^{-1}\left(\mathrm{~S}_{\mathrm{aes}}\left(\mathrm{X}_{\mathrm{aes}}\left(\mathrm{X}_{\mathrm{sm} 4}^{-1}\left(\mathrm{~A}_{\mathrm{sm} 4} \mathrm{X}+0 \mathrm{xd} 3\right)\right)\right)+0 \mathrm{x} 63\right)+0 \mathrm{xd3}
\end{array}

$$

由此可得出，

$$
\begin{array}{l}
M=X_{\text {aes }} X_{s m 4}^{-1} A_{s m 4} \\
C_{1}=X_{\text {aes }} X_{s m 4}^{-1} 0xd3 \\
L=A_{s m 4} X_{s m 4} X_{\text {aes }}^{-1}A_{\text {aes }}^{-1} \\
C_{2}=A_{s m 4} X_{s m 4} X_{\text {aes }}^{-1} A_{\text {aes }}^{-1} 0x 63+0xd3 \\
\end{array}

$$

## 性能测试



SM4_C & SM4_AESNI & Openssl\\\

34.41751 &38.58956&103.4529\\\

## 优势对比

SM4采用常采用查表实现方法, 实现思想简单, 可移植性强,适用于多个平台。但查表方法同样存在明显缺点:1) CPU在做查表操作时, 由于SM4的表规模相对较大, 表中的数据在内存和cache之间频繁对换导致查表延时较大;2) 查表方法无法并行加/解密多组消息, 这在一定程度上制约了SM4的软件实现性能。相比于查表方法, 使用SIMD指令实现SM4时, 数据存放在SIMD寄存器中, 读取数据延时较小, 更重要的是SIMD指令在并行性方面有明显优势. 相较于一般查表实现, SIMD指令实现具有较明显的加速效果。

****
