# Hash函数长度拓展攻击

### Hash函数介绍

Hash函数的构造方式多种多样,可以利用数学困难问题构造,可以基于分组密码构造,还可以定制构造.

定制Hash函数主流结构有MD结构、Sponge结构,

诸如MD4、MD5、SHA-1、SHA-2 和 SM3等知名Hash算法都属于MD结构.

### MD结构及其长度拓展攻击

将消息填充为固定长度L的整数倍, 将填充后消息分为多个L长序列, 按序作为压缩函数的输入之一.

<img title="" src=".\\picture\\MD.png" alt="MD结构" style="zoom:80%;">

但MD结构易受长度拓展攻击.



**长度拓展攻击**

已知 $ h=Hash(M) $和$|M|$,   
构造$z=0^d\|\ |M|\ \|x$, 其中x为任意长度消息.  
则可计算$h^{'}=f_h(x\|pad)$ 满足$h^{'}=Hash(M\|z)$  
可在不知道M的情况下计算$Hash(M\|z)$



### 针对SHA256与SM3的 长度拓展攻击

SHA256与SM3都是MD结构,并且填充方式相同, 输出Hash值长度也同为256bit, 两者主要差异仅在压缩函数上.

**填充方式**

将M填充至512bit的整数倍: 

- 首先在M后填充1bit 1

- 再填充d bit 0, 其中$d=512-64-1-|M|\ mod\ 512$

- 最后填充64bit的$|M|$

**攻击算法**

给定 $h=Hash(M)$ 和 $|M|$,

可计算出$d=512-64-1-|M| \ mod\ 512$,

构造$z=1\|0^d\| \ |M|\ \|x$,  其中$|M|$为64bit长.



计算$D=|M\|z\ |$,  $f=512-64-1-D \ mod\ 512$, 

则 $pad=1\|0^{f}\|D$.

可计算$h^{'}=f_h(x\|pad)$,  且$h^{'}=Hash(M\|z)$

**攻击实现**

- SM3
  C语言实现

- SHA256
  Python实现
  
  
  
  
  
  

[1] [Merkle-Damgaard hash函数如何构造](https://www.cnblogs.com/zhuowangy2k/p/12245508.html)