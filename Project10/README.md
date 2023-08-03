# Deduce technique in Ethereum with ECDSA

以太坊中交易消息不包含任何 "来源" 信息。因为发起者的公钥可以直接从ECDSA签名中计算出来。而当有了公钥，便可以通过固定流程很容易地计算出地址. 该技术使得无需额外存储公钥, 减小了空间占用, 同时还保证了签名与公钥来源相同, 提升了安全性.



## ECDSA签名算法

回顾ECDSA签名算法:

 $ Key Gen:$

- $  P=d G$, n  is order of group $<G>$
- $SK=d$, $PK=P$

$ \operatorname{Sign}(m) $

- $ k \leftarrow Z_{n}^{* }, R=k G $
- $ r=R_{x} \bmod n, r \neq 0 $
- $ e=\operatorname{hash}(m)\ mod\ n$
- $ s=k^{-1}(e+d r) \bmod n $
- Signature is  (r, s) 
  
  

## 公钥推导

**算法**

已知消息$M$和其签名$(r,s)$

- 已知点$R$的横坐标 $r$,带入椭圆曲线得到方程 $y^2=r^3+7\ mod\ p$ , 即二次剩余求解问题.

- 使用Weierstrass方程计算出可能的两个纵坐标$y1,y2$.

- 因为签名中添加了$R_y$最后一字节作为区分信息, 因此可唯一确定点$R=(r, y)$.

- 计算公钥$P = r^{-1} (s\cdot R - e\cdot G)$, 其中$e=hash(M)$.

**正确性**

 $\because\ s=k^{-1}(e+d r) \bmod n $

$\therefore \ sG=k^{-1}(e+d r) G $

$\therefore dG=P=r^{-1}(skG-eG)$

$\therefore P=r^{-1}(sR-eG)$





## 实现结果

- 计算正确值并输出.

- 计算推导值并与正确值进行比较.
  
  <img src=".\\picture\\deduce.png" title="" alt="result" style="zoom:67%;">
