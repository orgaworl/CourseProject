



# Schnorr数字签名

### 介绍

比特币目前使用的是ECDSA签名，每一笔输入都需要有一次签名，因此占据空间大.

而Schnorr签名占据空间小，并且支持多签名聚合，一笔交易的所有签名只需聚合为一个签名即可,大大减小了空间占用.

同时, Schnorr签名还支持多个签名的批量验证, 提高多笔交易的验证效率.

**优点:** 使用Schnorr签名，不仅可以提升比特币的验证速度，降低每个人的交易费用，还可以减少空间占用, 变相的增加了比特币的容量.

## Schnorr数字签名方案

Key Generation

- $P=d G$

Sign on given message  M 

- random $ k$ , $R=k G$ 
- $e=hash(R \| M)$ 
- $s=k+e d \bmod n $
- Signature is :  (R, s) 

Verify  (R, s)  of  M  with  P 

- Check  $s G$  vs  $R+e P$ 
- $s G=(k+e d) G=k G+e d G=R+e P$ 
  
  

## Schnorr数字签名批量验证

Schnorr数字签名可同时验证多个签名,提高验证效率.在数据吞吐量大的比特币系统中能有效提升运行效率.



- Schnorr 单签名验证: 
  
  $$
  s G=(k+e d) G=k G+e d G=R+e P 
  $$
  
  

- Schnorr 批量签名验证 :
  
  $$
  \left(\sum_{i=1}^{n} s_{i}\right) * G=\left(\sum_{i=1}^{n} R_{i}\right)+\left(\sum_{i=1}^{n} e_{i} * P_{i}\right) 
  $$
  
  但这种验证方式存在伪造攻击, 因此不使用.

- 抗伪造Schnorr批量签名验证:    随机 $a_{i} \in[0, \mathrm{p}-1]$, $\mathrm{i} \in[2, n]$ , 验证:
  
  

$$
\left(s_{1}+\sum_{\{i=2\}}^{\{n\}} a_{i} s_{i}\right) * G=\left(R_{1}+\sum_{\{i=2\}}^{n} a_{i} * R_{i}\right)+\left(e_{1} * P_{1}+\sum_{\{i=2\}}^{n}\left(e_{i} a_{i}\right) * P_{i}\right)  \ \ \ (1)
$$

## 实现及结果

### Schnorr数字签名

本文实现了基于椭圆曲线的基础Schnorr数字签名方案, 选取椭圆曲线同ECDSA为**secp256k1**.

基础实现共包含KeyGen, Sign, Verify 三部分,能代表单个用户对消息进行签名, 同时只能验证单个签名.

<img src=".\\picture\\testSchnorr.png" title="" alt="Schnorr" style="zoom:67%;">





### Schnorr数字签名批量验证

在上文基础上, 本文又实现了Schnorr数字签名的批量验证, 能够对多个用户对不同消息进行的签名一起验证, 有效提高了签名验证效率.



如下是三个用户对不同消息签名的批量验证结果.

<img src=".\\picture\\testBatchVerify.png" title="" alt="batch verify" style="zoom:67%;">


