# 伪造签名

## ECDSA签名

### 算法

 $ Key Gen:$

- $  P=d G$, n  is order of group $<G>$

$ \operatorname{Sign}(m) $

- $ k \leftarrow Z_{n}^{* }, R=k G $
- $ r=R_{x} \bmod n, r \neq 0 $
- $ e=\operatorname{hash}(m) $
- $ s=k^{-1}(e+d r) \bmod n $
- Signature is  (r, s) 

Verify  (r, s) of  m  with  P 

- $ e=\operatorname{hash}(m) $

- $ w=s^{-1} \bmod n $

- $ \left(r^{\prime}, s^{\prime}\right)=e \cdot w G+r \cdot w P $

- Check if  $r^{\prime}==r $

### 正确性

  $ e s^{-1} G+r s^{-1} P\\
  =s^{-1}(e G+r P)\\
  =k(e+d r)^{-1}(e+d r) G\\
  =k G\\
  =R $



## 身份伪造

#### 算法

已知G和特定用户的公钥P, 可伪造针对私钥$d$的$e^{'}$的签名$\sigma^{'}=(r^{'},s^{'})$

- 选择$u,v\in \mathbb{F}_n^*$

- 计算$R^{'}=(x^{'},y^{'})=uG+vP$

- 选择$r^{'}=x^{'}\ mod\ n$

- 可计算伪造签名$\sigma^{'}=(r^{'},s^{'})$
  
  - $e^{'}=r^{'}uv^{-1}\ mod\ n$
  - $s^{'}=r^{'}v^{-1}\ mod\ n$

## 

## 实现

### 椭圆曲线选择

Bitcoin选择**secp256k1**为ECDSA算法椭圆曲线.

$y^2=x^3+ax^2+b\ over \ F_p$
    $p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F$
    $a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000$
    $b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007$
    $n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141$
    $h = 1$
    $x_G = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798$
    $y_G = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8$
    $G = 04\_79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F817\\\ \ \ \ \ \ \ \ \ \ 98\_483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8  $

即在有限域$F_p$上的椭圆曲线 y² = x³ + 7 



### 结果展示

本文在椭圆曲线类中实现了椭圆曲线上点加法和常数乘法. 

在此基础上, 本文实现了ECDSA的全过程并进行测试验证了其正确性.

<img src=".\\picture\\testECDSA.png" title="" alt="验证" style="zoom:67%;">



随后,本文实现了ECDSA的身份伪造攻击, 可在已知公钥G和P情况下伪造e=Hash(m)的签名$\sigma^{'}=(r^{'},s^{'})$.

<img src=".\\picture\\testForge.png" title="" alt="forge" style="zoom:67%;">

最后, 我们只需获取中本聪的公钥即可伪造其身份.

查看区块链上最早的区块,能找到由satoshi发布的
