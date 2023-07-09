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

Holds  for correct sig since

- $ e s^{-1} G+r s^{-1} P\\
  =s^{-1}(e G+r P)\\
  =k(e+d r)^{-1}(e+d r) G\\
  =k G\\
  =R $
  
  

## 身份伪造

#### 算法

已知公钥G、P, 可伪造针对私钥$d$的$e^{'}$的签名$\sigma^{'}=(r^{'},s^{'})$

- 选择$u,v\in \mathbb{F}_n^*$

- 计算$R^{'}=(x^{'},y^{'})=uG+vP$

- 选择$r^{'}=x^{'}\ mod\ n$

- 可计算伪造签名$\sigma^{'}=(r^{'},s^{'})$
  
  - $e^{'}=r^{'}uv^{-1}\ mod\ n$
  - $s^{'}=r^{'}v^{-1}\ mod\ n$

### 实现

secp256k1椭圆曲线

$y^2=x^3+ax^2+b\ over \ F_p$
    $p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F$
    $a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000$
    $b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007$
    $x_G = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798$
    $y_G = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8$
    $n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141$
    $h = 1$
    $G = 04 \\79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 \\483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8$

即曲线 y² = x³ + 7 在有限域$F_p$
