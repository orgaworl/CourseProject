# Rho method

## 介绍

Rho method是一种用来高效寻找Hash函数碰撞的方法.  
该方法基于生日攻击原理, 有效提高了发现碰撞的概率.   
通过只保存区分点(distinguished point, DP), 使得相对生日攻击占用了更少的内存.  
同时,该方法还可通过并行有效提高碰撞查找效率.



## 方法

1. 选择$SP=x_0$ 作为起点, 计算点序列 $x_0,x_1,x_2, ...$ ,  
   其中  $x_i=f(x_{i-1})\ for\ i=1,2, ...$

2. 当发现第一个拥有k个前导零的点$x_d$时停止计算, 令$DP=x_d$ .

3. 保存$(DP,SP,d)$作为该序列 $x_0,x_1,x_2, ...,x_{d-1},x_d$的记录. 

4. 不断选择新SP, 如上计算对应DP并保存.

5. 当存在两序列具有相同DP时可计算碰撞: 
   5.1. 首先从更长序列的SP的开始不断计算下一点，直到该点到DP的距离和短序列SP到DP的距离相同.
   5.2. 随后两序列同时计算下一点，直到发现相同点, 此时即找到一组碰撞.
   
   <img title="计算碰撞[1]" src=".\\picture\\trail.gif" alt="result" data-align="inline" style="zoom:67%;">

## 实现

**简化SM3**

简化SM3函数, 将原散列值均分为多段, 计算所有段的异或值作为简化散列值.

**Rho method**

本文选择使用Python实现Rho method, 使用到如下库:

```python
from gmssl import sm3
import binascii
import random 
```

- 选择前导零有4个的点作为DP
- 测试了多种散列值长度下寻找碰撞的可行性.
- 

### 结果展示

| 散列长度(bit) | 散列值      | 碰撞                    |
| --------- | -------- | --------------------- |
| 8         | 95       | (7f , 3f)             |
| 16        | bc84     | (f714 , 5900)         |
| 32        | 01eb26ae | (7d05faf1 , 684d588f) |
| 64        | 耗时过长     | 耗时过长                  |

![result](.\\picture\\result01.png)

结果分析

RhoMethod方法寻找碰撞具有不确定的耗时.





## 参考文献

[1] B. Weber and X. Zhang, "Parallel hash collision search by Rho method with distinguished points," 2018 IEEE Long Island Systems, Applications and Technology Conference (LISAT), Farmingdale, NY, USA, 2018, pp. 1-7, doi: 10.1109/LISAT.2018.8378028.
