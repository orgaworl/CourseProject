### Birthday Attack Of SM3 Hash Function

#### Birthday attack

随机产生t个不同的消息,分别计算其对应的Hash值,若找到两个Hash值相同的消息,则找到一组碰撞.  
实质为穷举可能结果的暴力破解.  
成功概率超过$\frac{1}{2}$的时间复杂度为$O(2^{\frac{n}{2}})$, 其中n为散列值的二进制长度.



为了抵抗生日攻击，通常建议消息摘要的长度至少应取为128比特，此时生日攻击需要约$2^{64}$次Hash.   SM3 的Hash值为256比特, 基本可以抵抗生日攻击.

### Reduced SM3

为了令针对SM3的生日攻击在计算上可行, 我们需要缩短SM3输出Hash值的bit长度.   
本文选择将原本256bit长的Hash值划分为4组64bit并进行异或, 得到64bit的Hash值.



### Birthday Attack of Reduced SM3








