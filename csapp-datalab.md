---
title: csapp_datalab
date: 2021-04-03 00:02:14
tags:
---

csapp_datalab

my first week challenge

## 1.bitxor

构造异或门,我们要手动构造一个|，|直白的说就是有1则1，

题目只能用取反和与，首先对两个数字分别取反（不要加1得原值）

不加1，就算输入两个0，取反后还是非0，接着取与再取反又回到了0

全0为0，如果输入一个1一个0，1取反得到-2，0取反得到-1，取与返回-2再取反得到1so，|=~(~x&~y))

然后再&上(~(x&y))

```c
//1
/* 

 * bitXor - x^y using only ~ and & 
 * Example: bitXor(4, 5) = 1
 * Legal ops: ~ &
 * Max ops: 14
 * Rating: 1
    */
   int bitXor(int x, int y) {
     return (~(~x&~y))&(~(x&y));
   }
```

## 2.tmin

最小值随便一个数非0左移动31位得到，c中最大值为0x7fffffff

二进制全1为0xffffffff

```c
/* 
 * tmin - return minimum two's complement integer 
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 4
 *   Rating: 1
 */
int tmin(void) {

  return 0x1<<31;

}
```

## 3.isTmax

解析看注释

```c
//2
/*
 * isTmax - returns 1 if x is the maximum, two's complement number,
 *     and 0 otherwise 
 *   Legal ops: ! ~ & ^ | +
 *   Max ops: 10
 *   Rating: 1
 */
int isTmax(int x) 
{
  int i=x+1;
  x=x+i;
  x=~x;
  i=!i;
  x=x+i;
  return !x;/*假设我们此时输入最大值，补码最大值0x7fffffff+1得到补码最小值,最大加最小得到-1，接着取反得0，对i取非得到0，相加得到0，结果取非得到1*/
}
```

## 4.allOddBits

```c
/* 
 * allOddBits - return 1 if all odd-numbered bits in word set to 1
 *   where bits are numbered from 0 (least significant) to 31 (most significant)
 *   Examples allOddBits(0xFFFFFFFD) = 0, allOddBits(0xAAAAAAAA) = 1
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 2
 */
int allOddBits(int x) {
	int a=0xaaaaaaaa;
  return !((a&x)^a);/*奇数位置全一的只有0xaaaaaaaa,直接把输入值和它先进行&判断排除0xffffffff最后在进行异或判断*/
}
```

## 5.negate

直接利用取反+1得到一个数的负数

```c
* 
 * negate - return -x 
 *   Example: negate(1) = -1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 5
 *   Rating: 2
 */
int negate(int x) {

  return ~x+1;
}
```

## 6.isAsciiDigit

解析见注释

```C
//3
/* 
 * isAsciiDigit - return 1 if 0x30 <= x <= 0x39 (ASCII codes for characters '0' to '9')
 *   Example: isAsciiDigit(0x35) = 1.
 *            isAsciiDigit(0x3a) = 0.
 *            isAsciiDigit(0x05) = 0.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 15
 *   Rating: 3
 */
int isAsciiDigit(int x) {
	int min=0x2f+(~x+1);
	int max=0x39+(~x+1);
	min=!!(min>>31);
	max=!(max>>31);
  return min&max;//利用符号位判断，若在min=-1，max=0然后进行对min的二次取非得到1，max取非得到1，二者取&；大于9的min=-1，max=-1运算后得0，小于0的min=0，max=0运算还是0
}
```

**7.conditional**



```c
/* 
 * conditional - same as x ? y : z 
 *   Example: conditional(2,4,5) = 4
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 16
 *   Rating: 3
 */
int conditional(int x, int y, int z) {	
	 x=~(!!x)+1;
  return (x&y)|(~x&z);//三目运算符构造，输入0取双非，得0,取反+1还是0，0&y得到0，~0&z得到z；输入非0，取双非得1，取反加一得-1，~-1&z=0，-1&y=y
}
```

## 7.conditional

解析见注释

```C
/* 
 * conditional - same as x ? y : z 
 *   Example: conditional(2,4,5) = 4
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 16
 *   Rating: 3
 */
int conditional(int x, int y, int z) {	
	 x=~(!!x)+1;
  return (x&y)|(~x&z);//三目运算符构造，输入0取双非，得0,取反+1还是0，0&y得到0，~0&z得到z；输入非0，取双非得1，取反加一得-1，~-1&z=0，-1&y=y
}
```

## 8.isLessOrEqual

```C
/* 
 * isLessOrEqual - if x <= y  then return 1, else return 0 
 *   Example: isLessOrEqual(4,5) = 1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 24
 *   Rating: 3
 */
int isLessOrEqual(int x, int y) {
	int a=x+(1+~y);
	int b=(a>>31);
	int c=(x>>31);
	int d=(y>>31);
	return (!!b & !(c ^ d)) /*x<y*/| ((c ^ 0x0) & !(d ^0x0)) |  !(x^y)/*x=y*/ & !(!(y << 1) & (y ^0x0));
	//判断x<=y true rt1 false rt2 依然利用符号位，但是需要考虑四种情况 x-y<0同号,x=y,x<0 y>0异号,x=最小值
}
```

## 9.logicalNeg

解析见注释

```C
//4
/* 
 * logicalNeg - implement the ! operator, using all of 
 *              the legal operators except !
 *   Examples: logicalNeg(3) = 0, logicalNeg(0) = 1
 *   Legal ops: ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 4 
 */
int logicalNeg(int x) {
	 x|=(x<<16);
	 x|=x<<8;
	 x|=x<<4;
	 x|=x<<2;
	 x|=x<<1;
	 return((x>>31)+1);//构造非门,只要不是全0的0输入，有1就是1，取1的符号位+1

}
```

## 得分情况

1-9全满分

余下四题能力有限无法解决0分

共计20分