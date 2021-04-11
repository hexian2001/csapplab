---
title: csapp_bomb_lab
date: 2021-04-11 12:01:24
tags:
---

my second week Challange

bomb lab

<!--more-->

根据readme里面要求，我们需要对这个二进制文件的汇编语言进行解读

按要求输入内容通关



## 1

如图所示，把字符串给esi寄存器然后调用一个函数

![1.png](https://i.loli.net/2021/04/11/EaqI5sSvepP1rm9.png)

如图箭头所指，调用字符串长度计算函数，然后下面cmp命令去比较

比对成功就通关

![2.png](https://i.loli.net/2021/04/11/YmLPuxb1fhjIdDz.png)

## 2

如图调用一个函数输入6个数字

![3.png](https://i.loli.net/2021/04/11/idZyJHhNTBlEc8z.png)

输入函数如图

![4.png](https://i.loli.net/2021/04/11/MutCdbHnJVOUocK.png)

接着看下面的命令，在400f17这里rbx-4就是指向rsp

后面的add相当于乘2，然后下面比对第二个数是不是第一个的2倍是就执行400f25



在看下面400f25，又去执行400f17，循环往复直到6个数字比对完

![5.png](https://i.loli.net/2021/04/11/CMlLpvOGa8eRDtF.png)

so我们可以输入

1 2 4 8 16 32



## 3

按图从上到下，我们输入两个数字，一个用来选选项，一个用来比对

这里有7个case加一个default case 

我这里拿case 0举例

我们输入0 207

先会进行选项输入的比对，看我们输入的是什么，然后会把选项里面的内容

比如case 0里面是207 那就会把这个数值给到eax

接着会拿我们的输入值去和eax里面数字比对

比对成功就ret返回否则调用炸弹函数

![6.png](https://i.loli.net/2021/04/11/hyq9Yviup5FUbrB.png)

![7.png](https://i.loli.net/2021/04/11/P4n7rfeTw31lAEG.png)

![8.png](https://i.loli.net/2021/04/11/RnKBO87WCzPyYlo.png)



## 4

 按次序输入参数1和2

结合图1我们可以发现参数2必须为0不然就会boom

那么至于参数1我们可以去康康func4，图2

把func4变成python

我们可以得知满足逻辑的参数1有0 1 3 7

so 我们输入 0 0就可以了

```python
# -*- coding:utf-8 -*-

edx = 14
esi = 0
edi = 8  # param 1
eax = 0
ecx = 0


def func4():
    global edx, esi, edi, eax, ecx
    eax = edx
    eax = eax - esi
    ecx = eax
    ecx = ecx >> 31
    eax = eax + ecx
    eax = eax >> 1
    ecx = eax + esi 

    if ecx <= edi:
        eax = 0
        if ecx >= edi:  # ecx == edi
            return eax
        else:           # ecx < edi
            esi = ecx + 1
            func4()
            eax = eax*2 + 1
            return eax
    else:               # ecx > edi
        edx = ecx - 1
        func4()
        eax = eax*2
        return eax


if __name__ == "__main__":
    # for edi in range(7, 15):
    edi = 7
    res = func4()
    print(edi, ": ", res)
```

![9.png](https://i.loli.net/2021/04/11/HFhMqj2JBG3yfoY.png)

![10.png](https://i.loli.net/2021/04/11/NsS5ochVZmIx1Up.png)

 

## 5

如图一我们只能输入6个字符的字符串否则boom

用gdb调试输入abcdef 结果显示我们输入的不是这个

证明中间存在转化过程

再结合图一输入必须是flyers才可以通过

我们看图三这个是一个循环的函数

我们点开数组看到

so我们要看rdx的值哪里来的就可以自由的得到我们要的目标字符串了

通过gdb对地址0x4024b0内容查看找到字符串

```
"maduiersnfotvbylSo you think you can stop the bomb with ctrl-c, do you?"
```

地址0x4024b0 发现是一个字符串, 通过rdx的低四位值来对字符串中的数据进行读取, 最后存放到edx寄存器中

然后再保存到[rsp+rax*1+0x10], 因为rax是从0–5, 因此存放地址就是[rsp+0x10]–[rsp+0x15]

地址0x4010ae处: 退出循环以后,将[rsp+0x16] 置为0, 作为循环生成后字符串的结束标志:’\0’.

然后地址0x4010b3处将字符串”flyers”放入esi寄存器中,用于后续strings_not_equal()函数的字符串比较

然后地址0x4010b8处将[rsp+0x10]放入寄存器rdi中, 用于后续strings_not_equal()函数的字符串比较
通过ASCII表比对得到答案 ionefg

![11.png](https://i.loli.net/2021/04/11/cCRb4eYfnoThWrV.png)

![12.png](https://i.loli.net/2021/04/11/XwnJyfPBagVdR1o.png)

![13.png](https://i.loli.net/2021/04/11/KYJeGrOQUlDqVkv.png)

![14.png](https://i.loli.net/2021/04/11/9ln4LzF6QjHV2c1.png)



## 6

汇编能力有限