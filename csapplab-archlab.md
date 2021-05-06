---
title: csapplab_archlab
date: 2021-05-06 21:26:16
tags:
password: 
---

this my fifth week challenge!

<!--more-->

第一次看wp都看的头大的东西



# PART A

任务：模拟examples.c完成三个函数的翻译：从c语言到Y86-64的汇编语言。





如下是例子.c文件中定义的一个链表

```
/* linked list element */
typedef struct ELE {
    long val;
    struct ELE *next;
} *list_ptr
```

以下是其测试得到的数据

```
# Sample linked list
.align 8
ele1:
    .quad 0x00a
    .quad ele2
ele2:
    .quad 0x0b0
    .quad ele3
ele3:
    .quad 0xc00
    .quad 0

```



## sum_list

```
/* sum_list - Sum the elements of a linked list */
long sum_list(list_ptr ls)
{
    long val = 0;
    while (ls) {
        val += ls->val;
        ls = ls->next;
    }
    return val;
}

```

这个是要求我们对链表进行迭代求和=-=



#### sum_list.ys

```
# Execution begins at address 0 
	.pos 0
	irmovq stack, %rsp  	# Set up stack pointer
	call main		# Execute main program
	halt			# Terminate program 
	
# 内存区域，存放数据/链表之类
# Sample linked list
.align 8
ele1:
    .quad 0x00a
    .quad ele2
ele2:
    .quad 0x0b0
    .quad ele3
ele3:
    .quad 0xc00
    .quad 0
# END

main:	
	irmovq ele1,%rdi  #参数准备
	call sum_list		# sum_list(ele1)
	ret

# long sum_list(long i)
# ele1 in %rdi
sum_list:	
	xorq %rax,%rax           #val=0
loop:
    mrmovq (%rdi),%r8 #读取node.val值到寄存器r8
    addq %r8,%rax #将结果加到return val中
    mrmovq 8(%rdi),%rdi
    jmp test       #无条件跳转到test
test:
    andq %rdi,%rdi      
    jne loop
	ret                

# Stack starts here and grows to lower addresses.
# 这里自定义栈开始地址
	.pos 0x200
stack:


```

执行以下命令可以得到测试结果

```
./yas sum_list.ys ./yis sum_list.yo
```



## rsum_list

```
/* rsum_list - Recursive version of sum_list */
long rsum_list(list_ptr ls)
{
    if (!ls)
	    return 0;
    else {
        long val = ls->val;
        long rest = rsum_list(ls->next);
        return val + rest;
    }
}

```



和前面的sum_list大同小异，rsum这里先对node.val存储到了末尾才开始

addq %rbx,%rax



#### rsum_list.ys

```
# Execution begins at address 0 
	.pos 0
	irmovq stack, %rsp  	# Set up stack pointer
	call main		# Execute main program
	halt			# Terminate program 
	
# 内存区域，存放数据/链表之类
# Sample linked list
.align 8
ele1:
    .quad 0x00a
    .quad ele2
ele2:
    .quad 0x0b0
    .quad ele3
ele3:
    .quad 0xc00
    .quad 0
# END

main:	
	irmovq ele1,%rdi  #参数准备
	call rsum_list		# rsum_list(ele1)
	ret

# long rsum_list(long i)
# ele1 in %rdi
rsum_list:	
    pushq %rbx          #自递归，需要保存目前的结果。其实rbx就是存了 上一个node.val
	xorq %rax,%rax           #return val=0
    andq %rdi, %rdi
    je finish
    mrmovq (%rdi), %rbx  #当前的node.val
    mrmovq 8(%rdi), %rdi #node = node->next
    call rsum_list
    addq %rbx, %rax #在这里仍然会继续往下执行。

finish:
    popq %rbx            #
	ret                  # Return

# Stack starts here and grows to lower addresses.
# 这里自定义栈开始地址
	.pos 0x200
stack:

```



## copy_block

```
/* copy_block - Copy src to dest and return xor checksum of src */
long copy_block(long *src, long *dest, long len)
{
    long result = 0;
    while (len > 0) {
        long val = *src++; //两个语句：long val = *src;src++;
        *dest++ = val;//两个语句：*dest = val;dest++
        result ^= val;//update checksum
        len--;
    }
    return result;
}







.align 8
# Source block
src:
.quad 0x00a
.quad 0x0b0
.quad 0xc00
# Destination block
dest:
.quad 0x111
.quad 0x222
.quad 0x333

```





#### copy_block.sy

```
# Execution begins at address 0 
	.pos 0
	irmovq stack, %rsp  	# Set up stack pointer
	call main		# Execute main program
	halt			# Terminate program 
	
# 内存区域，存放数据/链表之类
.align 8
# Source block
src:
.quad 0x00a
.quad 0x0b0
.quad 0xc00
# Destination block
dest:
.quad 0x111
.quad 0x222
.quad 0x333

#END
main:	
	irmovq src,%rdi     #param1
    irmovq dest,%rsi    #param2
    irmovq $3,%rdx     #param3
	call copy_block		# copy_block(src,dest,)
	ret

# long copy_block(long *src, long *dest, long len)
# src in %rdi
# dest in %rsi
# 3 in %rdx
copy_block:	
    pushq %rbx
    pushq %r9
    pushq %r10
	xorq %rax,%rax           #result=0
    irmovq $8,%r9
    irmovq $1,%r10
    jmp test
loop:
    mrmovq (%rdi),%rbx        #long val = *src;
    addq %r9,%rdi            #src++;
    rmmovq %rbx,(%rsi)        #*dest = val;
    addq %r9,%rsi            #dest++;
    xorq %rbx,%rax            #update checksum
    subq %r10,%rdx           #len--
test:
    andq %rdx,%rdx  #set CC
    jne loop        #Stop when len = 0
    popq %r10
    popq %r9
    popq %rbx
	ret                         

# Stack starts here and grows to lower addresses.
	.pos 0x200
stack:

```











pa就看的我死去活来了。。。pb pc真的有空补吧人都要没了