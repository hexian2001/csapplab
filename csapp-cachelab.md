---
title: csapp_cachelab
date: 2021-05-16 20:02:59
tags:
---

my sixth  week challenge！！！

<!--more-->

=-=，逐渐失去理智┗|｀O′|┛ 嗷~~

## part A

 编写一个cache模拟器，该模拟器可以模拟在一系列的数据访问中cache的命中、不命中与牺牲行的情况，其中，需要牺牲行时，用LRU替换策略进行替换。

        cache模拟器需要能处理一系列如下的命令：
    
        Usage: ./csim-ref [-hv] -s <s> -E <E> -b <b> -t <tracefile>
    
        其中各参数意义如下：

①-h：输出帮助信息的选项；

②-v：输出详细运行过程信息的选项；

③-s：组索引的位数(意味着组数S=2^s)；

④-E：每一组包含的行数；

⑤-b：偏移位的宽度(意味着块的大小为B=2^b);

⑥-t：输入数据文件的路径(测试数据从该文件里面读取)。




### CODE

```
int s,S,E,b;
FILE *fp;
for(int i=1;i<argc;){
         //printf("%s",argv[i]);
	 if(argv[i][0]=='-'){
		if(argv[i][1] == 's'){
			i++;
			s = change2number(argv[i]);
			S = (1<<s);
			i++;
		}
		else if(argv[i][1] == 'E'){
			i++;
			E = change2number(argv[i]);
			i++;
		}
		else if(argv[i][1] == 'b'){
			i++;
			b = change2number(argv[i]);
			i++;
		}
		else if(argv[i][1] == 't'){
			i++;
			fp = fopen(argv[i],"r");
	         	i++;
		}
	}
}
```



## part B

①编写一个实现矩阵转置的函数。即对于给定的矩阵A[N][M]，得到矩阵B[M][N]，使得对于任意0<=i<N、0<=j<M，有B[j][i]=A[i][j]，并且使函数调用过程中对cache的不命中数miss尽可能少。

②在如下函数里面编写最终代码：

char transpose_submit_desc[] = "Transpose submission";

void transpose_submit(int M, int N, int A[N][M], int B[M][N])；

=-=题目看懂了 手不会这个矩阵转置才刚学没多久麻了，强了再回来看