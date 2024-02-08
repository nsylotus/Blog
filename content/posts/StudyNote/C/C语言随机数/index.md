---
title: "C语言生成随机数" # 文章标题.
date: 2022-06-30
draft: false
tags: ["C语言"]
categories: ["C语言"]
---

## 生成随机数

C语言如何生成随机数？

使用rand()函数来生成随机数，但是rand()函数生成的随机数是固定的，所以在调用rand()函数之前需要先调用srand()函数。

```c
srand((unsigned int)time(NULL));
int random = rand() % 100 + 1; // 生成1-100的随机数,rand()%100生成的数是在0-99之间的
```

time()函数在time.h头文件中。

rand()函数在stdlib.h的头文件中。

rand() 会随机生成一个位于 0 ~ RAND_MAX 之间的整数。RAND_MAX 是 <stdlib.h> 头文件中的一个宏，它用来指明rand()所能返回的随机数的最大值。C语言标准并没有规定 RAND_MAX 的具体数值，只是规定它的值至少为 32767。