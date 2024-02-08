---
title: "C语言算数转换作业" # 文章标题.
date: 2022-08-13
draft: false
tags: ["C语言"]
categories: ["C语言"]
---

# C语言算数转换作业

判断下面程序的输出结果

```c
#include <stdio.h>
int i; // i是全局变量,不初始化，默认是0
int main(void) {
	i--; // -1
	// sizeof这个操作符,算出的结果的类型是unsigned int
	// int类型与unsigned int类型比较时将int类型转换为unsigned int类型进行比较
	if (i>sizeof(i)) { // -1<4 Error
		printf(">\n"); // √
	}
	else{
		printf("<\n");
	}
	return 0;
}
```

求水仙花数

```c
#include <stdio.h>
#include <math.h>
int main(void) {
	// 判断i是否是自幂数
	for (int i = 0; i <= 100000;i++) {
		// 1.计算i的位数
		int i_size = 1;
		int temp = i;
		while (temp/10) {
			temp = temp / 10;
			i_size++;
		}
		// 2.计算i的每一位的n次方
		double result = 0;
		temp = i;
		while (temp) {
			result += pow((temp % 10), i_size);
			temp /= 10;
		}
		// 3.判断
		if (result == i) {
			printf("%d ",i);
		}
	}
	return 0;
}
```

