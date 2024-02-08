---
title: "const关键字" # 文章标题.
date: 2022-07-27
draft: false
tags: ["C语言"]
categories: ["C语言"]
---

# const关键字

C语言如何写出优秀的代码：

1. 使用assert
2. 使用const

## 模拟实现strcpy函数

```c
char* strcpy(目标空间的起始地址,源空间的起始地址);
```

```c
#include <stdio.h>
#include <string.h>
#include <assert.h>

char* my_Strcpy(char *,const char *);
int main(void) {
    char str_1[10] = "xxxxxxxx";
    char str_2[] = "Hello";
    // my_Strcpy(str_1,str_2);
    // strcpy函数,其实返回的是拷贝目标的起始地址
    // strcpy(目标空间的起始地址,源空间的起始地址);
    // strcpy(str_1,str_2);
    printf("%s\n", my_Strcpy(str_1,str_2)); // 如果函数的返回值类型定义为char*，这样就可以使用函数调用的链式法则
    // void类型无法使用
    return 0;
}
/*void my_Strcpy(char *dest,char *src){
    while (*src != '\0'){
        *dest = *src;
        dest++;
        src++;
    }
    *dest = *src;
}*/
// 与以上代码是等价的
// 把src指向的内容拷贝放进dest指向的空间中
// 从本质说，希望dest指向的内容被修改，src指向的内容不应该被修改
/*void my_Strcpy(char * dest,char *src){
    // 加入断言,防止程序输入自己不想要的值,类似于try...catch...
    assert(src!=NULL); // 断言
    assert(dest!=NULL);// 里面的值为0(假)的话报错
    while (*dest++ = *src++){
        // src最后一位是\0,而\0赋值给dest后仍然是\0,然而\0的ASCII码值为0
        // c语言中,\0的ascii码是0,而0既是假,然而这时候的\0也就赋值上了
        // 即copy了\0,又终止了循环
        ;
    }
}*/
char* my_Strcpy(char * dest,const char* src){
    assert(src != NULL);
    assert(dest);
    char * ret = dest;
    // 加入const可以有效的避免报错
    while (*dest++ = *src++){
        ;
    }
    return ret; // 返回目标空间的起始地址
}
```

## const关键字

const修饰变量，这个变量称为常变量，**不能被修改**，但本质上还是变量

```c
#include <stdio.h>
int main(void) {
	int num_1 = 10;
	const int num_2 = 20;
	// num_2 = 30; // 提示左值为const对象
	// printf("%d\n",num_2);
	num_1 = 20;
	const int* p_num_2 = &num_2;
    *p_num_2 = 30;
	printf("%d\n", *p_num_2);
    // 在前面没有加const的情况下,虽然num_2是const修饰的,但是我们可以使用指针的方式间接修改num_2的值
	// 如果加了const,即const修饰指针变量的时候
	// const如果放在*的左边,修饰的是*p_num_2,表示指针制指向的内容,是不能通过指针来改变的
	// 但是指针变量本身是可以被修改的
	
	// const修饰指针变量的时候
	// const如果放在*的右边,修饰的是指针变量p,表示指针变量不能被改变
	// 但是指针所指的内容可以被改变
	return 0;
}
```

## 模拟实现strlen函数

### 第一种方法

```c
#include <stdio.h>
#include <string.h>
#include <assert.h>
int my_strlen(char*);
int main(void) {
	char string[] = "Hello";
	printf("%d\n",my_strlen(string));
	return 0;
}
int my_strlen(const char* str) {
	assert(str);
	int count = 0;
	while ('\0' != *str++) {
		count++;
	}
	return count;
}
```

### 第二种方法

```c
int my_strlen(const char* str) {
	assert(str);
	const char* end = str;
    // 这种是源码的方法
	while (*end++); // 但是这种方法我不理解,因为又const修饰了所以*end++应该是不能在改变了啊为什么?
	return (end - str - 1);
}
```

`while(*end++)`的理解：

看下面的代码：

```c
#include <stdio.h>
int main(void) {
	const int nums[] = {1,2,3,4,5,0};
	const int* p_nums = nums;
	while (*p_nums) {
		printf("%d ",*(p_nums++));
		printf("%d ", *p_nums++); // 这两行代码是等价的
        // 1 2 3 4 5
	}
}
```

这就涉及到`*p++`和 `(*p)++`的区别了

`*p++`是指下一个地址，就是`*(p++)`

`(*p)++`是指将`*p`所指的数据的值加1。

## extern关键字

利用关键字**extern**，可以在一个文件中引用另一个文件中定义的变量或者函数
