---
title: "C语言操作符" # 文章标题.
date: 2022-07-13
draft: false
tags: ["C语言"]
categories: ["C语言"]
---
# C语言操作符

## 位运算

补充：

对于数来说内存中存储的是二进制的补码，正数的原码，反码，补码相同，负数不同

原码：原始的二进制数字，-1的二进制数字为`eg：10000000000000000000000000000001`

反码：原码符号位保持不变，其他位按位取反`eg：11111111111111111111111111111110`

补码：反码+1`eg：11111111111111111111111111111111`

用二进制的最高位表示符号位，0为正，1为负。

### 左移操作符

左边丢弃，右边补0

### 右移操作符

右移操作符分为：

1. 算数右移：右边丢弃，左边补原符号位
2. 逻辑右移：右移丢弃，左边补0

```c
#include <stdio.h>
int main(void)
{
    int number_1 = 11;
    number_1 = number_1 << 2; // 11*2的2次方
    int number_2 = 22;
    int number_3 = -1;
    number_2 = number_2 >> 2; // 22/2的2次方
    number_3 = number_3 >> 1;
    printf("%d\n", number_1); // 44
    printf("%d\n", number_2); // 5
    printf("%d\n", number_3); // 算数右移
}
```

### &，|，^   (按位与，按位或，按位异或)操作符

```c
#include <stdio.h>
int main(void)
{
    int number_1 = 3, number_2 = 5, number_3 = -1;
    // &,|,^必须是整数
    printf("%d\n", number_1 & number_2); // 有0则0
    printf("%d\n", number_1 | number_2); // 有1则1
    printf("%d\n", number_1 ^ number_2); // 相同为0,相异为1
    printf("%d\n", number_1 ^ number_1); // 0
    printf("%d\n", 0 ^ number_1);        // 3
    printf("%d\n", ~number_3);           // 按位取反 0
    return 0;
}
```

#### 关于^操作符

任何两个相同的数字^结果都是0，0^任何一个数都是本身

#### 实现两数交换

##### 第一种实现方法

定义一个临时变量

```c
#include <stdio.h>
int main(void)
{
    int number_1 = 1, number_2 = 2, temp;
    temp = number_1;
    number_1 = number_2;
    number_2 = temp;
    printf("%d,%d\n", number_1, number_2);
    return 0;
}
```

##### 第二种实现方法

不使用临时变量，使用简单的加减法，但是这样会有一个错误，如果一个数，超过了32767这个数，会造成栈的溢出，所以不建议使用这种方法

```c
#include <stdio.h>
int main(void)
{
    int number_1 = 10, number_2 = 13;
    number_1 = number_1 + number_2;
    number_2 = number_1 - number_2;
    number_1 = number_1 - number_2;
    printf("%d,%d\n", number_1, number_2);
    return 0;
}
```

##### 第三种实现方法

这种方法是在第二种方法的基础上进行延申过来的，这个使用了按位异或运算符

```c
#include <stdio.h>
int main(void)
{
    int number_1 = 10, number_2 = 13;
    // 1010 = 10
    // 1101 = 13
    // 0111 = 7
    number_1 = number_1 ^ number_2; // 0111 = 7
    number_2 = number_1 ^ number_2; // 1010 = 10 
    // <==> number_1 ^ number_2 ^ number_2 <==> number_1 ^ 0 = number_1
    number_1 = number_1 ^ number_2; // 1101 = 13
    // 异或是相同为0,不同为1
    printf("%d,%d\n", number_1, number_2);
    return 0;
}
```

#### |（按位或操作符）

```c
#include <stdio.h>
int main(void)
{
    // 将二进制位中的第五位改为1
    int number_1 = 13, number_2 = 0, number_3;
    // 01101 = 13
    // 10000 = 1 << 4    "|"
    // 11101
    number_2 = number_1 | (1 << 4);
    printf("%d\n", number_2);
    // 将number_2修改为原来的数字,即将二进制位中的第五位改为0
    number_3 = number_2 & ~(1 << 4);
    // 11101 = 29
    // 01111 = ~10000 = 1 << 4    "&"
    // 01101 = 13
    printf("%d\n", number_3);
    return 0;
}
```

## 三目运算符

注意表达式的结构

```c
#include <stdio.h>
int main(void)
{
    // 三目运算符
    int number_1 = 5, number_2 = 0;
    if (number_1 > 10)
    {
        number_2 = 1;
    }
    else
    {
        number_2 = -1;
    }
    // 三目运算符，与上面的if-else语句类似
    number_2 = (number_1 > 10) ? 2 : -2;
    printf("%d\n", number_2);
    return 0;
}
```

## 逗号表达式","

逗号表达式：要从左向右依次计算，但是整个表达式的结果是最后一个表达式的结果，不能直接计算最后一个表达式，因为前面的表达式也有可能影响后面的结果

```c
#include <stdio.h>
int main(void)
{
    // 逗号表达式
    int number_1 = 3, number_2 = 5, number_3 = 0;
    int number_4 = (number_3 = 5, number_1 = number_3 + 3, number_2 = number_1 - 4, number_3 += 5);
    printf("%d\n", number_4); // 10
    return 0;
}
```

## 结构成员访问操作符

分为`.`操作符（值操作符），和`->`操作符（地址操作符）

`.`：`结构体变量名.成员名`，`->`：`结构体指针->成员名`

```c
#include <stdio.h>
struct Book
{
    char *BookName;
    char *BookNumber;
    int BookMoney;
};

int main(void)
{
    struct Book book = {"杀死一只知更鸟", "123456789", 100};
    struct Book *pbook = &book;
    // . 结构体变量名.成员名
    // -> 结构体指针->成员名
    // 这三种方式的实现效果是一样的
    printf("%s\n", book.BookName);
    printf("%s\n", (*pbook).BookNumber);
    printf("%d\n", pbook->BookMoney);
    return 0;
}
```

