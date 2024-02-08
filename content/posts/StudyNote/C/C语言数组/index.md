---
title: "C语言数组" # 文章标题.
date: 2022-07-06
draft: false
tags: ["C语言"]
categories: ["C语言"]
---

# 数组

```c
strlen() // 函数-求字符串的长度,找\0之前的字符个数
sizeof() // 其实是一个操作符,并不是一个函数,用来计算变量/类型所占的内存大小,单位是字节
```

注：以下代码这种两种定义数组的方式是有区别的
```c
#include <stdio.h>
#include <string.h>
int main(void)
{
    char string_1[] = {'a', 'b', 'c', 'd', 'e', '\0'}; 
    // 这样定义的字符串是没有\0的,也就是说，没有字符串的结束标志
    char string_2[] = "abcde";
    printf("%d %d\n", sizeof(string_1), sizeof(string_2)); // 6 6
    printf("%d %d", strlen(string_1), strlen(string_2));   // 5 5
    return 0;
}
```

注：二维数组可以省略一维的大小，但不可省略二维的大小！！！定义二维数组时行数可以省略,但是列数不能省略

## 数组与数组名的关系

数组名是数组元素的首地址，但是有两个例外：

1. sizeof(数组名) --- 数组名表示整个数组，计算的是整个数组的大小单位是字节
2. &数组名 --- 数组名表示整个数组，取出来的是整个数组的地址

## 数组排序

### 冒泡排序

```c
#include <stdio.h>
// 冒泡排序
void bubble_sort(int[], int);
int main(void)
{
    int numbers[] = {1, 9, 10, 6, 3, 7, 5, 2};
    int numbers_len = sizeof(numbers) / sizeof(numbers[0]);
    bubble_sort(numbers, numbers_len);
    for (int i = 0; i < numbers_len; i++)
    {
        printf("%d ", numbers[i]);
    }
    return 0;
}
void bubble_sort(int numbers[], int arrs_len)
{
    for (int i = 0; i < arrs_len - 1; i++)
    {
        for (int j = 0; j < arrs_len - i - 1; j++)
        {
            if (numbers[j] > numbers[j + 1])
            {
                int temp = numbers[j + 1];
                numbers[j + 1] = numbers[j];
                numbers[j] = temp;
            }
        }
    }
}
```

冒泡排序的优化

```c
#include <stdio.h>
// 冒泡排序
void bubble_sort(int[], int);
int main(void)
{
    int numbers[] = {1, 9, 10, 6, 3, 7, 5, 2};
    int numbers_len = sizeof(numbers) / sizeof(numbers[0]);
    bubble_sort(numbers, numbers_len);
    for (int i = 0; i < numbers_len; i++)
    {
        printf("%d ", numbers[i]);
    }
    return 0;
}
void bubble_sort(int numbers[], int arrs_len)
{
    for (int i = 0; i < arrs_len - 1; i++)
    {
        int flag = 1; // 这个可以更加方便的去对已经有序的数组减少排序次数
        for (int j = 0; j < arrs_len - i - 1; j++)
        {
            if (numbers[j] > numbers[j + 1])
            {
                int temp = numbers[j + 1];
                numbers[j + 1] = numbers[j];
                numbers[j] = temp;
                flag = 0;
            }
        }
        if (flag == 1)
        {
            break;
        }
    }
}
```

