---
title: "C语言结构体" # 文章标题.
date: 2022-07-20
draft: false
tags: ["C语言"]
categories: ["C语言"]
---

# C语言结构体

结构体与数组的区别：

1. 数组：一些相同类型元素的集合

2. 结构体：一类元素的集合，可以是不同的数据类型，这些值被称为成员变量

结构体的声明：

```c
struct 结构体名{
    // 成员变量
    数据列表;
} 结构体变量; // 全局变量,当然这个也可以被称为是对象
```

## 结构体的传参用法

```c
#include <stdio.h>
struct Message
{
    int age;
    char *address;
};

struct Student
{
    char *name;
    struct Message message;
} student01 = {"李四", {21, "上海"}};

void struct_print(struct Student); // 传结构体
void ptr_struct_print(struct Student *); // 传地址

int main(void)
{
    struct Student student02 = {"张三", {18, "北京"}};
    struct Student *ptr_student02 = &student02;
    struct_print(student02);
    struct_print(student01);
    ptr_struct_print(ptr_student02);
    return 0;
}

void struct_print(struct Student stu)
{
    printf("%s %d %s\n", stu.name, stu.message.age, stu.message.address);
}
void ptr_struct_print(struct Student *ptr_stu)
{
    printf("%s %d %s\n", (*ptr_stu).name, (ptr_stu)->message.age, (*ptr_stu).message.address);
}
```

结论：结构体在传参的过程中，要传结构体的地址

因为：函数传参的时候，参数是需要压栈的，如果传递一个结构体的对象，结构体过大，参数压栈的系统内存开销大，所以会导致性能的下降

