---
title: "JAVA可变长度参数" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 可变长度参数

```java
public static void m1(int... args) {} // int... args 这就是可变长度参数
```

语法是：类型...  （注意：一定是3个点。）

注意：

1. 可变长度参数要求的参数个数是：0~N个。
2. 可变长度参数在参数列表中必须在最后一个位置上，而且可变长度参数只能有1个。
3. 可变长度参数可以当做一个数组来看待

###### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        m1();
        m1(100,500);
        m2("abc","def");
        int[] intArr = {123,521};
        m3(intArr);
    }
    public static void m1(int... args) {
        for (int data:args){
            System.out.println(data);
        }
        System.out.println("m1(int... args)方法执行了！");
    }
    public static void m2(String... args) {
        // args有length属性，说明args是一个数组！
        // 可以将可变长度参数当做一个数组来看。
        for (int i = 0 ; i < args.length ; i++){
            System.out.println(args[i]);
        }
        System.out.println("m2(String... args)方法执行了！");
    }
    public static void m3(int[] args) {
        for (int data:args){
            System.out.println(data);
        }
        System.out.println("m3s(int[] args)方法执行了！");
    }
}
```

