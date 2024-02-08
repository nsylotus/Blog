---
title: "JAVA字符串的拼接" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 字符串的拼接

### StringBuffer/StringBuilder

1. StringBuffer/StringBuilder可以看做可变长度字符串。

2. StringBuffer/StringBuilder初始化容量16

3. StringBuffer/StringBuilder是完成字符串拼接操作的，方法名：append

4. StringBuffer是线程安全的。StringBuilder是非线程安全的。

5. 频繁进行字符串拼接不建议使用“+”，因为java中的字符串是不可变的，每一次拼接都会产生新字符串。这样会占用大量的方法区内存。造成内存空间的浪费。给方法区字符串常量池带来很大的压力。
   	例如：

   ```java
   String s = "abc";
   s += "hello";
   // 就以上两行代码，就导致在方法区字符串常量池当中创建了3个对象："abc","hello","abchello"
   ```

6. 如果以后需要进行大量字符串的拼接操作，建议使用Java中自带的
	
	```java
	java.lang.StringBuffer
	java.lang.StringBuilder
	```
	
#### StringBuffer

1. 如何优化StringBuffer的性能？
   1. 在创建StringBuffer的时候尽可能给定一个初始化容量。
   2. 最好减少底层数组的扩容次数。预估计一下，给一个大一些初始化容量。
   3. 关键点：给一个合适的初始化容量。可以提高程序的执行效率。

##### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        // 创建一个初始化容量为16个byte[] 数组。（字符串缓冲区对象）
        StringBuffer stringBuffer1 = new StringBuffer();
        // 拼接字符串，以后拼接字符串统一调用 append()方法。
        // append是追加的意思。
        stringBuffer1.append("d");
        stringBuffer1.append("e");
        // append方法底层在进行追加的时候，如果byte数组满了，会自动扩容。
        stringBuffer1.append("f!!!");
        System.out.println(stringBuffer1.toString());// def!!!
        // 指定初始化容量的stringBuffer1对象（字符串缓冲区对象）
        StringBuffer stringBuffer2 = new StringBuffer(99);
        stringBuffer2.append("hello");
        stringBuffer2.append("word!!!");
        System.out.println(stringBuffer2.toString());// helloword!!!
    }
}
```

##### String为什么是不可变的？

通过源代码，String类中有一个byte[]数组，这个byte[]数组采用了final修饰，因为数组一旦创建，长度不可变。并且被final修饰的引用一旦指向某个对象之后，不可再指向其它对象，所以String是不可变的！"abc" 无法变成 "abcd"

##### StringBuilder/StringBuffer为什么是可变的呢？

通过源代码，StringBuffer/StringBuilder内部实际上是一个byte[]数组，这个byte[]数组没有被final修饰，StringBuffer/StringBuilder的初始化容量是16，当存满之后会进行扩容，底层调用了数组拷贝的方法System.arraycopy()方法，是这样扩容的。所以StringBuilder/StringBuffer适合于使用字符串的频繁拼接操作。

```java
public class Test {
    public static void main(String[] args) {
        // 字符串不可变是什么意思？
        // 是说双引号里面的字符串对象一旦创建不可变。
        String s = "abc"; //"abc"放到了字符串常量池当中。"abc"不可变。

        // s变量是可以指向其它对象的。
        // 字符串不可变不是说以上变量s不可变。说的是"abc"这个对象不可变。
        s = "xyz";//"xyz"放到了字符串常量池当中。"xyz"不可变。
    }
}
```

#### StringBuilder

1. StringBuffer和StringBuilder的区别？

   1.  StringBuffer中的方法都有：synchronized关键字修饰。表示StringBuffer在多线程环境下运行是安全的，**StringBuffer是线程安全的。**

   2. StringBuilder中的方法都没有：synchronized关键字修饰，表示StringBuilder在多线程环境下运行是不安全的。

      **StringBuilder是非线程安全的。**

##### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        // 使用StringBuilder也是可以完成字符串的拼接。
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("def");
        stringBuilder.append("!!!");
        System.out.println(stringBuilder.toString());// def!!!
    }
}
```

