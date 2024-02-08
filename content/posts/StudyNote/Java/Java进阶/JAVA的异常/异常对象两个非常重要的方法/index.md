---
title: "Java异常对象两个非常重要的方法" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 异常对象两个非常重要的方法

1. 获取异常简单的描述信息：

   ```java
   String msg = exception.getMessage();
   ```

2. 打印异常追踪的堆栈信息：

   ```java
   exception.printStackTrace();// 一般都是使用这个。exception为异常对象
   ```

3. 异常信息追踪信息，从上往下一行一行看。

#### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        // 这里只是为了测试getMessage()方法和printStackTrace()方法。
        // 这里只是new了异常对象，但是没有将异常对象抛出。JVM会认为这是一个普通的java对象。
        NullPointerException e = new NullPointerException("空指针异常");

        // 获取异常简单描述信息：这个信息实际上就是构造方法上面String参数。
        String msg = e.getMessage(); //空指针异常
        System.out.println(msg);

        // 打印异常堆栈信息
        // java后台打印异常堆栈追踪信息的时候，采用了异步线程的方式打印的。
        e.printStackTrace();

        for(int i = 0; i < 1000; i++){
            System.out.println("i = " + i);
        }

        System.out.println("Hello World!");
    }
}
```

