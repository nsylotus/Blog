---
title: "Java标准的字节输出流" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### PrintStream：标准的字节输出流

java.io.PrintStream：标准的字节输出流。默认输出到控制台。

标准输出流不需要手动close()关闭。

标准输出流可以改变输出的方向，向不同的地方进行输出。例如文件中。

```java
import java.io.*;
public class Test {
    public static void main(String[] args) throws Exception {
        // 联合起来写
        System.out.println("hello world!");
        // 分开写
        PrintStream ps = System.out;
        ps.println("def");
        PrintStream printStream = new PrintStream(new FileOutputStream("D:/myfile.txt"));
        // 修改输出方向，将输出方向修改到"log"文件。
        System.setOut(printStream);
        // 再输出
        printStream.println("Hello Word!!!");
        System.out.println("def");
    }
}
```

##### 日志工具的示例

```java
import java.io.*;
import java.util.Date;
import java.text.*;

public class Test {
    public static void main(String[] args) throws Exception {
        Log.log("调用了System类的gc()方法，建议启动垃圾回收");
    }
}
class Log{
    //记录日志的方法。
    public static void log(String msg) throws Exception {
        // 指向一个日志文件
        PrintStream ps = new PrintStream(new FileOutputStream("D:/log.txt",true));
        // 改变输出方向
        System.setOut(ps);
        // 日期当前时间
        Date date = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        String newDate = sdf.format(date);
        System.out.println(newDate + ": " + msg);
    }
}
```

