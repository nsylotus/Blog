---
title: "Java的缓冲流" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### BufferedReader与BufferedWriter

当一个流的构造方法中需要一个流的时候，这个被传进来的流叫做：节点流。

外部负责包装的这个流，叫做：包装流/处理流。

#### BufferedReader

带有缓冲区的字符输入流。使用这个流的时候不需要自定义char数组，或者说不需要自定义byte数组。自带缓冲。

BufferedReader：带有缓冲的字符输入流。InputStreamReader：转换流

###### 代码示例

```java
import java.io.*;
public class Test {
    public static void main(String[] args) throws Exception {
        FileReader fr = new FileReader("D:/myfile.txt");
        BufferedReader br = new BufferedReader(fr);// 需要传入一个Reader类型。
        // 对当前这个程序来说：FileReader就是一个节点流。BufferedReader就是包装流/处理流。
        // 读一行
        System.out.println(br.readLine());// br.readLine()方法读取一个文本行，但不带换行符。
        String s = null;
        while ((s = br.readLine()) != null){
            System.out.println(s);
        }
        // 关闭流
        // 对于包装流来说，只需要关闭最外层流就行，里面的节点流会自动关闭。（可以看源代码。）
        br.close();
    }
}
```

###### 字节流使用BufferedReader类需要通过转换流转换

```java
import java.io.*;
public class Test {
    public static void main(String[] args) throws Exception {
        /*// 字节流
        FileInputStream fis = new FileInputStream("D:/myfile.txt");
        // 通过转换流转换（InputStreamReader将字节流转换成字符流。）
        // fis是节点流。isr是包装流。
        InputStreamReader isr = new InputStreamReader(fis);
        // 这个构造方法只能传一个字符流。不能传字节流。要传入字节流需要借助InputStreamReader类去转换
        // isr是节点流。br是包装流。
        BufferedReader br = new BufferedReader(isr);*/
        // 合并
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("D:/myfile.txt")));
        String s = null;
        while ((s = br.readLine()) != null){
            System.out.println(s);
        }
        br.close();
    }
}
```

#### BufferedWriter

BufferedWriter：带有缓冲的字符输出流。OutputStreamWriter：转换流

###### 代码示例

```java
import java.io.*;
public class Test {
    public static void main(String[] args) throws IOException {
        // 带有缓冲区的字符输出流
        // BufferedWriter bw = new BufferedWriter(new FileWriter("D:/file.txt"));
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("D:/file.txt")));
        // 开始写。
        bw.write("Hello Word!!!");
        bw.write("\n");
        bw.write(100);
        // 刷新
        bw.flush();
        // 关闭最外层
        bw.close();
    }
}
```

