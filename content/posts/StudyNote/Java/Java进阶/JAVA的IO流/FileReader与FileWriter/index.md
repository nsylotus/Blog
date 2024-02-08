---
title: "Java的FileReader与FileWriter" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### FileReader与FileWriter

##### FileReader

文件字符输入流，只能读取普通文本。读取文本内容时，比较方便，快捷。

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        FileReader fr = null;
        try {
            // 创建文件字符输入流
            fr = new FileReader("D:/file.txt");
            //准备一个char数组
            char[] chars = new char[6];
            // 往char数组中读
            /*fr.read(chars);// 按照字符的方式读取
            for (char c : chars){
                System.out.println(c);
            }*/
            // 循环读取
            int readCount = 0;
            while ((readCount = fr.read(chars)) != -1){
                System.out.println(new String(chars, 0, readCount));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fr != null) {
                try {
                    fr.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

##### FileWriter

文件字符输出流。写。只能输出普通文本。

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        FileWriter fw = null;
        // 创建文件字符输出流对象
        try {
            fw = new FileWriter("D:/file.txt");
            // 开始写。
            char[] chars = {'我','是','中','国','人'};
            fw.write(chars);
            // 写出一个换行符。
            fw.write("\n");
            fw.write(chars, 2, 3);
            // 刷新
            fw.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fw != null) {
                try {
                    fw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

#### 文件的拷贝

使用FileReader，FileWriter进行拷贝的话，只能拷贝“普通文本”文件。

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        FileReader fr = null;
        FileWriter fw = null;
        try {
            // 读
            fr = new FileReader("D:/file.txt");
            // 写
            fw = new FileWriter("D:/myfile.txt");
            // 一边读一边写：
            char[] chars = new char[6];
            int readCount = 0;
            while ((readCount = fr.read(chars)) != -1){
                fw.write(chars,0,readCount);
            }
            // 刷新
            fw.flush();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(fw != null){
                try {
                    fw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if(fr != null){
                try {
                    fr.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

