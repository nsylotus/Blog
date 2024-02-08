---
title: "Java的FileInputStream" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### FileInputStream

文件字节输入流，万能的，任何类型的文件都可以采用这个流来读。以字节的方式，完成输入的操作，完成读的操作（硬盘---> 内存）

FileInputStream类的其它常用方法：

```java
int read() // 从此输入流中读取一个数据字节。
int read(byte[] b) // 从此输入流中将最多 b.length个字节的数据读入一个byte 数组中。
int read(byte[] b, int off, int len) // 从此输入流中将最多 len 个字节的数据读入一个 byte 数组中。
long skip(long n) // 跳过几个字节不读。
int available() // 返回流当中剩余的没有读到的字节数量
void close() // 关闭此文件输入流并释放与此流有关的所有系统资源。
```

##### 一个字节一个字节的读

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        // 创建文件字节输入流对象
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("D:\\Test.txt");
            // 开始读
            /*int readData = fis.read(); // 这个方法的返回值是：读取到的“字节”本身，读到文件的末尾，再读的时候读取不到任何数据，返回-1.
            System.out.println(readData);*/
            // 使用while循环
            int readData = 0;
            while ((readData = fis.read()) != -1){
                System.out.println(readData);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            // 在finally语句块当中确保流一定关闭。
            if (fis != null) { // 避免空指针异常！
                // 关闭流的前提是：流不是空。流是null的时候没必要关闭。
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

##### 使用数组的方式读

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("D:/Test.txt");
            // 开始读，采用byte数组，一次读取多个字节。最多读取“数组.length”个字节。
            byte[] bytes = new byte[2];// 准备一个2个长度的byte数组，一次最多读取2个字节。
            int readCount = 0;
            // fis.read(bytes)这个方法的返回值是：读取到的字节数量。（不是字节本身）
            while ((readCount = fis.read(bytes)) != -1){// 1个字节都没有读取到返回-1
                System.out.println(readCount);// 第一次读到了2个字节。第二次读到了1个字节。
                // System.out.println(new String(bytes)); // 将字节数组全部转换成字符串：读到的是ab,cb
                // 不应该全部都转换，应该是读取了多少个字节，转换多少个。
                System.out.println(new String(bytes,0, readCount));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

###### 常用方法

```java
import java.io.*;

public class Test {
    public static void main(String[] args) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("D:/Test.txt");
            System.out.println("总字节数量：" + fis.available());// 总字节数量：3
            // 读1个字节
            int readByte = fis.read();
            System.out.println("剩下多少个字节没有读：" + fis.available());// 剩下多少个字节没有读：2
            // byte[] bytes = new byte[fis.available()]; // 这种方式不太适合太大的文件，因为byte[]数组不能太大。

            // skip跳过几个字节不读取，这个方法也可能以后会用！
            fis.skip(1);
            System.out.println(fis.read()); //99
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

