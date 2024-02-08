---
title: "Java的数据字节流" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 数据字节流。

在IO包中，提供了两个与平台无关的数据操作流：

通常数据输出流会按照一定的格式将数据输出，再通过数据输入流按照一定的格式将数据读入。读写顺序必须一样。是将数据以及数据的类型一并写入到文件当中的流。

##### DataInputStream:数据字节输入流。

DataOutputStream写的文件，只能使用DataInputStream去读。并且读的时候你需要提前知道写入的顺序。读的顺序需要和写的顺序一致。才可以正常取出数据。DataOutputStream是OutputStream的子类

##### DataOutputStream:数据字节输出流。

这个流可以将数据连同数据的类型一并写入文件。是将数据以及数据的类型一并写入到文件当中的流。

注意：这个文件不是普通文本文档。（这个文件使用记事本打不开。）

###### 代码示例

```java
import java.io.*;

public class Test {
    public static void main(String[] args) throws Exception{
        // 创建数据专属的字节输出流
        DataOutputStream dos = new DataOutputStream(new FileOutputStream("D:/data.txt"));
        // 创建数据专属的字节输入流
        DataInputStream dis = new DataInputStream(new FileInputStream("D:/data.txt"));
        // 写数据
        int num = 100;
        boolean bool = false;
        char ch = 'A';
        // 写
        dos.writeInt(num);// 把数据以及数据的类型一并写入到文件当中。
        dos.writeBoolean(false);
        dos.writeChar(ch);
        // 刷新
        dos.flush();
        // 关闭最外层
        dos.close();
        // 开始读
        int readNum = dis.readInt();
        boolean readBool = dis.readBoolean();
        char readCh = dis.readChar();
        System.out.println(readNum + "+" + readBool + "+" + readCh);
    }
}
```

