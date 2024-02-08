---
title: "Java的File类" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### File类

1. File类和四大家族没有关系，所以File类不能完成文件的读和写。

2. 简述File类的作用：

   1. 一个File对象而可以代表一个文件或目录，File可以实现获取文件和目录属性等功能，可以实现对文件和目录的创建，删除等功能。
   2. 它不允许访问文件内容。File类主要用于命名文件、查询文件属性和处理文件目录。
   3. File 类不具有从文件读取信息和向文件写入信息的功能，它仅描述文件本身的属性。
   4. File类主要是JAVA为文件这块的操作(如删除、新增等)而设计的相关类。
   5. File类的包名是java.io，其实现了Serializable, Comparable两大接口以便于其对象可序列化和比较

3. File对象代表什么？

   1. 文件和目录路径名的抽象表示形式。
   2. C:\Drivers 这是一个File对象
   3. C:\Drivers\Readme.txt 也是File对象。
   4. 一个File对象有可能对应的是目录，也可能是文件。File只是一个路径名的抽象表示形式。

4. File类中常用的方法

   ```java
   boolean mkdirs() // 可以创建多重目录吗？
   boolean mkdir() // 创建此抽象路径名指定的目录。
   String getParent() // 获取文件的父路径,如果此路径名没有指定父目录，则返回 null。
   String getAbsolutePath() // 返回路径名的绝对路径
   File getAbsoluteFile() // 返回路径名的绝对路径名形式。
   boolean exists() // 测试此抽象路径名表示的文件或目录是否存在。
   boolean createNewFile() // 如果文件或者目录不存在以文件的形式创建。
   String getName() // 返回文件或目录的名称。
   boolean isDirectory() // 判断是否是一个目录
   boolean isFile() // 判断是否是一个文件
   long lastModified() // 获取文件最后一次修改时间，这个毫秒是从1970年到现在的总毫秒数。
   long length() // 获取文件大小，大小是字节。
   File[] listFiles() // 获取当前目录下所有的子文件。
   ```

###### 代码示例

```java
import java.io.File;

public class Test {
    public static void main(String[] args) {
        // 创建一个File对象
        // File file = new File("D:/myfile");
        // 判断是否存在！
        // System.out.println(file.exists());// 不存在返回false
        // 如果D:/myfile不存在，则以文件的形式创建出来
        /*if(!file.exists()) {
            // 以文件形式新建
            file.createNewFile();
        }*/
        // 如果D:\file不存在，则以目录的形式创建出来
        /*if(!file.exists()) {
            // 以目录的形式新建。
            file.mkdir();
        }*/
        // 可以创建多重目录吗？
        // File file = new File("D:/myfile/wwwroot/");
        /*if(!file.exists()) {
            // 多重目录的形式新建。
            file.mkdirs();
        }*/
        File file = new File("D:/var/www/html/myfile.txt");
        // 获取文件的父路径
        String parentPath = file.getParent();
        System.out.println(parentPath);// D:\var\www\html
        File parentFile = file.getParentFile();
        System.out.println("绝对路径：" + parentFile.getAbsolutePath()); // 获取绝对路径：D:\var\www\html
    }
}
```

###### 代码示例

```java
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Test {
    public static void main(String[] args) {
        File file = new File("D:\\var\\www\\html\\myfile.txt");
        // 获取文件名
        System.out.println("文件名：" + file.getName()); // 文件名：myfile.txt
        // 判断是否是一个目录
        System.out.println(file.isDirectory()); // false
        // 判断是否是一个文件
        System.out.println(file.isFile()); // true
        // 获取文件最后一次修改时间
        long createDate = file.lastModified(); // 这个毫秒是从1970年到现在的总毫秒数。
        Date date = new Date(createDate);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        String newDate = sdf.format(date);
        System.out.println(newDate);
        // 获取文件大小
        System.out.println("文件大小是:"+file.length()); // 文件大小是:0字节

        // File[] listFiles()
        // 获取当前目录下所有的子文件。
        File dirFile = new File("D:\\");
        File[] files = dirFile.listFiles();
        for (File f:files){
            System.out.println(f.getAbsolutePath());
            System.out.println(f.getName());
        }
    }
}
```

#### 目录的拷贝

```java
import java.io.*;
// 拷贝目录
public class Test {
    public static void main(String[] args) {
        // 拷贝源
        File srcFile = new File("D:\\course\\02-JavaSE\\document");
        // 拷贝目标
        File destFile = new File("C:\\a\\b\\c");
        // 调用方法拷贝
        copyDir(srcFile, destFile);
    }

    /**
     * 拷贝目录
     * @param srcFile 拷贝源
     * @param destFile 拷贝目标
     */
    private static void copyDir(File srcFile, File destFile) {
        if(srcFile.isFile()) {
            // srcFile如果是一个文件的话，递归结束。
            // 是文件的时候需要拷贝。
            // ....一边读一边写。
            FileInputStream in = null;
            FileOutputStream out = null;
            try {
                // 读这个文件
                in = new FileInputStream(srcFile);
                // 写到这个文件中
                String path = (destFile.getAbsolutePath().endsWith("\\") ? destFile.getAbsolutePath() : destFile.getAbsolutePath() + "\\")  + srcFile.getAbsolutePath().substring(3);
                out = new FileOutputStream(path);
                // 一边读一边写
                byte[] bytes = new byte[1024 * 1024]; // 一次复制1MB
                int readCount = 0;
                while((readCount = in.read(bytes)) != -1){
                    out.write(bytes, 0, readCount);
                }
                out.flush();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (out != null) {
                    try {
                        out.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            return;
        }
        // 获取源下面的子目录
        File[] files = srcFile.listFiles();
        for(File file : files){
            // 获取所有文件的（包括目录和文件）绝对路径
            // System.out.println(file.getAbsolutePath());
            if(file.isDirectory()){
                // 新建对应的目录
                //System.out.println(file.getAbsolutePath());
                String srcDir = file.getAbsolutePath();
                String destDir = (destFile.getAbsolutePath().endsWith("\\") ? destFile.getAbsolutePath() : destFile.getAbsolutePath() + "\\")  + srcDir.substring(3);
                File newFile = new File(destDir);
                if(!newFile.exists()){
                    newFile.mkdirs();
                }
            }
            // 递归调用
            copyDir(file, destFile);
        }
    }
}
```

