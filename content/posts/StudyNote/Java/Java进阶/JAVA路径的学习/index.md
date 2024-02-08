---
title: "Java路径的学习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java路径的学习

1. 由于以前用的获取文件路径的方式移植性差，在IDEA中默认的当前路径是Project的根。假设这个代码假设离开了IDEA，换到了其它位置，可能当前路径就不是Project的根了，这时这个路径就无效了。

   以前获取路径的方式：

   ```java
   FileReader reader = new FileReader("classinfo.properties");
   ```

2. 怎么获取一个文件的绝对路径。以下这种方式是通用的。但前提是：文件需要在类路径下。才能用这种方式。

3. 什么类路径下？

   方式在src下的都是类路径下。src是类的根路径。

4. 获取路径的方法的解析：

```java
static Thread currentThread() // 当前线程对象
ClassLoader getContextClassLoader() // 是线程对象的方法，可以获取到当前线程的类加载器对象。
URL getResource(String name) // 查找具有给定名称的资源。【获取资源】这是类加载器对象的方法，当前线程的类加载器默认从类的根路径下加载资源。
String getPath() // 返回此 URI 的已解码的路径组成部分。
```
5. 代码演示：

   ```java
   String path = Thread.currentThread().getContextClassLoader().getResource("写相对路径，但是这个相对路径从src出发开始找").getPath();
   String path = Thread.currentThread().getContextClassLoader().getResource("abc").getPath(); // 必须保证src下有abc文件。
   String path = Thread.currentThread().getContextClassLoader().getResource("var/db").getPath();  // 必须保证src下有var目录，var目录下有db文件。
   ```

   这种方式是为了获取一个文件的绝对路径。（通用方式，不会受到环境移植的影响。）但是该文件要求放在类路径下，换句话说：也就是放到src下面。src下是类的根路径。

   ###### 代码示例

   ```java
   public class Test {
       public static void main(String[] args) {
           String strPath = Thread.currentThread().getContextClassLoader().getResource("userinfo.properties").getPath(); // 这种方式获取文件绝对路径是通用的。
           // src是根路径
           // 采用以上的代码可以拿到一个文件的绝对路径。（从类的根路径下作为起点开始）
           System.out.println(strPath);
       }
   }
   ```

6. 直接以流的形式返回：

   ```java
   InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("test.properties");
   ```

   ###### 代码示例

   ```java
   import java.io.*;
   import java.util.Properties;
   
   public class Test{
       public static void main(String[] args) throws Exception{
           // 获取一个文件的绝对路径了！！！！！
           /*String path = Thread.currentThread().getContextClassLoader().getResource("userinfo.properties").getPath();
           FileReader fr = new FileReader(path);*/
   
           // 直接以流的形式返回。
           InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("userinfo.properties");
           Properties properties = new Properties();
           properties.load(in);
           in.close();
           // 通过key获取value
           String className = properties.getProperty("classname");
           System.out.println(className);
       }
   }
   ```

7. IO + Properties，怎么快速绑定属性资源文件？

   java.util包下提供了一个资源绑定器，便于获取属性配置文件中的内容。使用以下这种方式的时候，属性配置文件xxx.properties必须放到类路径下。

   1. 要求：第一这个文件必须在类路径下
   2. 第二这个文件必须是以.properties结尾。

   资源绑定器，只能绑定xxx.properties文件。并且这个文件必须在类路径下。文件扩展名也必须是properties，并且在写路径的时候，路径后面的扩展名不能写。

   ```java
   ResourceBundle bundle = ResourceBundle.getBundle("test");// test.properties不写properties
   String value = bundle.getString(key);
   ```

   ```java
   import java.util.ResourceBundle;
   
   public class Test {
       public static void main(String[] args) {
           // 资源绑定器，只能绑定xxx.properties文件。并且这个文件必须在类路径下。文件扩展名也必须是properties
           // 并且在写路径的时候，路径后面的扩展名不能写。
           ResourceBundle resourceBundle = ResourceBundle.getBundle("userinfo");
           String className = resourceBundle.getString("classname");
           System.out.println(className);
       }
   }
   ```

   







