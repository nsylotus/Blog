---
title: "Java的try..catch中的finally子句" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---


### try..catch中的finally子句

1. 在finally子句中的代码是最后执行的，并且是**一定会执行的**，即使try语句块中的代码出现了异常。

2. finally子句必须和try一起出现，不能单独编写。

3. finally语句通常使用在哪些情况下呢？

   1. 通常在finally语句块中完成资源的释放/关闭。因为finally中的代码比较有保障。即使try语句块中的代码出现异常，finally中代码也会正常执行。

   2. 例如：

      ```java
      import java.io.FileInputStream;
      import java.io.FileNotFoundException;
      import java.io.IOException;
      
      public class Test {
          public static void main(String[] args) {
              FileInputStream fis = null;// 声明位置放到try外面。这样在finally中才能用。
              try {
                  // 创建输入流对象
                  fis = new FileInputStream("D:\\123.txt");
                  // 开始读文件....
                  fis.read();
                  String s = null;
                  // 这里一定会出现空指针异常！NullPointerException
                  s.toString();
                  // 出异常后后面的代码不会被执行。
                  System.out.println("Hello Word!!!");
                  // 流使用完需要关闭，因为流是占用资源的。
                  // 即使以上程序出现异常，流也必须要关闭！
                  // 放在这里有可能流关不了。
                  // fis.close();
                  fis.close();
              } catch (FileNotFoundException e) {
                  e.printStackTrace();
              } catch (IOException e) {
                  e.printStackTrace();
              } catch (NullPointerException e){
                  e.printStackTrace();
              } finally {
                  System.out.println("Hello finally");
                  // 流的关闭放在这里比较保险。
                  // finally中的代码是一定会执行的。
                  // 即使try中出现了异常！
                  if(fis != null){// 避免空指针异常！
                      try {
                          fis.close();// close()方法有异常，采用捕捉的方式。
                      } catch (IOException e) {
                          e.printStackTrace();
                      }
                  }
              }
              System.out.println("Hello end");
          }
      }
      ```

4. try和finally，没有catch可以吗？

   1. 可以。try不能单独使用。try finally可以联合使用。

   2. 要是finally中的语句不执行，必须退出JVM。

   3. 代码示例

      ```java
      public class Test {
          /**
           * 以下代码的执行顺序：
           * 先执行try...
           * 再执行finally...
           * 最后执行 return（return语句只要执行方法必然结束。）
           * @param args
           */
          public static void main(String[] args) {
              try {
                  System.out.println("Hello try");
                  System.exit(0);// 退出JVM之后，finally语句中的代码就不执行了！
                  return;
              } finally {
                  // finally中的语句会执行。能执行到。
                  System.out.println("Hello finally");
              }
              // 这里不能写语句，因为这个代码是无法执行到的。因为return的原因。
              // System.out.println("Hello Word");
          }
      }
      ```

#### finally经典题目

###### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        int result = m1();
        System.out.println(result);
    }
    /*
    java语法规则（有一些规则是不能破坏的，一旦这么说了，就必须这么做！）：
        java中有一条这样的规则：
            方法体中的代码必须遵循自上而下顺序依次逐行执行（亘古不变的语法！）
        java中海油一条语法规则：
            return语句一旦执行，整个方法必须结束（亘古不变的语法！）
     */
    private static int m1() {
        int i = 100;
        try {
            // 这行代码出现在int i = 100;的下面，所以最终结果必须是返回100
            // return语句还必须保证是最后执行的。一旦执行，整个方法结束。
            return i;
        } finally {
            i++;
        }
    }
}
```

#### final finally finalize有什么区别？

###### final 关键字

1. final修饰的类无法继承。
2. final修饰的方法无法覆盖。
3. final修饰的变量不能重新赋值。

###### finally 关键字

1. 和try一起联合使用。
2. finally语句块中的代码是必须执行的。

###### finalize 标识符

1. 是一个Object类中的方法名。
2. 这个方法是由垃圾回收器GC负责调用的。

###### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        // final是一个关键字。表示最终的。不变的。
        final int i = 100;
        // i = 200;错误

        // finally也是一个关键字，和try联合使用，使用在异常处理机制中
        // 在fianlly语句块中的代码是一定会执行的。
        try {

        } finally {
            System.out.println("finally....");
        }

        // finalize()是Object类中的一个方法。作为方法名出现。
        // 所以finalize是标识符。
        // finalize()方法是JVM的GC垃圾回收器负责调用。
        Object obj;
    }
}

// final修饰的类无法继承
final class A {
    // 常量。
    public static final double MATH_PI = 3.1415926;
}

class B {
    // final修饰的方法无法覆盖
    public final void doSome(){}
}
```



