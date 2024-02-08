---
title: "JAVA的ArrayList集合" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### ArrayList集合

1. 默认初始化容量10（底层先创建了一个长度为0的数组，当添加第一个元素的时候，初始化容量10。）

2. 集合底层是一个Object[]数组。

3. 构造方法：

   ```java
   new ArrayList();// 默认构造函数，使用初始容量10构造一个空列表(无参数构造)
   new ArrayList(20);// 带初始容量参数的构造函数。（用户自己指定容量）
   public ArrayList(Collection<? extends E> c)// 构造包含指定collection元素的列表，这些元素利用该集合的迭代器按顺序返回如果指定的集合为null，则抛出throws NullPointerException。 
   ```

   ###### 代码示例

   ```java
   import java.util.*;
   
   public class Test {
       public static void main(String[] args) {
           // 默认初始化容量10
           List myList1 = new ArrayList();
   
           // 指定初始化容量100
           List myList2 = new ArrayList(100);
   
           // 创建一个HashSet集合
           Collection collection = new HashSet();
           // 添加元素到Set集合
           collection.add(100);
           collection.add(200);
           collection.add(900);
           collection.add(50);
   
           // 通过这个构造方法就可以将HashSet集合转换成List集合。
           List myList3 = new ArrayList(collection);
           for(int i = 0; i < myList3.size(); i++){
               System.out.println(myList3.get(i));
           }
       }
   }
   ```

4. ArrayList集合的扩容：增长到原容量的1.5倍。

5. ArrayList集合底层是数组，怎么优化？

   1. 尽可能少的扩容。因为数组扩容效率比较低，建议在使用ArrayList集合的时候预估计元素的个数，给定一个初始化容量。

6. 数组优点：

   1. 检索效率比较高。（每个元素占用空间大小相同，内存地址是连续的，知道首元素内存地址，然后知道下标，通过数学表达式计算出元素的内存地址，所以检索效率最高。）向数组末尾添加元素，效率很高，不受影响。

7. 数组缺点：

   1. 随机增删元素效率比较低。
   2. 另外数组无法存储大数据量。（很难找到一块非常巨大的连续的内存空间。）

8. 哪个集合最多？

   1. ArrayList集合。因为往数组末尾添加元素，效率不受影响。另外，在检索/查找某个元素的操作比较多。

9. ArrayList集合是非线程安全的。（不是线程安全的集合。）

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        // 默认初始化容量是10
        // 数组的长度是10
        List list1 = new ArrayList();
        // 集合的size()方法是获取当前集合中元素的个数。不是获取集合的容量。
        System.out.println(list1.size()); // 0
        // 指定初始化容量
        // 数组的长度是20
        List list2 = new ArrayList(20);
        // 集合的size()方法是获取当前集合中元素的个数。不是获取集合的容量。
        System.out.println(list2.size()); // 0
        for (int i = 1; i <= 10; i++) {
            list1.add(i);
        }
        System.out.println(list1.size());// 10个元素。
        // 再加一个元素
        list1.add(11);
        /*
        int newCapacity = ArraysSupport.newLength(oldCapacity,minCapacity - oldCapacity,oldCapacity >> 1);
         */
        System.out.println(list1.size()); // 11个元素。
        // 100 二进制转换成10进制： 00000100右移一位 00000010 （2）  【4 / 2】
        // 原先是4、现在增长：2，增长之后是6，增长之后的容量是之前容量的：1.5倍。
        // 6是4的1.5倍
    }
}
```

#### 位的运算

位运算符 >>，乘除2的n次方。左除右乘。

```java
public class Test {
    public static void main(String[] args) {
        // >> 1 二进制右移1位。
        // >> 2 二进制右移2位。
        // 10的二进制位是：00001010  【10】
        // 10的二进制右移1位是：00000101  【5】
        System.out.println(10 >> 1); // 右移1位就是除以2

        // 二进制位左移1位
        // 10的二进制位是：00001010  【10】
        // 10的二进制左移1位：00010100 【20】
        System.out.println(10 << 1);
    }
}
```

