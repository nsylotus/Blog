---
title: "Java二维数组" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java二维数组

1. 二维数组其实是一个特殊的一维数组，特殊在这个一维数组当中的每一个元素是一个一维数组。

2. 三维数组是什么？
   	三维数组是一个特殊的二维数组，特殊在这个二维数组中每一个元素是一个一维数组。

3. 二维数组静态初始化

   ```java
   int[][] array = {{2,3},{4,5,6},{7,8,9}};
   array[二维数组中的一维数组的下标][一维数组的下标]
   对于array[3][100]来说，其中array[3]是一个整体。[100]是前面array[3]执行结束的结果然后再下标100.
   a[0][0]：表示第1个一维数组中的第1个元素。
   ```

#### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        // 静态初始化二维数组,里面的是3个一维数组。
        int[][] intArrayStatic = {{1,2},{3,4,5},{6,7,8}};
        System.out.println(intArrayStatic.length);// 3
        arrayPrint(intArrayStatic);
        System.out.println(intArrayStatic[1][2]);// 5
        // 动态初始化二维数组。
        int[][] intArrayDynamic = new int[3][3];
        arrayPrint(intArrayDynamic);
        // 可以这样写。也是动态初始化
        arrayPrint(new int[][]{{1,2,3},{4,5,6},{7,8,9}});
        // 没有这种语法
        // arrayPrint({{1,2,3},{4,5,6},{7,8,9}});
    }
    public static void arrayPrint(int[][] intArray){
        // 遍历二维数组
        for (int i = 0; i < intArray.length; i++) {
            int[] array = intArray[i];
            // 负责遍历一维数组
            for (int j = 0; j < array.length; j++) {
                // System.out.print(intArray[i][j]+",");
                System.out.print(array[j]+",");
            }
            System.out.println();
        }
    }
}
```

#### Object类型的数组

Object[]可以装任何引用数据类型的数据

```java
public class Test {
    public static void main(String[] args) {
        // 注意:"abc" 这是一个字符串对象，字符串在java中有优待，不需要new也是一个对象。
        // "abc" 字符串也是java对象，属于String类型。
        // Object[] 这是一个万能的口袋，这个口袋中可以装任何引用数据类型的数据。
        Object[] objs = {new Myclass(),"abc"};
        arrayPrint(objs);
    }
    public static void arrayPrint(Object[] objs){
        for (int i = 0; i < objs.length; i++) {
            System.out.println(objs[i]);
        }
    }
}
class Myclass{}
```
