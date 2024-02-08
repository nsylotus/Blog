---
title: "Java的foreach关键字" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### foreach的学习

增强for（foreach）

##### 语法

```java
for(元素类型 变量名 : 数组或集合){
	System.out.println(变量名);
}
```

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        // int类型数组
        int[] arr = {1314,521,100};
        // 遍历数组（普通for循环）
        for(int i = 0; i < arr.length; i++) {
            System.out.println(arr[i]);
        }
        // foreach有一个缺点：没有下标。在需要使用下标的循环中，不建议使用foreach循环。
        for (int data : arr){
            // data就是数组中的元素（数组中的每一个元素。）
            System.out.println(data);
        }
        List<String> stringList = new ArrayList<>();
        stringList.add("abc");
        stringList.add("def");
        for (String str : stringList) {
            System.out.println(str);
        }
    }
}
```

