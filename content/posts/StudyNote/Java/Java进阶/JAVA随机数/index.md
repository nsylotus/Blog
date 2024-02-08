---
title: "Java随机数" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java随机数

Java中的随机数使用Random来生成。

###### 代码示例

```java
import java.util.Random;

public class Test {
    public static void main(String[] args) {
        // 创建随机数对象
        Random random = new Random();
        // 随机产生一个int类型取值范围内的数字。
        int num1 = random.nextInt();
        System.out.println(num1);

        // 产生[0~100]之间的随机数。不能产生101。
        // nextInt翻译为：下一个int类型的数据是101，表示只能取到100.
        int num2 = random.nextInt(101); //不包括101
        System.out.println(num2);
    }
}
```

###### 生成5个不重复的随机数[0-100]。

```java
import java.util.Random;

public class Test {
    public static void main(String[] args) {
        // 准备一个长度为5的一维数组。
        int arr[] = new int[5];// 默认值都是0
        // 创建Random对象
        Random random = new Random();
        // 修改每一位的默认值为-1,这样不会与生成的0混淆。
        for (int i = 0; i < arr.length; i++) {
            arr[i] = -1;
        }
        // 循环，生成随机数
        int index = 0;
        while (index < arr.length){
            // 生成随机数
            int num = random.nextInt(101);
            System.out.println("生成的随机数是:"+num);
            // 判断arr数组中有没有这个num
            // 如果没有这个num，就放进去。
            if(! contains(arr,num)){
                arr[index++] = num;
            }
        }
        // 遍历以上的数组
        for (int i = 0; i < arr.length; i++) {
            System.out.println(arr[i]);
        }
    }

    /**
     * 单独编写一个方法，这个方法专门用来判断数组中是否包含某个元素
     * @param array arr 数组
     * @param key key 元素
     * @return true表示包含，false表示不包含。
     */
    public static boolean contains(int[] array, int key){
        // 对数组进行升序,这个方案bug。（排序出问题了。）
        // Arrays.sort(arr);
        // 进行二分法查找
        // 二分法查找的结果 >= 0说明，这个元素找到了，找到了表示存在！
        // return Arrays.binarySearch(arr, key) >= 0;
        for (int i = 0; i < array.length; i++) {
            if(array[i] == key){
                // 条件成立了表示包含，返回true
                return true;
            }
        }
        // 这个就表示不包含！
        return false;
    }
}
```

