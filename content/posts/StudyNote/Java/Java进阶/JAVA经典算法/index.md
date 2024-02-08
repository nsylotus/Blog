---
title: "JAVA经典算法" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java经典算法

#### 冒泡排序算法

1. 每一次循环结束之后，都要找出最大的数据，放到参与比较的这堆数据的最右边。（冒出最大的那个气泡。）
2. 核心：
   	拿着左边的数字和右边的数字比对，当左边 > 右边的时候，交换位置。
   	一共进行了array.length-1次循环，在第一次循环中比较array.length-1次。在第二次循环中比第一次循环少比较一次。
3. 缺点：
	在不需要交换的时候也进行了比较。

##### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        int[] array = {1314,521,100,666};
        int count = 0;
        int swopCount = 0;
        for (int i = array.length-1; i > 0; i--) {
            for (int j = 0; j < i; j++) {
                count++;
                if(array[j]>array[j+1]){
                    int temp = array[j];
                    array[j] = array[j+1];
                    array[j+1] = temp;
                    swopCount++;
                }
            }
        }
        System.out.println("比较次数:" + count);
        System.out.println("交换的次数:"+swopCount);
        printArray(array);
    }
    public static void printArray(int[] array){
        for (int i = 0; i < array.length; i++) {
            System.out.print(array[i]+",");
        }
    }
}
```

#### 选择排序

选择排序比冒泡排序的效率高。
	高在交换位置的次数上。
	选择排序的交换位置是有意义的。

循环一次，然后找出参加比较的这堆数据中最小的，拿着这个最小的值和最前面的数据“交换位置”。

n条数据循环n-1次。（外层循环n-1次。）

##### 代码示例

```java
public class Test {
    public static void main(String[] args) {
        int[] array = {1314,521,100,666};
        int count = 0;
        int swopConut = 0;
        // 4条数据循环3次。（外层循环3次。）
        for (int i = 0; i < array.length - 1; i++) {
            // i的值是0 1 2
            // i正好是“参加比较的这堆数据中”最左边那个元素的下标。
            // i是一个参与比较的这堆数据中的起点下标。
            // 假设起点i下标位置上的元素是最小的。
            int min = i;
            for (int j = i + 1; j < array.length; j++) {
                count++;
                if(array[j] < array[min]){
                    min = j;//最小值的元素下标是j
                }
            }
            // 当i和min相等时，表示最初猜测是对的。
            // 当i和min不相等时，表示最初猜测是错的，有比这个元素更小的元素，
            // 需要拿着这个更小的元素和最左边的元素交换位置。
            if(min != i){
                // 表示存在更小的数据
                // arr[min] 最小的数据
                // arr[i] 最前面的数据
                swopConut++;
                int temp = array[min];
                array[min] = array[i];
                array[i] = temp;
            }
        }
        // 冒泡排序和选择排序实际上比较的次数没变。
        // 交换位置的次数减少了。
        System.out.println("比较的次数:"+count);
        System.out.println("交换的次数:"+swopConut);
        printArray(array);
    }
    public static void printArray(int[] array){
        for (int i = 0; i < array.length; i++) {
            System.out.print(array[i]+",");
        }
    }
}
```

#### 数组的元素查找

判断数组中是否有某个元素可以使用二分法查找的方法。

数组元素查找有两种方式：

1. 第一种方式：一个一个挨着找，直到找到为止。
2. 第二种方式：二分法查找（算法），这个效率较高。

##### 普通

使用循环遍历的方式一个接一个的查找。

```java
public class Test {
    public static void main(String[] args) {
        int[] array = {100,123,200,300,456,100,999,1314};
        int index = binarySearch(array, 1314);
        System.out.println(index == -1 ? "该元素不存在！" : "该元素下标" + index);
    }

    /**
     * 使用循环遍历从数组中查找目标元素的下标。
     * @param array 被查找的数组（这个必须是已经排序的。）
     * @param dest 目标元素
     * @return -1表示该元素不存在，其它表示返回该元素的下标。
     */
    private static int binarySearch(int[] array, int dest) {
        for (int i = 0; i < array.length; i++) {
            if(dest == array[i]){
                return i;
            }
        }
        return -1;
    }
}
```

##### 二分法

1. 二分法查找建立在排序的基础之上。

2. 二分法查找效率要高于“一个挨着一个”的这种查找方式。
3. 二分法的查找原理：
   1. 将一个数组按中间位置分为两份，然后再分别对每一份进行二分查找。
4. 二分法查找的终止条件：一直折半，直到中间的那个元素恰好是被查找的元素。

```java
public class Test {
    public static void main(String[] args) {
        int[] array = {100,123,200,300,456,100,999,1314};
        int index = binarySearch(array, 100);
        System.out.println(index == -1 ? "该元素不存在！" : "该元素下标" + index);
    }

    /**
     * 使用二分法从数组中查找目标元素的下标。
     * @param array 被查找的数组（这个必须是已经排序的。）
     * @param dest 目标元素
     * @return -1表示该元素不存在，其它表示返回该元素的下标。
     */
    private static int binarySearch(int[] array, int dest) {
        // 开始下标
        int begin = 0;
        // 结束下标
        int end = array.length - 1;
        // 开始元素的下标只要在结束元素下标的左边，就有机会继续循环。
        while (begin <= end){
            // 中间元素下标
            int middle = (begin + end) / 2;
            if(array[middle] == dest){
                return middle;
            }else if(array[middle] < dest){
                // 目标在“中间”的右边
                // 开始元素下标需要发生变化（开始元素的下标需要重新赋值）
                begin = middle + 1;// 一直增
            }else if(array[middle] > dest){
                // arr[mid] > dest
                // 目标在“中间”的左边
                // 修改结束元素的下标
                end = middle - 1;// 一直减
            }
        }
        return -1;
    }
}
```

##### 使用Java自带的Arrays类

其中sort()是排序的方法，binarySearch()是二分法查找的算法。

```java
import java.util.Arrays;
public class Test {
    public static void main(String[] args) {
        int[] array = {100,123,200,300,456,100,999,1314};
        Arrays.sort(array);
        arrayPrint(array);
        int index = Arrays.binarySearch(array,123);
        System.out.println(index == -1 ? "该元素不存在！" : "该元素下标" + index);
    }
    public static void arrayPrint(int[] array){
        for (int i = 0; i < array.length; i++) {
            System.out.print(array[i]+",");
        }
        System.out.println();
    }
}
```

