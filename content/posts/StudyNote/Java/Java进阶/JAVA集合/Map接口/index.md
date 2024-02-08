---
title: "JAVA的Map接口" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Map接口

1. Map和Collection没有继承关系。

2. Map集合以key和value的方式存储数据：

   1. 键值对key和value都是引用数据类型。key和value都是存储对象的内存地址。key起到主导的地位，value是key的一个附属品。

3. 遍历Map集合的两种方式：

   1. 第一种：获取所有key，遍历每个key，通过key获取value.
   2. 第二种：获取Set<Map.Entry>即可，遍历Set集合中的Entry，调用entry.getKey()，entry.getValue()

4. Map接口中常用方法：

   ```java
   V put(K key, V value) // 向Map集合中添加键值对，V是Value的意思
   V get(Object key) // 通过key获取value
   void clear() // 清空Map集合
   boolean containsKey(Object key) // 判断Map中是否包含某个key
   boolean containsValue(Object value) // 判断Map中是否包含某个value
   boolean isEmpty() // 判断Map集合中元素个数是否为0
   V remove(Object key) // 通过key删除键值对
   int size() // 获取Map集合中键值对的个数。
   Collection<V> values() // 获取Map集合中所有的value，返回一个Collection
   Set<K> keySet() // 获取Map集合所有的key（所有的键是一个set集合）
   Set<Map.Entry<K,V>> entrySet() // 将Map集合转换成Set集合
   ```

假设现在有一个Map集合，如下所示：

![Map集合转换成Set集合entrySet()方法](./Map集合转换成Set集合entrySet()方法.png)

注意：Map集合通过entrySet()方法转换成的这个Set集合，Set集合中元素的类型是 Map.Entry<K,V>

Map.Entry和String一样，都是一种类型的名字，只不过：Map.Entry是静态内部类，是Map中的静态内部类

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        // 创建Map集合对象
        Map<Integer,String> integerStringMap = new HashMap<>();
        // 向Map集合中添加键值对
        integerStringMap.put(1,"张三"); // 1在这里进行了自动装箱。
        integerStringMap.put(2,"李四");
        // 通过key获取value
        String value = integerStringMap.get(2);
        System.out.println(value);// 李四
        // 获取键值对的数量
        System.out.println("键值对的数量：" + integerStringMap.size()); // 键值对的数量：2
        // 通过key删除key-value
        integerStringMap.remove(2);
        System.out.println("键值对的数量：" + integerStringMap.size()); // 键值对的数量：1
        // 判断是否包含某个key
        // contains方法底层调用的都是equals进行比对的，所以自定义的类型需要重写equals方法。
        System.out.println(integerStringMap.containsKey(new Integer(3))); // false
        // 判断是否包含某个value
        System.out.println(integerStringMap.containsValue(new String("张三"))); // true

        // 获取所有的value
        Collection<String> values = integerStringMap.values();
        // foreach
        for(String str : values){
            System.out.println(str); // 张三
        }
        // 清空map集合
        integerStringMap.clear();
        System.out.println("键值对的数量：" + integerStringMap.size()); // 键值对的数量：0
        // 判断是否为空
        System.out.println(integerStringMap.isEmpty()); // true
    }
}
```

##### Map集合的遍历

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        Map<Integer,String> integerStringMap = new HashMap<>();
        integerStringMap.put(1,"张三");
        integerStringMap.put(2,"李四");
        // 第一种方式：获取所有的key，通过遍历key，来遍历value
        // 遍历Map集合
        // 获取所有的key，所有的key是一个Set集合
        Set<Integer> integerSet = integerStringMap.keySet();
        Iterator<Integer> integerIterator = integerSet.iterator();
        while (integerIterator.hasNext()){
            // 取出其中一个key
            Integer key = integerIterator.next();
            // 通过key获取value
            String value = integerStringMap.get(key);
            System.out.println(key + "=" + value);
        }
        // foreach也可以
        for(Integer key : integerSet){
            System.out.println(key + "=" + integerStringMap.get(key));
        }

        // 第二种方式：Set<Map.Entry<K,V>> entrySet()
        // 以上这个方法是把Map集合直接全部转换成Set集合。
        // Set集合中元素的类型是：Map.Entry
        Set<Map.Entry<Integer,String>> entrySet = integerStringMap.entrySet();
        // 遍历Set集合，每一次取出一个Node
        // 迭代器
        Iterator<Map.Entry<Integer,String>> entryIterator = entrySet.iterator();
        while(entryIterator.hasNext()){
            Map.Entry<Integer,String> node = entryIterator.next();
            Integer key = node.getKey();
            String value = node.getValue();
            System.out.println(key + "=" + value);
        }

        // foreach
        // 这种方式效率比较高，因为获取key和value都是直接从node对象中获取的属性值。
        // 这种方式比较适合于大数据量。
        for(Map.Entry<Integer,String> node : entrySet){
            System.out.println(node.getKey() + "--->" + node.getValue());
        }
    }
}
```

### 静态内部类

###### 代码示例

```java
import java.util.*;
public class Test {
    // 声明一个静态内部类
    private static class InnerClass {
        // 静态方法
        public static void m1(){
            System.out.println("静态内部类的m1方法执行");
        }
        // 实例方法
        public void m2(){
            System.out.println("静态内部类中的实例方法执行！");
        }
    }
    public static void main(String[] args) {
        // 类名叫做：Test.InnerClass
        Test.InnerClass.m1();
        // 创建静态内部类对象
        Test.InnerClass Ti = new Test.InnerClass();
        Ti.m2();
        // 给一个Set集合
        // 该Set集合中存储的对象是：Test.InnerClass类型
        Set<Test.InnerClass> set = new HashSet<>();
        // 这个Set集合中存储的是字符串对象。
        Set<String> set2 = new HashSet<>();
        Set<MyMap.MyEntry<Integer, String>> set3 = new HashSet<>();
    }
}
class MyMap {
    public static class MyEntry<K,V> {

    }
}
```

