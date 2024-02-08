---
title: "JAVA中Hashtable与HashMap的区别" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Hashtable与HashMap的区别

1. Hashtable的key可以为null吗？
   1. Hashtable的key和value都是不能为null的。HashMap集合的key和value都是可以为null的。
2. Hashtable方法都带有synchronized：线程安全的。线程安全有其它的方案，这个Hashtable对线程的处理导致效率较低，使用较少了。
3. Hashtable和HashMap一样，底层都是哈希表数据结构。Hashtable的初始化容量是11，默认加载因子是：0.75f，Hashtable的扩容是：原容量 * 2 + 1
4. HashMap和Hashtable的区别。
   1. HashMap：
      1. 初始化容量16，扩容2倍。非线程安全，key和value可以为null。
   2. Hashtable：
      1. 初始化容量11，扩容2倍+1，线程安全，key和value都不能是null。

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        Map map = new Hashtable();
        // map.put(null,123); // java.lang.NullPointerException异常
        map.put(100,null); // // java.lang.NullPointerException异常
    }
}
```

