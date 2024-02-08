---
title: "JAVA的HashSet集合" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### HashSet集合

1. HashSet集合：
   1. 无序不可重复。
      1. 无序：存储时顺序和取出的顺序不同。
      2. 不可重复。
      3. 放到HashSet集合中的元素实际上是放到HashMap集合的key部分了。

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        Set<String> stringSet = new HashSet<>();
        // 添加元素
        stringSet.add("Hello");
        stringSet.add("Word");
        stringSet.add("Hello");
        stringSet.add("def");
        stringSet.add("Hello");
        stringSet.add("Hello");
        for (String str:stringSet) {
            System.out.println(str);
            /*Word
            Hello
            def*/
        }
    }
}
```

