---
title: "JAVA的Properties属性类" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Properties属性类

1. Properties是一个Map集合，继承Hashtable，Properties的key和value都是String类型。
2. Properties被称为属性类对象。
3. Properties是线程安全的。

两个方法：

```java
Object setProperty(String key, String value); // 存入数据。调用 Hashtable 的方法 put。
String getProperty(String key) // 根据key取出相应的内容。
void load(Reader reader) // 调用Properties对象的load方法将文件中的数据加载到Map集合中。
```

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        // 创建一个Properties对象
        Properties properties = new Properties();
        properties.setProperty("english","150");
        // 通过key获取value
        String eng = properties.getProperty("english");
        System.out.println(eng);
    }
}
```

### IO+Properties的联合应用

1. 设计理念：

   1. ​	以后经常改变的数据，可以单独写到一个文件中，使用程序动态读取。将来只需要修改这个文件的内容，java代码不需要改动，不需要重新编译，服务器也不需要重启。就可以拿到动态的信息。

   2. 类似于以上机制的这种文件被称为配置文件。并且当配置文件中的内容格式是：

      ```java
      key1=value
      key2=value
      ```

      的时候，我们把这种配置文件叫做属性配置文件。

2. java规范中有要求：属性配置文件建议以.properties结尾，但这不是必须的。这种以.properties结尾的文件在java中被称为：属性配置文件。其中Properties是专门存放属性配置文件内容的一个类。

3. 在配置文件中：

   1. 建议key和value之间使用=的方式。不适用:
   2. =左边是key，=右边是value
   3. 在属性配置文件中井号是注释###
   4. 属性配置文件的key重复的话，value会自动覆盖！
   5. 最好不要有空格

###### 代码示例

```java
import java.io.*;
import java.util.*;

public class Test {
    public static void main(String[] args) throws Exception{
        // Properties是一个Map集合，key和value都是String类型。想将userinfo文件中的数据加载到Properties对象当中。
        // 新建一个输入流对象
        FileReader fr = new FileReader("src/userinfo.properties");
        // 新建一个Map集合
        Properties pro = new Properties();
        // 调用Properties对象的load方法将文件中的数据加载到Map集合中。
        pro.load(fr); // 文件中的数据顺着管道加载到Map集合中，其中等号=左边做key，右边做value
        // 通过key来获取value
        String username = pro.getProperty("username");
        System.out.println(username);
    }
}
```

