---
title: "Java的Date日期类" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Date日期类

获取系统当前时间

```java
Date nowTime = new Date();
```

日期格式化：

Date --> String

将日期Date转换为自己想要的字符串格式

```java
SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
String nowTimeStr = sdf.format(new Date());
```

String --> Date

将字符串日期格式转换为Date格式

```java
SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
Date date = sdf.parse("2008-08-08 08:08:08");
```

获取毫秒数

```java
long begin = System.currentTimeMillis();// 获取自1970年1月1日 00:00:00 000到当前系统时间的总毫秒数。
Date date = new Date(begin - 1000 * 60 * 60 * 24);
```

#### SimpleDateFormat类的注意事项

SimpleDateFormat构造方法传的字符串中，应使用一下的字符串。

```
yyyy 年(年是4位)
MM 月（月是2位）
dd 日
HH 时
mm 分
ss 秒
SSS 毫秒（毫秒3位，最高999。1000毫秒代表1秒）
注意：在日期格式中，除了y M d H m s S这些字符不能随便写之外，剩下的符号格式自己随意组织。
```

##### 代码示例

```java
import java.text.SimpleDateFormat;
import java.util.Date;

public class Test {
    public static void main(String[] args) throws Exception {
        // 获取系统当前时间（精确到毫秒的系统当前时间）
        // 直接调用无参数构造方法就行。
        Date nowTime = new Date();
        System.out.println(nowTime);
        // java.util.Date类的toString()方法已经被重写了。
        // 输出的应该不是一个对象的内存地址，应该是一个日期字符串。

        // 将日期类型Date,按照指定的格式进行转换:Date --转换成具有一定格式的日期字符串-->String
        // SimpleDateFormat是java.text包下的。专门负责日期格式化的。
        SimpleDateFormat simpleDateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        String nowTimeStr = simpleDateFormat1.format(nowTime);
        System.out.println(nowTimeStr);

        String time = "2008-08-08 08:08:08 888";
        //SimpleDateFormat sdf2 = new SimpleDateFormat("格式不能随便写，要和日期字符串格式相同");
        // 注意：字符串的日期格式和SimpleDateFormat对象指定的日期格式要一致。不然会出现异常：java.text.ParseException
        SimpleDateFormat simpleDateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        Date date = simpleDateFormat2.parse(time);
        System.out.println(date);// Fri Aug 08 08:08:08 CST 2008

        // 获取自1970年1月1日 00:00:00 000到当前系统时间的总毫秒数。1秒 = 1000毫秒
        long nowTimeMillis = System.currentTimeMillis();
        System.out.println(nowTimeMillis);

        // 这个时间是什么时间？
        // 1970-01-01 00:00:00 001
        Date date3 = new Date(1); // 注意：参数是一个毫秒

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss SSS");
        String strTime = sdf.format(date3);
        // 北京是东8区。差8个小时。
        System.out.println(strTime); // 1970-01-01 08:00:00 001

        // 获取昨天的此时的时间。
        Date time2 = new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 24);
        String strTime2 = sdf.format(time2);
        System.out.println(strTime2);
    }
}
```

#### System类的相关属性和方法

```java
System.out // out是System类的静态变量。
System.out.println() // println()方法不是System类的，是PrintStream类的方法。
System.gc() // 建议启动垃圾回收器
System.currentTimeMillis() // 获取自1970年1月1日到系统当前时间的总毫秒数。
System.exit(0) // 退出JVM。
```

