---
title: "Java数字格式化类" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 数字格式化类

#### DecimalFormat类

java.text.DecimalFormat专门负责数字格式化的。

```java
DecimalFormat decimalFormat = new DecimalFormat("数字格式");
```

##### 数字格式有哪些？

```java
# 代表任意数字
, 代表千分位
. 代表小数点
0 代表不够时补0
例如:###,###.## // 表示：加入千分位，保留2个小数。
```

###### 代码示例

```java
import java.text.DecimalFormat;

public class Test {
    public static void main(String[] args) {
        // java.text.DecimalFormat专门负责数字格式化的。
        // DecimalFormat decimalFormat = new DecimalFormat("数字格式");
        DecimalFormat decimalFormat1 = new DecimalFormat("###,###.##");
        String numStr = decimalFormat1.format(1314.234);
        System.out.println(numStr);// 1,314.23
        DecimalFormat decimalFormat2 = new DecimalFormat("###,###.0000");
        String s2 = decimalFormat2.format(1234.56);
        System.out.println(s2); // "1,234.5600"
    }
}
```

#### BigDecimal类

BigDecimal 属于大数据，精度极高。不属于基本数据类型，属于java对象（引用数据类型）

java.math.BigDecimal处理财务数据时使用，尽量不要使用double。

###### 代码示例

```java
import java.math.BigDecimal;

public class Test {
    public static void main(String[] args) {
        // 这个100不是普通的100，是精度极高的100
        BigDecimal bigDecimal1 = new BigDecimal(100);
        // 精度极高的200
        BigDecimal bigDecimal2 = new BigDecimal(200);
        // 求和
        // bigDecimal1 + bigDecimal2; // 这样不行，v1和v2都是引用，不能直接使用+求和。
        // 调用方法求和。
        BigDecimal bigResult1 = bigDecimal1.add(bigDecimal2);
        System.out.println(bigResult1);// 300
        BigDecimal bigResult2 = bigDecimal2.divide(bigDecimal1);// 调用除法
        System.out.println(bigResult2);// 2
    }
}
```

