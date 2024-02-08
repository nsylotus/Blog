---
title: "JAVA反射Method类的学习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 反射Method类的学习

Java中依靠方法名和参数列表，来区分方法。

Method类常用的方法：

```java
Method getDeclaredMethods() // 获取所有的方法，其中：包括公共、保护、默认（包）访问和私有方法，返回 Method 对象的一个数组，但不包括继承的方法。
Class<?> getReturnType() // 得到Method的返回值类型。
Class<?>[] getParameterTypes() // 返回Method的形参，是一个数组
Method getDeclaredMethod(String name, Class<?>... parameterTypes) // 返回一个 Method 对象，一个方法对象。
Object invoke(Object obj, Object... args) // 对带有指定参数的指定对象调用由此 Method 对象表示的底层方法。传入参数调用方法
```

###### 代码示例

```java
import java.lang.reflect.*;

public class Test {
    public static void main(String[] args) throws Exception {
        // 获取类
        Class myClass = Class.forName("User");
        // 获取所有的Method（包括私有的！）
        Method[] methods = myClass.getDeclaredMethods();
        System.out.println(methods.length); // 3
        // 遍历Method
        for (Method method:methods){
            // 获取修饰符列表
            System.out.println(Modifier.toString(method.getModifiers()));
            // 获取方法的返回值类型
            System.out.println(method.getReturnType());
            // 获取方法名
            System.out.println(method.getName());
            // 方法的修饰符列表（一个方法的参数可能会有多个。）
            Class[] parameterTypes = method.getParameterTypes();
            for (Class pt:parameterTypes){
                System.out.println(pt.getSimpleName());
            }
        }
    }
}
```

##### 反编译一个类的方法

```java
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class Test {
    public static void main(String[] args) throws Exception{
        StringBuilder stringBuilder = new StringBuilder();
        Class myClass = Class.forName("User");
        stringBuilder.append(Modifier.toString(myClass.getModifiers())+" class "+myClass.getSimpleName()+"{\n");
        Method[] methods = myClass.getDeclaredMethods();
        for (Method method:methods){
            stringBuilder.append("\t");
            stringBuilder.append(Modifier.toString(myClass.getModifiers())+" ");
            stringBuilder.append(method.getReturnType()+" ");
            stringBuilder.append(method.getName()+"(");
            Class[] parameterTypes = method.getParameterTypes();
            // 参数列表
            for (Class pt:parameterTypes){
                stringBuilder.append(pt.getSimpleName()+",");
            }
            if(parameterTypes.length > 0){
                // 删除指定下标位置上的字符
                stringBuilder.deleteCharAt(stringBuilder.length()-1);
            }
            stringBuilder.append("){}\n");
        }
        stringBuilder.append("}");
        System.out.println(stringBuilder);
    }
}
```

### 通过反射机制调用一个对象的方法？

反射机制，让代码很具有通用性，可变化的内容都是写到配置文件当中，将来修改配置文件之后，创建的对象不一样了，调用的方法也不同了，java代码不需要做任何改动。这就是反射机制的魅力。

调用方法的四要素：

1. 相应的对象
2. 相应对象的方法
3. 方法传入的实参列表
4. 方法的返回值

```java
import java.lang.reflect.Method;

public class Test {
    public static void main(String[] args) throws Exception{
        // 不使用反射机制，怎么调用方法
        // 创建对象
        User user = new User();
        // 调用方法
        /*
        要素分析：
            要素1：对象user
            要素2：login方法名
            要素3：实参列表
            要素4：返回值
         */
        boolean loginSuccess = user.login("admin","123");
        System.out.println(loginSuccess ? "登录成功" : "登录失败");
        // 使用反射机制来调用一个对象的方法该怎么做？
        Class userClass = Class.forName("User");
        // 创建对象
        Object obj = userClass.newInstance();
        // 获取Method(方法)
        Method loginMethod = userClass.getMethod("login", String.class, String.class);
        // 调用方法
        // 调用方法有几个要素？ 也需要4要素。
        // 反射机制中最最最最最重要的一个方法，必须记住。
        /*
        四要素：
        loginMethod方法
        obj对象
        "admin","123" 实参
        retValue 返回值
         */
        Object retValue = loginMethod.invoke(obj,"admin","123");
        System.out.println(retValue);// true
    }
}
```

