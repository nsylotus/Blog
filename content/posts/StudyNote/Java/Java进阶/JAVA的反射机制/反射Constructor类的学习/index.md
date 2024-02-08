---
title: "JAVA反射Constructor类的学习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 反射Constructor类的学习

常用方法：

```java
Constructor<?>[] getDeclaredConstructors() // 返回 Constructor 对象的一个数组，这些对象反映此 Class 对象表示的类声明的所有构造方法。
Constructor<T> getDeclaredConstructor(Class<?>... parameterTypes) // 返回一个 Constructor 对象，该对象反映此 Class 对象所表示的类或接口的指定构造方法。
```

###### 代码示例

```java
import java.lang.reflect.*;

public class Test {
    public static void main(String[] args) throws Exception{
        StringBuilder stringBuilder = new StringBuilder();
        Class myClass = Class.forName("java.lang.String");
        stringBuilder.append(Modifier.toString(myClass.getModifiers())+" class "+myClass.getSimpleName()+"{\n");
        Constructor[] constructors = myClass.getDeclaredConstructors();
        for (Constructor constructor:constructors){
            stringBuilder.append("\t");
            stringBuilder.append(Modifier.toString(constructor.getModifiers())+" ");
            stringBuilder.append(constructor.getName()+"(");
            Class[] parameterTypes =  constructor.getParameterTypes();
            for (Class parameterType : parameterTypes){
                stringBuilder.append(parameterType.getSimpleName()+",");
            }
            if(parameterTypes.length > 0){
                stringBuilder.deleteCharAt(stringBuilder.length() - 1);
            }
            stringBuilder.append("){}\n");
        }
        stringBuilder.append("}");
        System.out.println(stringBuilder);
    }
}
```

#### 反射机制调用构造方法实例化java对象。



```java
import java.lang.reflect.Constructor;

public class Test {
    public static void main(String[] args) throws Exception{
        // 不使用反射机制怎么创建对象
        User user1 = new User();
        User user2 = new User("张三",18);
        // 使用反射机制怎么创建对象呢？
        Class myClass = Class.forName("User");
        // 调用无参数构造方法
        Object obj = myClass.newInstance();
        System.out.println(obj);
        // 调用有参数的构造方法怎么办？
        // 第一步：先获取到这个有参数的构造方法
        Constructor constructor1 = myClass.getConstructor(String.class,int.class);
        // 第二步：调用构造方法new对象
        Object newObj1 = constructor1.newInstance("李四",21);
        System.out.println(newObj1);
        // 获取无参数构造方法
        Constructor constructor2 = myClass.getConstructor();
        Object newObj2 = constructor2.newInstance();
        System.out.println(newObj2);
    }
}
```

### 获取这个类的父类，已经实现了哪些接口？

主要方法：

```java
Class<? super T> getSuperclass() // 获取父类。
Class<?>[] getInterfaces() // 确定此对象所表示的类或接口实现的接口。
```

###### 代码示例

```java
public class Test {
    public static void main(String[] args) throws Exception{
        // String举例
        Class strClass = Class.forName("java.lang.String");
        // 获取String的父类
        Class superClass = strClass.getSuperclass();
        System.out.println(superClass.getName()); // java.lang.Object
        // 获取String类实现的所有接口（一个类可以实现多个接口。）
        Class[] interfaces = strClass.getInterfaces();
        for (Class inter : interfaces){
            System.out.println(inter.getName());
        }
    }
}
```

