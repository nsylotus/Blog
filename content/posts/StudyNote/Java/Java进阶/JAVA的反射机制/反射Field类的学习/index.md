---
title: "JAVA反射Field类的学习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---


### 反射Field类的学习

##### 反射属性Field

Field翻译为字段，其实就是属性/成员，每一个属性相当于一个Field对象。

Field的常用方法：

```java
int getModifiers() // 获取属性的修饰符列表，但是返回的是一个整数，需要使用Modifier类的toString方法进行转化。
String getSimpleName() // 返回源代码中给出的底层类的简称。
Field[] getDeclaredFields() // 获取所有的Field
Field[] getFields() // 获取类中所有的public修饰的Field
Field getDeclaredField(String name) // 返回一个 Field 对象，该对象反映此 Class 对象所表示的类或接口的指定已声明字段。
String getName() // 获取全类名
String getSimpleName() // 获取简类名
Class<?> getType() // 获取属性的类型
void setAccessible(boolean flag) // 将此对象的 accessible 标志设置为指示的布尔值，修改对象的属性的访问控制权限。
```

Modifier类的常用方法：

```java
static String toString(int mod) // 将getModifiers方法返回的数字转化为相对应的字符串。
```

###### 代码示例

```java
import java.lang.reflect.*;

public class Test {
    public static void main(String[] args) throws Exception{
        Class myClass = Class.forName("User");
        String className = myClass.getName();
        System.out.println("完整类名：" + className);// 完整类名：java.lang.String
        String simpleName = myClass.getSimpleName();
        System.out.println("简类名：" + simpleName);// 简类名：String
        // 获取类中所有的public修饰的Field
        Field[] fields = myClass.getFields();
        System.out.println(fields.length); // 测试数组中只有2个元素
        // 取出这个Field
        Field field = fields[0];
        String fieldName = field.getName();
        System.out.println(fieldName);
        // 获取所有的Field
        Field[] fs = myClass.getDeclaredFields();
        System.out.println(fs.length); // 5
        for (Field f : fs){
            // 获取属性的修饰符列表
            int i = f.getModifiers(); // 返回的修饰符是一个数字，每个数字是修饰符的代号！！！
            System.out.println(i);
            // 可以将这个“代号”数字转换成“字符串”吗？
            String modifierString = Modifier.toString(i);
            System.out.println(modifierString);
            // 获取属性的类型
            Class fieldType = f.getType();
            String fieldTypeSimpleName = fieldType.getSimpleName();
            System.out.println(fieldTypeSimpleName);
            // 获取属性的名字
            String fn = f.getName();
            System.out.println(fn);
        }
    }
}
```

##### 通过反射机制，反编译一个类的属性Field

```java
import java.lang.reflect.*;
// 通过反射机制，反编译一个类的属性Field
public class Test {
    public static void main(String[] args) throws Exception{
        // 创建这个是为了拼接字符串。
        StringBuilder stringBuilder = new StringBuilder();
        Class myClass = Class.forName("java.lang.String");
        stringBuilder.append(Modifier.toString(myClass.getModifiers())+" class "+myClass.getSimpleName()+"{\n");
        Field[] fields = myClass.getDeclaredFields();
        for (Field field:fields){
            stringBuilder.append("\t");
            stringBuilder.append(Modifier.toString(myClass.getModifiers())+" ");
            stringBuilder.append(field.getType().getSimpleName()+" ");
            stringBuilder.append(field.getName()+"\n");
        }
        stringBuilder.append("}");
        System.out.println(stringBuilder);
    }
}
```

##### 通过反射机制访问一个java对象的属性

给属性赋值set，获取属性的值get。

给对象属性赋值的三要素：

1. 赋值的对象
2. 对象的属性
3. 要赋的值

读对象属性的二要素：

1. 获取对象
2. 使用该对象获取值

```java
import java.lang.reflect.*;

public class Test {
    public static void main(String[] args) throws Exception{
        // 不使用反射机制，怎么去访问一个对象的属性呢？
        User user = new User();
        // 给属性赋值
        user.no = 123; //三要素：给s对象的no属性赋值123，要素1：对象user，要素2：no属性，要素3：1111
        // 读属性值
        // 两个要素：获取user对象的no属性的值。
        System.out.println(user.no);

        // 使用反射机制，怎么去访问一个对象的属性。（set get）
        Class myClass = Class.forName("User");
        Object obj = myClass.newInstance();// obj就是User对象。（底层调用无参数构造方法）
        // 获取no属性（根据属性的名称来获取Field）
        Field noFiled = myClass.getDeclaredField("no");
        // 给obj对象(Student对象)的no属性赋值
        /*
        虽然使用了反射机制，但是三要素还是缺一不可：
            要素1：obj对象
            要素2：no属性
            要素3：666值
        注意：反射机制让代码复杂了，但是为了一个“灵活”，这也是值得的。
         */
        noFiled.set(obj,666);
        // 读取属性的值
        // 两个要素：获取obj对象的no属性的值。
        System.out.println(noFiled.get(obj));

        // 可以访问私有的属性吗？
        Field nameField = myClass.getDeclaredField("name");

        // 打破封装（反射机制的缺点：打破封装，可能会给不法分子留下机会！！！）
        // 这样设置完之后，在外部也是可以访问private的。
        nameField.setAccessible(true);

        // 给name属性赋值
        nameField.set(obj, "jackson");
        // 获取name属性的值
        System.out.println(nameField.get(obj));
    }
}
```



