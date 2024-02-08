---
title: "JAVA注解" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 注解

1. 注解，或者叫做注释类型，英文单词是：Annotation

2. 注解的本质就是一个Annotation接口

3. 注解中其实是可以有属性和方法，但是接口中的属性都是static final的，对于注解来说没什么意义，而我们定义接口的方法就相当于注解的属性，为什么注解只有属性成员变量，其实他就是接口的方法，这就是为什么成员变量会有括号。

4. 注解Annotation是一种引用数据类型。编译之后也是生成xxx.class文件。

5. 怎么自定义注解呢？语法格式？

   ```java
   [修饰符列表] @interface 注解类型名{}
   ```

6. 注解怎么使用，用在什么地方？

   1. 默认情况下，注解可以出现在任意位置。
   2. 第一：注解使用时的语法格式是：@注解类型名
   3. 第二：注解可以出现在类上、属性上、方法上、变量上等....
   4. 注解还可以出现在注解类型上。

7. JDK内置了哪些注解呢？

   1. java.lang包下的注释类型：
      1. Deprecated用@Deprecated注释的程序元素，不鼓励程序员使用这样的元素，通常是因为它很危险或存在更好的选择。已过时。在IDEA中会出现横线。 有更好的解决方案存在。
      
      2. Override表示一个方法声明打算重写超类中的另一个方法声明。 @Override这个注解只能注解方法。@Override这个注解是给编译器参考的，和运行阶段没有关系。
      
         凡是java中的方法带有这个注解的，编译器都会进行编译检查，如果这个方法不是重写父类的方法，编译器报错。
      
         ```java
         @Target(ElementType.METHOD)
         @Retention(RetentionPolicy.SOURCE)
         public @interface Override {
         }
         ```
      
         标识性注解，给编译器做参考的。
      
         编译器看到方法上有这个注解的时候，编译器会自动检查该方法是否重写了父类的方法。
      
         如果没有重写，报错。
      
         这个注解只是在编译阶段起作用，和运行期无关！
      
      3. SuppressWarnings指示应该在注释元素（以及包含在该注释元素中的所有程序元素）中取消显示指定的编译器警告。 

8. 元注解

   1. 什么是元注解？用来标注“注解类型”的“注解”，称为元注解。

9. 如果一个注解当中有属性，那么必须给属性赋值。（除非该属性使用default指定了默认值。）

10. 给注解赋值的语法：

   ```java
   @注解的名字(属性名=属性值,属性名=属性值,属性名=属性值)
   ```

   ###### 代码示例

   ```java
   public class Test {
       @MyAnnotation(name = "王五",addr = {"上海,北极"}) // 如果一个注解当中有属性，那么必须给属性赋值。（除非该属性使用default指定了默认值。）
       public static void main(String[] args) {
   
       }
       // 如果一个注解的属性的名字是value，并且只有一个属性的话，在使用的时候，该属性名可以省略。如果不是value的话不可以省略。
       // @OtherAnnotation("")或者@OtherAnnotation(value = "")
       public void doSome(){}
   }
   /**
    * 自定义注解：MyAnnotation
    * 在注解当中可以定义属性，以下这个是MyAnnotation的name属性。
    * 看着像1个方法，但实际上我们称之为属性name。
    */
   @interface MyAnnotation{
       String name() default "张三"; // 属性指定默认值
       String[] addr();
   }
   // 如果一个注解当中有属性，那么必须给属性赋值。（除非该属性使用default指定了默认值。）
   @MyAnnotation(name = "李四",addr = {"上海,北极"}) // 注解修饰注解。给注解赋值。
   // 数组是大括号,如果数组中只有1个元素：大括号可以省略。
   @interface OtherAnnotation{
       String value();
   }
   ```

11. 如果一个注解的属性的名字是value，并且只有一个属性的话，在使用的时候，该属性名可以省略。

12. 常见的元注解有哪些？

   13. Target

   14. Retention

15. 关于Target注解：

    这是一个元注解，用来标注“注解类型”的“注解”，这个Target注解用来标注“被标注的注解”可以出现在哪些位置上。

    @Target(ElementType.METHOD)：表示“被标注的注解”只能出现在方法上。

    @Target(value={CONSTRUCTOR, FIELD, LOCAL_VARIABLE, METHOD, PACKAGE, MODULE, PARAMETER, TYPE})

    表示该注解可以出现在：构造方法上，字段上，局部变量上，方法上，....，类上...

    @Target({ElementType.TYPE, ElementType.METHOD})：只允许该注解可以标注类、方法

16. 关于Retention注解：

    这是一个元注解，用来标注“注解类型”的“注解”，这个Retention注解用来标注“被标注的注解”最终保存在哪里。

    @Retention(RetentionPolicy.SOURCE)：表示该注解只被保留在java源文件中。

    @Retention(RetentionPolicy.CLASS)：表示该注解被保存在class文件中。

    @Retention(RetentionPolicy.RUNTIME)：表示该注解被保存在class文件中，并且可以被反射机制所读取。

17. Retention的源代码

    ```java
    @Documented // 元注解
    @Retention(RetentionPolicy.RUNTIME) // 元注解
    @Target(ElementType.ANNOTATION_TYPE) // 元注解
    public @interface Retention {
        // 属性
        RetentionPolicy value();
    }
    ```

18. RetentionPolicy的源代码：

    ```java
    public enum RetentionPolicy {
        SOURCE,
        CLASS,
        RUNTIME
    }
    ```

19. Target的源代码：

    ```java
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.ANNOTATION_TYPE)
    public @interface Target {
        ElementType[] value();
    }
    ```

20. 注解当中的属性可以是哪一种类型？

    属性的类型可以是：byte short int long float double boolean char String Class 枚举类型，以及以上每一种的数组形式。

### 反射机制使用注解

常用方法：

```java
boolean isAnnotationPresent(Class<? extends Annotation> annotationClass) // 判断类上面是否有某个类型的注解。
<A extends Annotation> A getAnnotation(Class<A> annotationClass) // 如果存在该元素的指定类型的注释，则返回这些注释，否则返回 null。 
Method getDeclaredMethod(String name, Class<?>... parameterTypes) // 返回一个 Method 对象，该对象反映此 Class 对象所表示的类或接口的指定已声明方法。
```

###### 代码示例

```java
import java.lang.annotation.*;
import java.lang.reflect.Method;

public class Test {
    public static void main(String[] args) throws Exception{
        // 获取这个类
        Class myClass = Class.forName("MyAnn");
        // 判断类上面是否有@MyAnnotation
        System.out.println(myClass.isAnnotationPresent(MyAnnotation.class));// true
        // 获取doSome()方法
        Method doSomeMethod = myClass.getDeclaredMethod("doSome");
        if(myClass.isAnnotationPresent(MyAnnotation.class)){
            // 获取该注解对象
            MyAnnotation myAnnotation = (MyAnnotation) myClass.getAnnotation(MyAnnotation.class);
            System.out.println("类上面的注解对象:" + myAnnotation); // 类上面的注解对象:@MyAnnotation("\u5357\u6781")
            // 获取注解对象的属性怎么办？和调接口没区别。
            String name = myAnnotation.name();
            System.out.println(name); // 南极
        }
        // 判断该方法上是否存在这个注解
        if(doSomeMethod.isAnnotationPresent(MyAnnotation.class)){
            MyAnnotation doMyAnn = doSomeMethod.getAnnotation(MyAnnotation.class);
            System.out.println(doMyAnn.name());// 北极
        }
    }
}
// 只允许该注解可以标注类、方法
@Target({ElementType.TYPE, ElementType.METHOD})
// 希望这个注解可以被反射
@Retention(RetentionPolicy.RUNTIME)
@interface MyAnnotation{
    // value属性。
    String name() default "北极";
}
@MyAnnotation(name = "南极")
class MyAnn{
    // @MyAnnotation
    int i;
    // @MyAnnotation
    public MyAnn() {}
    @MyAnnotation
    public void doSome(){
        // @MyAnnotation
        int i;
    }
}
```

#### 注解在开发中有什么用呢？

需求：

假设有这样一个注解，叫做：@Id，这个注解只能出现在类上面，当这个类上有这个注解的时候，要求这个类中必须有一个int类型的id属性。如果没有这个属性就报异常。如果有这个属性则正常执行！

```java
import java.lang.annotation.*;
import java.lang.reflect.Field;

public class Test {
    public static void main(String[] args) throws Exception{
        // 获取类
        Class userClass = Class.forName("User");
        // 判断类上是否存在Id注解
        if(userClass.isAnnotationPresent(MustHasIdPropertyAnnotation.class)){
            // 当一个类上面有@MustHasIdPropertyAnnotation注解的时候，要求类中必须存在int类型的id属性
            // 如果没有int类型的id属性则报异常。
            // 获取类的属性
            Field[] fields = userClass.getDeclaredFields();
            boolean isOk = false; // 给一个默认的标记
            for (Field field : fields){
                if("id".equals(field.getName()) && "int".equals(field.getType().getSimpleName())){
                    // 表示这个类是合法的类。有@Id注解，则这个类中必须有int类型的id
                    isOk = true; // 表示合法
                    break;
                }
            }
            // 判断是否合法
            if(!isOk){
                throw new HasNotIdPropertyException("被@MustHasIdPropertyAnnotation注解标注的类中必须要有一个int类型的id属性！");
            }
        }
    }
}
@MustHasIdPropertyAnnotation
class User{
    int id;
    String name;
    String password;
}
// 表示这个注解只能出现在类上面
@Target(ElementType.TYPE)
// 该注解可以被反射机制读取到
@Retention(RetentionPolicy.RUNTIME)
@interface MustHasIdPropertyAnnotation{
// 这个注解@MustHasIdPropertyAnnotation用来标注类，被标注的类中必须有一个int类型的id属性，没有就报异常。
}
// 自定义异常
class HasNotIdPropertyException extends RuntimeException {
    public HasNotIdPropertyException(){

    }
    public HasNotIdPropertyException(String s){
        super(s);
    }
}
```
