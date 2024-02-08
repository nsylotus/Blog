---
title: "JAVA泛型" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java泛型

1. 泛型这种语法机制，只在程序编译阶段起作用，只是给编译器参考的。（运行阶段泛型没用！）

2. 使用了泛型好处是什么？
   1. 第一：集合中存储的元素类型统一了。
   2. 第二：从集合中取出的元素类型是泛型指定的类型，不需要进行大量的“向下转型”！
3. 泛型的缺点是什么？
   1. 导致集合中存储的元素缺乏多样性！

###### 代码示例

```java
import java.util.*;

public class Test {
    public static void main(String[] args) {
        /*
        // 不使用泛型机制，分析程序存在缺点
        List myList = new ArrayList();
        // 准备对象
        Cat cat = new Cat();
        Bird bird = new Bird();
        // 将对象添加到集合当中
        myList.add(cat);
        myList.add(bird);
        // 遍历集合，取出每个Animal，让它move
        Iterator iterator = myList.iterator();
        while(iterator.hasNext()) {
            Object obj = iterator.next();
            // obj中没有move方法，无法调用，需要向下转型！
            if(obj instanceof Animal){
                Animal animal = (Animal)obj;
                animal.move();
            }
        }*/
        // 使用泛型List<Animal>之后，表示List集合中只允许存储Animal类型的数据。
        // 用泛型来指定集合中存储的数据类型。
        List<Animal> myList = new ArrayList<Animal>();
        // 指定List集合中只能存储Animal，那么存储String就编译报错了。
        // 这样用了泛型之后，集合中元素的数据类型更加统一了。
        // myList.add("abc");
        Cat cat = new Cat();
        Bird bird = new Bird();
        myList.add(cat);
        myList.add(bird);
        // 获取迭代器
        // 这个表示迭代器迭代的是Animal类型。
        Iterator<Animal> iterator = myList.iterator();
        while (iterator.hasNext()){
            // 使用泛型之后，每一次迭代返回的数据都是Animal类型。
            Animal animal = iterator.next();
            // 这里不需要进行强制类型转换了。直接调用。
            animal.move();

            // 调用子类型特有的方法还是需要向下转换的！
            if(animal instanceof Cat){
                Cat itCat = (Cat) animal;
                itCat.catchMouse();
            }else if(animal instanceof Bird){
                Bird itBird = (Bird)animal;
                itBird.fly();
            }
        }
    }
}
class Animal {
    // 父类自带方法
    public void move(){
        System.out.println("动物在移动！");
    }
}

class Cat extends Animal {
    // 特有方法
    public void catchMouse(){
        System.out.println("猫抓老鼠！");
    }
}

class Bird extends Animal {
    // 特有方法
    public void fly(){
        System.out.println("鸟儿在飞翔！");
    }
}
```

#### 自动类型推断机制

自动类型推断机制。（又称为钻石表达式）

```java
ArrayList<这里的类型会自动推断>();
```

###### 代码示例

```java
import java.util.*;
public class Test {
    public static void main(String[] args) {
        // ArrayList<这里的类型会自动推断>()
        // 自动类型推断，钻石表达式！
        List<String> stringList = new ArrayList<>();
        // 类型不匹配。
        // stringList.add(123);
        stringList.add("Hello");
        stringList.add("Word!!!");
        System.out.println(stringList.size());// 2
        Iterator<String> iterator = stringList.iterator();
        while (iterator.hasNext()){
            // 如果没有使用泛型
            /*Object obj = iterator.next();
            if(obj instanceof String){
                String str = (String)obj;
                System.out.println(str.substring(2));
            }*/
            // 直接通过迭代器获取了String类型的数据
            String str = iterator.next();
            // 直接调用String类的substring方法截取字符串。
            String newString = str.substring(2);
            System.out.println(newString);
        }

    }
}
```

#### 自定义泛型

自定义泛型
自定义泛型的时候，<> 尖括号中的是一个标识符，随便写。java源代码中经常出现的是：<E>和<T>E是Element单词首字母。T是Type单词首字母。

```java
public class Test<标识符随便写> {
    public static void main(String[] args) {
        // new对象的时候指定了泛型是：String类型
        Test<String> stringTest = new Test<>();
        // 类型不匹配
        // stringTest.doSome(100);
        stringTest.doSome("abc");
        Test<Integer> integerTest = new Test<>();
        integerTest.doSome(100);
        // 类型不匹配
        // integerTest.doSome("abc");
        MyIterator<String> stringMyIterator = new MyIterator<>();
        String str = stringMyIterator.get();
        // 不用泛型就是Object类型。
        Test test = new Test();
        test.doSome(new Object());
    }
    public void doSome(标识符随便写 t){
        System.out.println(t);
    }
}
class MyIterator<T>{
    public T get(){
        return null;
    }
}
```

