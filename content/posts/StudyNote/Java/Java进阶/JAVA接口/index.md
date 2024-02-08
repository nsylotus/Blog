---
title: "JAVA接口" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java接口

#### 接口的基础语法

1. 接口也是一种“引用数据类型”。编译之后也是一个class字节码文件。

2. 接口是完全抽象的。（抽象类是半抽象。）或者也可以说接口是特殊的抽象类。

3. 接口怎么定义，语法是什么？

   ```java
   [修饰符列表] interface 接口名{}
   ```

   接口支持多继承，一个接口可以继承多个接口。

4. 接口中只包含两部分内容，一部分是：常量。一部分是：抽象方法。接口中没有其它内容了。只有以上两部分。**接口中只有常量+抽象方法。**

5. 接口中所有的元素都是public修饰的。（都是公开的。）

6. 接口中的抽象方法定义时：public abstract修饰符可以省略。

7. 接口中的方法都是抽象方法，所以接口中的方法不能有方法体。

8. 接口中的常量的public static final可以省略。

9. 接口中方法不能有方法体。

10. 一个非抽象的类，实现接口的时候，必须将接口中所有方法加以实现。

11. 一个类可以实现多个接口。

12. extends和implements可以共存，extends在前，implements在后。

13. 使用接口，写代码的时候，可以使用多态（父类型引用指向子类型对象）。

##### 代码实例

```java
public class SuperStudy {
    public static void main(String[] args) {
        // 访问接口的常量。
        System.out.println(MyMath.PI);// 3.1415926
        // 常量能重新赋值吗?
        //错误: 无法为最终变量PI分配值
        //MyMath.PI = 3.1415928;
    }
}
// 定义接口
interface A{}
// 接口支持继承
interface B extends A{}
// 一个接口可以继承多个接口（支持多继承）
interface C extends A,B{}
// 我的数学接口
interface MyMath{
    // 常量
    // public static final double PI = 3.1415926;
    // 接口中随便写一个变量就是常量。
    // 常量：值不能发生改变的变量。
    // public static final可以省略吗？
    double PI = 3.1415926;
    // 抽象方法
    // public abstract int sum(int a, int b);
    // 接口当中既然都是抽象方法，那么在编写代码的时候，public abstract可以省略吗？
    int sum(int a, int b);
    // 接口中的方法可以有方法体吗？
    // 错误: 接口抽象方法不能带有主体
	/*
	void doSome(){

	}
	*/
    // 相减的抽象方法
    int sub(int a, int b);
}
```

#### 接口与类(面向接口编程)

1. 接口的基础语法：
   	类和类之间叫做继承，类和接口之间叫做实现。
   	别多想：你仍然可以将"实现"看做“继承”。
   	继承使用extends关键字完成。
   	实现使用implements关键字完成。
2. **当一个非抽象的类实现接口的话，必须将接口中所有的抽象方法全部实现（覆盖、重写）。**

##### 代码实例

```java
public class SuperStudy {
    public static void main(String[] args) {
        //错误: MyMath是抽象的; 无法实例化
        //new MyMath();
        
        // 能使用多态吗?可以。
        // 父类型的引用指向子类型的对象
        MyMath mm = new MyMathImpl();
        // 调用接口里面的方法（面向接口编程。）
        int result1 = mm.sum(10, 20);
        System.out.println(result1);

        int result2 = mm.sub(20, 10);
        System.out.println(result2);
    }
}
// 特殊的抽象类，完全抽象的，叫做接口。
interface MyMath{
    double PI = 3.1415926;
    int sum(int a, int b);
    int sub(int a, int b);
}
// 这样没问题
/*
abstract class MyMathImpl implements MyMath {
}
*/

// 编写一个类（这个类是一个“非抽象”的类）
// 这个类的名字是随意的。
//错误: MyMathImpl不是抽象的, 并且未覆盖MyMath中的抽象方法sub(int,int)
/*
class MyMathImpl implements MyMath {
}
*/
//修正
class MyMathImpl implements MyMath {
    //错误：正在尝试分配更低的访问权限; 以前为public
	/*
	int sum(int a, int b){
		return a + b;
	}
	*/

    // 重写/覆盖/实现 接口中的方法（通常叫做实现。）
    public int sum(int a, int b){
        return a + b;
    }

    public int sub(int a, int b){
        return a - b;
    }
}
```

#### 类实现多个接口

1. 接口和接口之间支持多继承，那么一个类可以同时实现多个接口吗？
   	一个类可以同时实现多个接口。
   	这种机制弥补了java中的哪个缺陷？
   		java中类和类只支持单继承。实际上单继承是为了简单而出现的，现实世界中存在多继承，java中的接口弥补了单继承带来的缺陷。接口A和接口B虽然没有继承关系，但是写代码的时候，可以互转。编译器没意见。但是运行时可能出现：ClassCastException
2. 之前有一个结论：
   	无论向上转型还是向下转型，两种类型之间必须要有继承关系，没有继承关系编译器会报错。（这句话不适用在接口方面。）最终实际上和之前还是一样，需要加：instanceof运算符进行判断。向下转型养成好习惯。转型之前先if+instanceof进行判断。

##### 代码实例

```java
public class SuperStudy {
    public static void main(String[] args) {
        // 多态该怎么用呢？
        // 都是父类型引用指向子类型对象
        A a = new D();
        //a.m2(); // 编译报错。A接口中没有m2()方法。
        B b = new D();
        // 这个编译没问题，运行也没问题。
        // 调用其他接口中的方法，你需要转型（接口转型。）
        B b2 = (B)a;
        b2.m2();// m2 ...
        // 直接向下转型为D可以吗？可以
        D d = (D)a;
        d.m2();// m2 ...
        M m = new E();
        // 经过测试：接口和接口之间在进行强制类型转换的时候，没有继承关系，也可以强转。
        // 但是一定要注意，运行时可能会出现ClassCastException异常。
        // 编译没问题，运行有问题。
        // K k = (K)m;
        if(m instanceof K){
            K k = (K)m;// 这个不会运行
        }
    }
}
interface K{}
interface M{}
class E implements M{}

interface X{
}
interface Y{
}
interface Z extends X,Y{ //接口和接口支持多继承。
}

interface A{
    void m1();
}
interface B{
    void m2();
}
// 实现多个接口，其实就类似于多继承。
class D implements A,B{
    @Override
    // 实现A接口的m1()
    public void m1() {
        System.out.println("m1 ...");
    }

    @Override
    // 实现B接口中的m2()
    public void m2() {
        System.out.println("m2 ...");
    }
}
```

#### extends和implements同时出现

1. 继承和实现都存在的话，代码应该怎么写？
   	extends 关键字在前。implements 关键字在后。

```java
public class SuperStudy {
    public static void main(String[] args) {
        // 创建对象（表面看Animal类没起作用！）
        Flyable flyableCat = new Cat();//多态。
        flyableCat.fly();
    }
}
// 动物类：父类
class Animal{
}
// 接口通常提取的是行为动作。
interface Flyable{
    void fly();
}
class Cat extends Animal implements Flyable{
    public void fly(){
        System.out.println("飞猫起飞，翱翔太空的一只猫，很神奇，我想做一只猫！！");
    }
}
// 猪（默认实际上是存在继承的，默认继承Object。）
/*
class Pig extends Object implements Flyable{
}
*/
class Pig implements Flyable{ //没写extends，也是有的，默认继承Object。
    public void fly(){
        System.out.println("我是一只会飞的猪！！！");
    }
}
```

#### 接口在开发中的作用

1. 注意：接口在开发中的作用，类似于多态在开发中的作用。

2. 多态：面向抽象编程，不要面向具体编程。降低程序的耦合度。提高程序的扩展力。

3. 面向抽象编程这句话以后可以修改为：面向接口编程。

4. 面向接口编程，可以降低程序的耦合度，提高程序的扩展力。符合OCP开发原则。

5. 接口的使用离不开多态机制。（接口+多态才可以达到降低耦合度。）

6. 接口可以解耦合，解开的是谁和谁的耦合！！！
   	任何一个接口都有调用者和实现者。
   	接口可以将调用者和实现者解耦合。
   	调用者面向接口调用。
   	实现者面向接口编写实现。

##### 代码实例

FoodMenu

```java
/*
	接口：菜单，抽象的
*/
public interface FoodMenu {
    // 西红柿炒蛋
    void shiZiChaoJiDan();

    // 鱼香肉丝
    void yuXiangRouSi();
}
```

Customer

```java
// 顾客
public class Customer {
    // 顾客手里有一个菜单
    // 记住：以后凡是能够使用 has a 来描述的，统一以属性的方式存在。
    // 实例变量，属性
    // 面向抽象编程，面向接口编程。降低程序的耦合度，提高程序的扩展力。
    private FoodMenu foodMenu;
    public void setFoodMenu(FoodMenu foodMenu){
        this.foodMenu = foodMenu;
    }
    public FoodMenu getFoodMenu(){
        return this.foodMenu;
    }
    public Customer(){

    }
    public Customer(FoodMenu foodMenu){
        this.foodMenu = foodMenu;
    }
    // 提供一个点菜的方法
    public void order(){
        // 先拿到菜单才能点菜
        foodMenu.shiZiChaoJiDan();
        foodMenu.yuXiangRouSi();
    }
}
```

AmericCooker

```java
// 西餐厨师
// 实现菜单上的菜
// 厨师是接口的实现者。
public class AmericCooker implements FoodMenu{
    @Override
    public void shiZiChaoJiDan() {
        System.out.println("西餐师傅做的西红柿炒鸡蛋！");
    }

    @Override
    public void yuXiangRouSi() {
        System.out.println("西餐师傅做的鱼香肉丝！");
    }
}
```

ChinaCooker

```java
// 中餐厨师
// 实现菜单上的菜
// 厨师是接口的实现者。
public class ChinaCooker implements FoodMenu{
    @Override
    public void shiZiChaoJiDan() {
        System.out.println("中餐师傅做的西红柿炒鸡蛋，东北口味！");
    }

    @Override
    public void yuXiangRouSi() {
        System.out.println("中餐师傅做的鱼香肉丝，东北口味！");
    }
}
```

TestStudy

```java
public class TestStudy {
    public static void main(String[] args) {
        FoodMenu foodMenu1 = new AmericCooker();
        FoodMenu foodMenu2 = new ChinaCooker();
        Customer customer1 = new Customer(foodMenu1);
        Customer customer2 = new Customer(foodMenu2);
        customer1.order();
        customer2.order();
    }
}
/*
西餐师傅做的西红柿炒鸡蛋！
西餐师傅做的鱼香肉丝！
中餐师傅做的西红柿炒鸡蛋，东北口味！
中餐师傅做的鱼香肉丝，东北口味！
*/
```

### 抽象类和接口有什么区别？

在这里我们只说一下抽象类和接口在语法上的区别。

1. 抽象类是半抽象的。

2. 接口是完全抽象的。

3. 抽象类中有构造方法。

4. 接口中没有构造方法。

5. 接口和接口之间支持多继承。

6. 类和类之间只能单继承。

7. 一个类可以同时实现多个接口。

8. 一个抽象类只能继承一个类（单继承）。

9. 接口中只允许出现常量和抽象方法。

10. 注意：
    	以后接口使用的比抽象类多。一般抽象类使用的还是少。
    	接口一般都是对“行为”的抽象。
