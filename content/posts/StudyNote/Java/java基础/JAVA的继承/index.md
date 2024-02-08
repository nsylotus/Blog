---
title: "JAVA的继承机制" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 继承

**使用extends关键字**

语法是：

```java
public class 基类{
    
}
public class 派生类 extends 基类{
    
}
```

#### 什么是继承，有什么用？

##### 继承的作用：

基本作用：子类继承父类，代码可以得到复用。（这个不是重要的作用，是基本作用。）

主要(重要)作用：因为有了继承关系，才有了后期的方法覆盖和多态机制。

##### 继承的相关特性

1. B类继承A类，则称A类为超类(superclass)、父类、基类，B类则称为子类(subclass)、派生类、扩展类。

   ```java
   class A{}
   class B extends A{}
   //我们平时聊天说的比较多的是：父类和子类。
   //superclass 父类，subclass 子类
   ```

2. java 中的继承只支持单继承，不支持多继承，C++中支持多继承，这也是 java 体现简单性的一点，换句话说，java 中不允许这样写代码：`class B extends A,C{ }` 这是错误的。

3. 虽然 java 中不支持多继承，但有的时候会产生间接继承的效果，例如：class C extends B，class B extends A，也就是说，C 直接继承 B，其实 C 还间接继承 A。

4. java 中规定，子类继承父类，除**构造方法不能继承**之外，剩下都可以继承。但是**私有的属性无法在子类中直接访问**。(父类中private修饰的不能在子类中直接访问。可以通过间接的手段来访问。**使用父类的setter和getter方法**)

5. java 中的类没有显示的继承任何类，则默认继承Object类，Object类是 java 语言提供的根类（老祖宗类），也就是说，一个对象与生俱来就有Object类型中所有的特征。


##### 继承的缺点，提高了程序的耦合性

继承也存在一些缺点，例如：CreditAccount类继承 Account 类会导致它们之间的耦合度非常高，Account 类发生改变之后会马上影响到 CreditAccount 类

#### 继承使用的问题

1. 子类继承父类之后，能使用子类对象调用父类方法吗？
   	可以，因为子类继承了父类之后，这个方法就属于子类了。当然可以使用子类对象来调用。
2. 在实际开发中，满足什么条件的时候，我可以使用继承呢？
   	凡是采用“is a”能描述的，都可以继承。
   	Cat is a Animal：猫是一个动物
   	Dog is a Animal：狗是一个动物
   	假设以后的开发中有一个A类，有一个B类，A类和B类确实也有重复的代码，那么他们两个之间就可以继承吗？不一定，还是要看一看它们之间是否能够使用is a来描述。
3. 任何一个类，没有显示继承任何类，默认继承Object，那么Object类当中有哪些方法呢？
   	1：你现在能看懂以下代码了吗？对System.out.println的解释
   		System.out.println("Hello World!");
   		System.out 中，out后面没有小括号，说明out是变量名。
   		另外System是一个类名，直接使用类名System.out，说明out是一个静态变量。
   		System.out 返回一个对象，然后采用“对象.”的方式访问println()方法。
   ​	2：Object类中有一个叫做toString()方法的，我们进行了测试，发现：
   ​		System.out.println(引用);
   ​		当直接输出一个“引用”的时候，println()方法会先自动调用“引用.toString()”，然后输出toString()方法的执行结果。
4. 子类继承父类之后，能使用子类对象调用父类方法吗？实际上以上的这个问题问的有点蹊跷！！！！！
   	哪里蹊跷？“能使用子类对象调用父类方法”本质上，子类继承父类之后，是将父类继承过来的方法归为自己所有。实际上调用的也不是父类的方法，是他子类自己的方法（因为已经继承过来了就属于自己的。）。

##### 自己实现一个类似的System.out.println();

JavaStudy

```java
public class JavaStudy {
    static Test test = new Test();
    public static void main(String[] args) {
        // 使用两行调用
        Test t = JavaStudy.test;
        t.dosome();
        // 使用一行调用
        JavaStudy.test.dosome();
        System.out.println(t);//Test@776ec8df,两个结果
        System.out.println(JavaStudy.test.toString());//Test@776ec8df
        /*toString()方法是一个实例方法，需要创建对象才能调用。
        * 776ec8df可以“等同”看做对象在堆内存当中的内存地址。
        * 实际上是内存地址经过“哈希算法”得出的十六进制结果。
        * System.out.println(引用);
        * 当直接输出一个“引用”的时候，println()方法会先自动调用“引用.toString()”，然后输出toString()方法的执行结果。
        * */
    }
}
```

Test

```java
public class Test {
    public void dosome(){
        System.out.println("dosome function");
    }
}
```

### 代码实例

JavaStudy

```java
public class JavaStudy {
    public static void main(String[] args) {
        Account account1 = new Account();
        account1.setId("123456");
        account1.setBalance(500);
        System.out.println(account1.getId()+"的余额是"+account1.getBalance());// 123456的余额是500.0
        Account account2 = new Account("000999",1314);
        System.out.println(account2.getId()+"的余额是"+account2.getBalance());// 000999的余额是1314.0
        CreditAccount creditAccount1 = new CreditAccount("666777",521,100);
        System.out.println(creditAccount1.getId()+"的余额是"+creditAccount1.getBalance()+"其信用为"+creditAccount1.getCredit());// 666777的余额是521.0其信用为100.0
        CreditAccount creditAccount2 = new CreditAccount();
        creditAccount2.setId("555666");
        creditAccount2.setBalance(520);
        creditAccount2.setCredit(88);
        System.out.println(creditAccount2.getId()+"的余额是"+creditAccount2.getBalance()+"其信用为"+creditAccount2.getCredit());// 555666的余额是520.0其信用为88.0
        creditAccount1.showAccountId();// 666777
    }
}
```

Account

```java
public class Account {
    private String id;
    private double balance;
    public Account(){

    }
    public Account(String id,double balance){
        this.id=id;
        this.balance=balance;
    }
    public void setId(String id){
        this.id=id;
    }
    public String getId(){
        return this.id;
    }
    public void setBalance(double balance){
        this.balance=balance;
    }
    public double getBalance(){
        return this.balance;
    }
}
```

CreditAccount

```java
public class CreditAccount extends Account{
    private double credit;
    public CreditAccount(){

    }
    public CreditAccount(String id,double balance,double credit){
        this.setId(id);
        this.setBalance(balance);
        this.credit=credit;
    }
    public void setCredit(double credit){
        this.credit = credit;
    }
    public double getCredit(){
        return this.credit;
    }
    public void showAccountId(){
        // 错误: id 在 Account 中是 private 访问控制
        // System.out.println(id);
        // 间接访问
        // System.out.println(getId());
        System.out.println(this.getId());
    }
}
```
