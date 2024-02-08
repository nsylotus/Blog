---
title: "JAVA方法的重写" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 方法的重写

#### 回顾一下方法重载！！！！

1. 什么时候考虑使用方法重载overload？
   	当在一个类当中，如果功能相似的话，建议将名字定义的一样，这样代码美观，并且方便编程。
2. 什么条件满足之后能够构成方法重载overload？
   ​	条件一：在同一个类当中
   ​	条件二：方法名相同
   ​	条件三：参数列表不同（个数、顺序、类型）

#### 方法覆盖

1. 方法覆盖又叫做：
   	方法重写（重新编写），英语单词叫做：Override、Overwrite，都可以。
   	比较常见的：方法覆盖、方法重写、override
2. 什么时候考虑使用方法覆盖？
   ​	父类中的方法无法满足子类的业务需求，子类有必要对继承过来的方法进行覆盖。
   ​	子类有权利对这个方法进行重新编写，有必要进行“方法的覆盖”。
3. 什么条件满足的时候构成方法覆盖？
   ​	条件一：两个类必须要有继承关系。
   ​	条件二：重写之后的方法和之前的方法具有：
   ​					相同的返回值类型、
   ​					相同的方法名、
   ​					相同的形式参数列表。
   ​	条件三：访问权限不能更低，可以更高。（这个先记住。）
   ​	条件四：重写之后的方法不能比之前的方法抛出更多的异常，可以更少。（这个先记住）

##### 重要结论：
​	当子类对父类继承过来的方法进行“方法覆盖”之后，
​	子类对象调用该方法的时候，一定执行覆盖之后的方法。

##### 这里还有几个注意事项：（与多态语法有关）
​	注意1：方法覆盖只是针对于方法，和属性无关。
​	注意2：私有方法无法覆盖。
​	注意3：构造方法不能被继承，所以构造方法也不能被覆盖。
​	注意4：方法覆盖只是针对于“实例方法”，“静态方法覆盖”没有意义。

##### 方法重载和方法覆盖有什么区别？

1. ​	方法重载发生在同一个类当中。

2. ​	方法覆盖是发生在具有继承关系的父子类之间。

3. ​	方法重载是一个类中，方法名相同，参数列表不同。

4. ​	方法覆盖是具有继承关系的父子类，并且重写之后的方法必须和之前的方法一致：
5. ​	方法名一致、参数列表一致、返回值类型一致。

#### 代码实例

JavaStudy

```java
public class JavaStudy {
    public static void main(String[] args) {
        ChinaPeople chinaPeople = new ChinaPeople();
        AmericPeople americPeople = new AmericPeople();
        chinaPeople.setName("张三");
        americPeople.setName("Join");
        chinaPeople.speak();
        americPeople.speak();
    }
}
```

People

```java
public class People {
    private String name;
    public People(){

    }
    public People(String name){
        this.name = name;
    }
    public void setName(String name){
        this.name = name;
    }
    public String getName(){
        return this.name;
    }
    public void speak(){
        System.out.println(this.name+"会说话");
    }
}
```

ChinaPeople

```java
public class ChinaPeople extends People{
    private static String country = "China";
    public ChinaPeople(){

    }
    public void speak(){
        System.out.println(ChinaPeople.country+"人"+this.getName()+"会说中文");
    }
}
```

AmericPeople

```java
public class AmericPeople extends People{
    static String country = "Americ";
    public AmericPeople(){

    }
    public void speak(){
        System.out.println(AmericPeople.country+"人"+this.getName()+"speak english");
    }
}
```

#### 方法的覆盖与方法的重写案例

```java
public class OverrideTest02{
	public static void main(String[] args){
		Bird b = new Bird();
		b.move();
		b.sing(1000); //Animal sing....

		Cat c = new Cat();
		c.move();
	}
}

class Animal{
	public void move(){
		System.out.println("动物在移动！");
	}

	public void sing(int i){
		System.out.println("Animal sing....");
	}
}

class Bird extends Animal{

	// 对move方法进行方法覆盖，方法重写，override
	// 最好将父类中的方法原封不动的复制过来。（不建议手动编写）
	// 方法覆盖，就是将继承过来的那个方法给覆盖掉了。继承过来的方法没了。
	public void move(){
		System.out.println("鸟儿在飞翔！！！");
	}

	//protected表示受保护的。没有public开放。
	// 错误：正在尝试分配更低的访问权限; 以前为public
	/*
	protected void move(){
		System.out.println("鸟儿在飞翔！！！");
	}
	*/

	//错误：被覆盖的方法未抛出Exception
	/*
	public void move() throws Exception{
		System.out.println("鸟儿在飞翔！！！");
	}
	*/

	// 分析：这个sing()和父类中的sing(int i)有没有构成方法覆盖呢？
	// 没有，原因是，这两个方法根本就是两个完全不同的方法。
	// 可以说这两个方法构成了方法重载吗？可以。
	public void sing(){
		System.out.println("Bird sing.....");
	}
}

class Cat extends Animal{

	// 方法重写
	public void move(){
		System.out.println("猫在走猫步！！！");
	}
}
```

#### 关于Object类中toString()方法的覆盖？

1. ​	toString()方法存在的作用就是：将java对象转换成字符串形式。
   ​	大多数的java类toString()方法都是需要覆盖的。因为Object类中提供的toString()方法输出的是一个java对象的内存地址。

2. ​	Object类中toString()方法的默认实现是什么？

   ```java
   public String toString() {
   	return getClass().getName() + "@" + Integer.toHexString(hashCode());
   }
   // toString: 方法名的意思是转换成String
   // 含义：调用一个java对象的toString()方法就可以将该java对象转换成字符串的表示形式。
   ```

   ###### 对toString方法进行重写

```java
public class JavaStudy {
    public static void main(String[] args) {
        MyDate myDate1 = new MyDate();
        System.out.println(myDate1);
        MyDate myDate2 = new MyDate(2021,5,21);
        System.out.println(myDate2.toString());
    }
}
class MyDate extends Object{
    private int year;
    private int month;
    private int day;
    public MyDate(){
        this(2021,9,21);
    }
    public MyDate(int year,int month,int day){
        this.year = year;
        this.month = month;
        this.day = day;
    }
    public void setYear(int year){
        this.year = year;
    }
    public int getYear(){
        return this.year;
    }
    public void setMonth(int month){
        this.month = month;
    }
    public int getMonth(){
        return this.month;
    }
    public void setDay(int day){
        this.day = day;
    }
    public int getDay(){
        return this.day;
    }
    // 从Object类中继承过来的那个toString()方法已经无法满足我业务需求了。
    // 我在子类MyDate中有必要对父类的toString()方法进行覆盖/重写。
    // 我的业务要求是：调用toString()方法进行字符串转换的时候，
    // 希望转换的结果是：xxxx年xx月xx日，这种格式。
    // 重写一定要复制粘贴，不要手动编写，会错的。
    public String toString(){
        return this.getYear()+"年"+this.getMonth()+"月"+this.getDay()+"日";
    }
}
```
