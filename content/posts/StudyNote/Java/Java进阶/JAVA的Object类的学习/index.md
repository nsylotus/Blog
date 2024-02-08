---
title: "JAVA中Object类的学习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Object类的学习

只需要知道这几个方法即可：

```java
protected Object clone()   // 负责对象克隆的。
int hashCode()	// 获取对象哈希值的一个方法。
boolean equals(Object obj)  // 判断两个对象是否相等
String toString()  // 将对象转换成字符串形式
protected void finalize()  // 垃圾回收器负责调用的方法
```

#### toString()方法

1. 以后所有类的toString()方法是需要重写的。

2. 重写规则，越简单越明了就好。

3. System.out.println(引用); 这里会自动调用“引用”的toString()方法。

4. 源代码长什么样？

   ```java
   public String toString() {
   	return this.getClass().getName() + "@" + Integer.toHexString(hashCode());
   }
   ```

5. toString()方法的作用是什么？
   	toString()方法的设计目的是：通过调用这个方法可以将一个“java对象”转换成“字符串表示形式”

6. String类是SUN写的，在String类中toString方法已经重写了。

#### equals()方法

1. 以后所有类的equals方法也需要重写，因为Object中的equals方法比较的是两个对象的内存地址，我们应该比较内容，所以需要重写。

2. 重写规则：自己定，主要看是什么和什么相等时表示**两个对象相等**。

3. 基本数据类型比较使用：==

4. 对象和对象比较：调用equals方法（引用数据类型之间的比较）

5. String类是SUN编写的，所以String类的equals方法重写了。

6. 以后判断两个字符串是否相等，不能使用==，要调用字符串对象的equals方法。因为字符串是一个对象。

7. equals方法是判断两个对象是否相等的。
   	判断两个java对象是否相等，不能使用“==”，因为“==”比较的是两个对象的内存地址。

8. 注意：**重写equals方法的时候要彻底。**

9. equals方法的源代码

   ```java
   public boolean equals(Object obj) {
   	return (this == obj);
   }
   ```

10. 在Object类中的equals方法当中，默认采用的是“==”判断两个java对象是否相等。而“==”判断的是两个java对象的内存地址，我们应该判断两个java对象的内容是否相等。所以老祖宗的equals方法不够用，需要子类重写equals。

11. java中基本数据类型比较是否相等，使用==

12. java中所有的引用数据类型统一使用equals方法来判断是否相等。

##### 代码实例1

```java
public class SuperStudy {
    public static void main(String[] args) {
        int num1 = 100;
        int num2 = 100;
        System.out.println(num1 == num2);// true
        Mytime mytime1 = new Mytime(2008,8,8);
        System.out.println(mytime1);// 2008年8月8日
        Mytime mytime2 = new Mytime(2008 ,8,8);
        System.out.println(mytime1 == mytime2);// false
        // true(重写equals方法之后,如果不重写equals方法则比较的是对象之间的内存地址,则与上面的结果相同)
        System.out.println(mytime1.equals(mytime2));
        Mytime mytime3 = new Mytime(2008,8,9);
        System.out.println(mytime1.equals(mytime3));// false
        Mytime mytime4 = null;
        System.out.println(mytime1.equals(mytime4));// false
    }
}
class Mytime extends Object{
    private int year;
    private int month;
    private int day;
    public void setYear(int day){this.day = day;}
    public void setMonth(int month){this.month = month;}
    public void setDay(int day){this.day = day;}
    public int getYear(){return this.year;}
    public int getMonth(){return  this.month;}
    public int getDay(){return this.day;}
    public Mytime(){super();}
    public Mytime(int year,int month,int day){
        super();
        this.year = year;
        this.month = month;
        this.day = day;
    }
    public boolean equals(Object obj) {
        if(obj == null || ! (obj instanceof Mytime)){
            return false;
        }
        if(this == obj){
            return true;
        }
        if(obj instanceof Mytime){
            Mytime mytime = (Mytime) obj;
            if(this.getYear() == mytime.getYear() && this.getMonth() == mytime.getMonth() && this.getDay() == mytime.getDay()){
                return true;
            }
        }
        return false;
    }
    @Override
    public String toString() {
        return this.year+"年"+this.month+"月"+this.day+"日";
    }
}
```

##### 代码实例1

```java
public class SuperStudy {
    public static void main(String[] args) {
        User user1 = new User("张三",new Address("北京","大兴区","11111"));
        User user2 = new User("张三",new Address("北京","大兴区","11111"));
        System.out.println(user1.equals(user2));
        System.out.println(user1);
    }
}
class User{
    private String name;
    private Address addr;
    public User(){super();}
    public User(String name, Address address){super();this.name = name;this.addr = address;}
    public void setName(String name){this.name = name;}
    public void setAddr(Address address){this.addr = address;}
    public String getName(){return this.name;}
    public Address getAddr(){return this.addr;}

    @Override
    public boolean equals(Object obj) {
        if(obj == null || ! (obj instanceof User)){return false;}
        if(this == obj){return true;}
        if(obj instanceof User){
            User user =(User)obj;
            return this.getName().equals(user.getName()) && this.getAddr().equals(user.getAddr());
        }
        return false;
    }

    @Override
    public String toString() {
        return "姓名:"+this.getName()+"\n地址=\t"+this.getAddr();
    }
}
class Address{
    private String city;
    private String street;
    private String zipcode;
    public Address(){super();}
    public Address(String city,String street, String zipcode){
        super();
        this.city = city;
        this.street = street;
        this.zipcode = zipcode;
    }
    public void setCity(String city){this.city = city;}
    public void setStreet(String street){this.street = street;}
    public void setZipcode(String zipcode){this.zipcode = zipcode;}
    public String getCity(){return this.city;}
    public String getStreet(){return this.street;}
    public String getZipcode(){return this.zipcode;}

    @Override
    public String toString() {
        return "城市:"+this.getCity()+"\t街道:"+this.getStreet()+"\t门牌号:"+this.getZipcode();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj == null || ! (obj instanceof Address)){return false;}
        if(this == obj){return true;}
        if(obj instanceof Address){
            Address address = (Address) obj;
            return this.getCity().equals(address.getCity()) && this.getStreet().equals(address.getStreet()) && this.getZipcode().equals(address.getZipcode());
        }
        return false;
    }

}
```

#### finalize()方法。

1. 这个方法是protected修饰的，在Object类中这个方法的源代码是？	

   ```java
   protected void finalize() throws Throwable {}
   ```

2. finalize()方法只有一个方法体，里面没有代码。

3. GC：负责调用finalize()方法。

4. 这个方法不需要程序员手动调用，JVM的垃圾回收器负责调用这个方法。不像equals toString，equals和toString()方法是需要你写代码调用的。finalize()只需要重写，重写完将来自动会有程序来调用。

5. 调用finalize()方法被成为一个时机，这个时机是垃圾回收时机。

6. finalize()方法的执行时机：
   	当一个java对象即将被垃圾回收器回收的时候，垃圾回收器负责调用finalize()方法。

##### 代码实例

```java
public class SuperStudy {
    public static void main(String[] args) {
        for (int i=0;i<100;i++){
            Person person = new Person();
            person = null;// 将person对象变成垃圾
            System.gc();// 建议启动垃圾回收器。（只是建议，可能不启动，也可能启动。启动的概率高了一些。）
        }
    }
}
class Person{
    // Person类型的对象被垃圾回收器回收的时候，垃圾回收器负责调用：person.finalize();
    protected void finalize() throws Throwable{
        System.out.println(this+"即将被销毁!");
    }
}
```

#### hashCode()方法

1. 在Object中的hashCode方法是怎样的？

   ```java
   public native int hashCode();
   ```

   ​	这个方法不是抽象方法，带有native关键字，底层调用C++程序。

2. hashCode()方法返回的是哈希码：
   	实际上就是一个java对象的内存地址，经过哈希算法，得出的一个值。
   	所以hashCode()方法的执行结果可以等同看做一个java对象的内存地址。

```java
public class SuperStudy {
    public static void main(String[] args) {
        MyClass myClass = new MyClass();
        System.out.println(myClass.hashCode());// 2003749087
    }
}
class MyClass{}
```

#### 匿名内部类

```java
public class SuperStudy {
    public static void main(String[] args) {
        // 创建数学对象
        Mymath mymath = new Mymath();
        ComputerImp computerImp = new ComputerImp();
        mymath.mysum(computerImp,100,200);
        // 创建一个无名的对象区调用这个类实现的sum方法
        mymath.mysum(new ComputerImp(),200,300);
        // 去new接口在其后面加上{}在{}中写接口抽象方法的实现，这就是匿名内部类.
        mymath.mysum(new Computer() {
            @Override
            public int sum(int num1, int num2) {
                return num1+num2;
            }
        },300,400);
    }
}
// 负责计算的接口
interface Computer{
    // 抽象的方法
    int sum(int num1 ,int num2);
}
// 写一个类实现其接口
class ComputerImp implements Computer{
    // 对抽象方法的实现
    public int sum(int num1, int num2){
        return num1+num2;
    }
}
class Mymath{
    // 数学的求和方法
    public void mysum(Computer computer ,int num1 ,int num2){
        int retValue = computer.sum(num1,num2);
        System.out.println(num1+"+"+num2+"="+retValue);
    }
}
```
