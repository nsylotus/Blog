---
title: "Java自定义异常" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 自定义异常

1. Java中怎么自定义异常呢？

   1. 两步：

      1. 第一步：编写一个类继承Exception或者RuntimeException.
      2. 第二步：提供两个构造方法，一个无参数的，一个带有String参数的。

   2. ###### 代码示例

   ```java
   public class Test {
       public static void main(String[] args) {
           // 创建异常对象（只new了异常对象，并没有手动抛出）
           MyException e = new MyException("用户名不能为空！");
   
           // 打印异常堆栈信息
           e.printStackTrace();
   
           // 获取异常简单描述信息
           String msg = e.getMessage();
           System.out.println(msg);
       }
   }
   class MyException extends Exception{
       public MyException(){}
       public MyException(String s){
           super(s);
       }
   }
   /*
   class MyException extends RuntimeException{ // 运行时异常
   
   }
   */
   ```


#### 数组示例

使用异常模拟栈的操作。

```java
public class Test {
    public static void main(String[] args) {
        MyStack myStack = new MyStack();
        try {
            myStack.push(new Object());
        } catch (MyStackOperationException e) {
            e.printStackTrace();
        }
        try {
            myStack.push(new Object());
        } catch (MyStackOperationException e) {
            e.printStackTrace();
        }
        try {
            System.out.println(myStack.pop());
        } catch (MyStackOperationException e) {
            e.printStackTrace();
        }
    }
}
class MyStack{
    // 为什么选择Object类型数组？因为这个栈可以存储java中的任何引用类型的数据,因为所有类的父类是Object。
    // 包括String也可以存储进去。因为String父类也是Object。
    // 一维数组动态初始化,默认初始化容量是10.
    private Object[] elements = new Object[10];
    // 栈帧，永远指向栈顶部元素
    // 那么这个默认初始值应该是多少。注意：最初的栈是空的，一个元素都没有。
    // private int index = 0; // 如果index采用0，表示栈帧指向了顶部元素的上方。
    // private int index = -1; // 如果index采用-1，表示栈帧指向了顶部元素。
    // 给index初始化
    private int index = -1;
    public void push(Object obj) throws MyStackOperationException{
        if(this.index >= this.elements.length-1){
            // System.out.println("压栈失败，栈已满！");
            // return;

            // 创建异常对象
            //MyStackOperationException e = new MyStackOperationException("压栈失败，栈已满！");
            // 手动将异常抛出去！
            //throw e; //这里捕捉没有意义，自己new一个异常，自己捉，没有意义。栈已满这个信息你需要传递出去。

            // 合并（手动抛出异常！）
            throw new MyStackOperationException("压栈失败，栈已满！");
        }
        // 程序能够走到这里，说明栈没满
        // 向栈中加1个元素，栈帧向上移动一个位置。
        this.elements[++index] = obj;
        // 在声明一次:所有的System.out.println()方法执行时，如果输出引用的话，自动调用引用的toString()方法。
        System.out.println("压栈" + obj + "元素成功，栈帧指向" + index);
    }
    public Object pop() throws MyStackOperationException{
        if(this.index < 0){
            // System.out.println("弹栈失败，栈已空！");
            // return null;
            throw new MyStackOperationException("弹栈失败，栈已空！");
        }
        // 程序能够执行到此处说明栈没有空。
        System.out.print("弹栈" + elements[index] + "元素成功，");
        // 栈帧向下移动一位。
        this.index--;
        System.out.println("栈帧指向" + index);
        return elements[index];
    }
}
/**
 * 栈操作异常：自定义异常！
 */
class MyStackOperationException extends Exception{ // 编译时异常！
    public MyStackOperationException(){}
    public MyStackOperationException(String s){
        super(s);
    }
}
```

###### 异常的代码示例

类在强制类型转换过程中，如果是类转换成接口类型。那么类和接口之间不需要存在继承关系，也可以转换，java语法中允许。

```java
public class Test {
    public static void main(String[] args) {
        // 构建一个军队
        Army army = new Army(2);// 军队只有4个武器。
        // 创建武器对象
        Tank tank1 = new Tank();
        Tank tank2 = new Tank();
        try {
            // 添加武器
            army.addWeapon(tank1);
            army.addWeapon(tank2);
        } catch (AddWeaponException e) {
            e.printStackTrace();
        }
        // 让所有可移动的移动
        army.attackAll();
        // 让所有可攻击的攻击
        army.moveAll();

        // 这是new一个异常对象。没有手动抛异常，它就是一个普通的java类。
        // 就像User类一样。没有区别。
        /* AddWeaponException e = new AddWeaponException("武器数量已达到上限！");
        System.out.println(e.getMessage()); */
    }
}
// 所有武器的父类
class Weapon {
}
// 可移动的接口
interface Moveable {
     // 移动行为
    void move();
}
//可射击的
interface Shootable {
    // 射击行为
    void shoot();
}
// 添加武器异常。
class AddWeaponException extends Exception {
    public AddWeaponException(){}
    public AddWeaponException(String s){
        super(s);
    }
}
//坦克是一个武器，可移动，可攻击。
class Tank extends Weapon implements Moveable,Shootable{
    @Override
    public void move() {
        System.out.println("坦克移动");
    }

    @Override
    public void shoot() {
        System.out.println("坦克开炮");
    }
}
class Army{
    // 武器数组
    private Weapon[] weapons;

    /**
     * 创建军队的构造方法。
     * @param count 武器数量
     */
    public Army(int count){
        // 动态初始化数组中每一个元素默认值是null。
        // 武器数组是有了，但是武器数组中没有放武器。
        this.weapons = new Weapon[count];
    }
    public void addWeapon(Weapon weapon) throws AddWeaponException{
        for (int i = 0; i < this.weapons.length; i++) {
            if(weapons[i] == null){
                weapons[i] = weapon;
                System.out.println(weapon + "：武器添加成功");
                return;
            }
        }
        // 程序如果执行到此处说明，武器没有添加成功
        throw new AddWeaponException("武器数量已达到上限！");
    }
    /**
     * 所有可攻击的武器攻击。
     */
    public void attackAll(){
        for (int i = 0; i < this.weapons.length; i++) {
            if(weapons[i] instanceof Shootable){
                Shootable shootable = (Shootable) weapons[i];
                shootable.shoot();
            }
        }
    }
    /**
     * 所有可移动的武器移动
     */
    public void moveAll(){
        for (int i = 0; i < this.weapons.length; i++) {
            if(weapons[i] instanceof Moveable){
                Moveable moveable = (Moveable) weapons[i];
                moveable.move();
            }
        }
    }
}
```

