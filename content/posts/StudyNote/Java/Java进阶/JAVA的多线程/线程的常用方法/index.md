---
title: "JAVA线程的常用方法" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 线程的常用方法

```java
static Thread currentThread() // 返回对当前正在执行的线程对象的引用。
String getName() // 返回该线程的名称。
void setName(String name) // 改变线程名称，使之与参数 name 相同。
static void sleep(long millis) //静态方法,参数是毫秒,让当前线程进入休眠，进入“阻塞状态”，放弃占有CPU时间片，让给其它线程使用。
void interrupt() // 中断线程。
void stop() // 杀死一个线程
```

1. 当线程没有设置名字的时候，默认的名字有什么规律？
   1. Thread-0
   2. Thread-1
   3. Thread-2

###### 代码示例

```java
public class Test {
    public void doSome(){
        String doName = Thread.currentThread().getName();
        System.out.println(doName);
    }
    public static void main(String[] args) {
        Test test = new Test();
        test.doSome(); // main
        // currentThread就是当前线程对象
        // 这个代码出现在main方法当中，所以当前线程就是主线程。
        Thread currentThread = Thread.currentThread();
        System.out.println(currentThread.getName());
        // 创建线程对象
        MyThread myThread1 = new MyThread();
        // 获取线程的名字
        String tName1 = myThread1.getName();
        System.out.println(tName1); // Thread-0
        MyThread myThread2 = new MyThread();
        // 设置线程的名字
        myThread2.setName("tName2");
        // 获取线程的名字
        String tName2 = myThread2.getName();
        System.out.println(tName2);// tName2
        // 启动线程
        myThread2.start();
    }
}
class MyThread extends Thread{
    @Override
    public void run() {
        for (int i = 0; i < 10; i++) {
            // currentThread就是当前线程对象。当前线程是谁呢？
            // 当t1线程执行run方法，那么这个当前线程就是t1
            // 当t2线程执行run方法，那么这个当前线程就是t2
            Thread currentThread = Thread.currentThread();
            System.out.println(currentThread.getName() + "-->" + i);
        }
    }
}
```

#### 线程的睡眠

##### sleep方法

```java
static void sleep(long millis) // 静态方法,参数是毫秒
```

1. 作用：
   1. **让当前线程进入休眠，进入“阻塞状态”**，放弃占有CPU时间片，让给其它线程使用。
   2. 这行代码出现在A线程中，A线程就会进入休眠。
   3. 这行代码出现在B线程中，B线程就会进入休眠。
2. Thread.sleep()方法，可以做到这种效果：间隔特定的时间，去执行一段特定的代码，每隔多久执行一次。
3. 用对象调用sleep方法：即对象名.sleep()还是会转化为Thread.sleep()方法，仍然让当前线程进入休眠。

```java
public class Test {
    public static void main(String[] args) {
        // 让当前线程进入休眠，睡眠1秒
        // 当前线程是主线程！！！
        for (int i = 0; i < 10; i++) {
            System.out.println(Thread.currentThread().getName() + "--->" + i);
            // 睡眠1秒
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        // 创建线程对象
        Thread myThread = new MyThread();
        myThread.setName("myThread");
        myThread.start();
        // 调用sleep方法
        try {
            // 问题：这行代码会让线程myThread进入休眠状态吗？
            myThread.sleep(1000 * 5);
            // 在执行的时候还是会转换成：Thread.sleep(1000 * 5);
            // 这行代码的作用是：让当前线程进入休眠，也就是说main线程进入休眠。
            // 这样代码出现在main方法中，main线程睡眠。
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Hello Word!!!");
    }
}
class MyThread extends Thread{
    public void run(){
        for (int i = 0; i < 10; i++) {
            System.out.println(Thread.currentThread().getName() + "--->" + i);
        }
    }
}
```

##### 终止线程的睡眠(打断线程)

1. 调用interrupt()方法。
2. sleep睡眠太久了，如果希望半道上醒来，你应该怎么办？也就是说怎么叫醒一个正在睡眠的线程？？使用异常处理。
   1.  注意：这个不是终断线程的执行，是终止线程的睡眠。

```java
public class Test {
    public static void main(String[] args) {
        Thread thread = new Thread(new MyRunnable());
        thread.setName("MyRunnableThread");
        thread.start();
        // 希望5秒之后，t线程醒来（5秒之后主线程手里的活儿干完了。）
        try {
            Thread.sleep(1000*5);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // 终断t线程的睡眠（这种终断睡眠的方式依靠了java的异常处理机制。）
        thread.interrupt();// 干扰，一盆冷水过去！
    }
}
class MyRunnable implements Runnable{
    // 重点：run()当中的异常不能throws，只能try catch
    // 因为run()方法在父类中没有抛出任何异常，子类不能比父类抛出更多的异常。
    @Override
    public void run() {
        System.out.println(Thread.currentThread().getName() + "------>" + "begin");
        try {
            // 睡眠1年
            Thread.sleep(1000 * 60 * 60 * 24 * 365);
        } catch (InterruptedException e) {
            // 打印异常信息
            e.printStackTrace();
        }
        // 1年之后才会执行这里
        System.out.println(Thread.currentThread().getName() + "------>" + "end");
    }
}
```

#### 终止线程

在java中怎么强行终止一个线程的执行。使用stop方法。

这种方式存在很大的缺点：容易丢失数据。因为这种方式是直接将线程杀死了，线程没有保存的数据将会丢失。不建议使用。

```java
public class Test {
    public static void main(String[] args) {
        Thread thread = new Thread(new MyRunnable());
        thread.setName("MyRunnableThread");
        thread.start();
        // 模拟5秒
        try {
            Thread.sleep(1000*5);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // 5秒之后强行终止t线程
        thread.stop(); // 已过时（不建议使用。）
    }
}
class MyRunnable implements Runnable{
    @Override
    public void run() {
        for (int i = 0; i < 10; i++) {
            System.out.println(Thread.currentThread().getName() + "------>" + i);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
```

###### 改进办法

```java
public class Test {
    public static void main(String[] args) {
        MyRunnable myRunnable = new MyRunnable();
        Thread thread = new Thread(myRunnable);
        thread.setName("MyRunnableThread");
        thread.start();
        // 模拟5秒
        try {
            Thread.sleep(1000*5);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // 5秒之后强行终止t线程
        // thread.stop(); // 已过时（不建议使用。）
        // 终止线程
        // 你想要什么时候终止t的执行，那么你把标记修改为false，就结束了。
        myRunnable.run = false;
    }
}
class MyRunnable implements Runnable{
    // 打一个布尔标记
    boolean run = true;
    @Override
    public void run() {
        for (int i = 0; i < 10; i++) {
            if(run){
                System.out.println(Thread.currentThread().getName() + "------>" + i);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }else {
                // return就结束了，你在结束之前还有什么没保存的。在这里可以保存呀。
                // save....

                //终止当前线程
                return;
            }
        }
    }
}
```

