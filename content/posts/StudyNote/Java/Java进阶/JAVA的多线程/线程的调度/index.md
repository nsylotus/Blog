---
title: "JAVA线程的调度" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 线程的调度

1. 常见的线程调度模型有哪些？

   1. 抢占式调度模型：
      1. 那个线程的优先级比较高，抢到的CPU时间片的概率就高一些/多一些。java采用的就是抢占式调度模型。
   2. 均分式调度模型：
      1. 平均分配CPU时间片。每个线程占有的CPU时间片时间长度一样。平均分配，一切平等。有一些编程语言，线程调度模型采用的是这种方式。

2. java中提供了哪些方法是和线程调度有关系的呢？

   ```java
   void setPriority(int newPriority) // 设置线程的优先级，是实例方法
   int getPriority() // 获取线程优先级。是实例方法
   static void yield() // 暂停当前正在执行的线程对象，执行其他线程。是静态方法
   void join() // 等待该线程终止。是实例方法
   ```

3. 线程的优先级

   ```java
   void setPriority(int newPriority) // 设置线程的优先级，是实例方法
   int getPriority() // 获取线程优先级。是实例方法
   ```
	1. 最低优先级1
   2. 默认优先级是5
   3. 最高优先级10
   4. 优先级比较高的获取CPU时间片可能会多一些。（但也不完全是，大概率是多的。）

   ```java
   public class Test {
       public static void main(String[] args) {
           // 设置主线程的优先级为1
           Thread.currentThread().setPriority(1);
           System.out.println("最高优先级" + Thread.MAX_PRIORITY); // 最高优先级10
           System.out.println("最低优先级" + Thread.MIN_PRIORITY); // 最低优先级1
           System.out.println("默认优先级" + Thread.NORM_PRIORITY); // 默认优先级5
           // 获取当前线程对象，获取当前线程的优先级
           System.out.println(Thread.currentThread().getName() + "线程的默认优先级是：" + Thread.currentThread().getPriority());// main线程的默认优先级是：1
           Thread thread = new Thread(new MyRunnable());
           thread.setName("MyRunnableThread");
           thread.start();
           // 优先级较高的，只是抢到的CPU时间片相对多一些。
           // 大概率方向更偏向于优先级比较高的。
           for (int i = 0; i < 100; i++) {
               System.out.println(Thread.currentThread().getName() + "------>" + i);
           }
       }
   }
   class MyRunnable implements Runnable{
       @Override
       public void run() {
           // 获取线程优先级
           System.out.println(Thread.currentThread().getName() + "线程的默认优先级：" + Thread.currentThread().getPriority()); // MyRunnableThread线程的默认优先级：1
           for (int i = 0; i < 100; i++) {
               System.out.println(Thread.currentThread().getName() + "------>" + i);
           }
       }
   }
   ```
   
4. 让位方法：

   ```java
   static void yield() // 暂停当前正在执行的线程对象，执行其他线程。是静态方法
   ```
   1. 暂停当前正在执行的线程对象，并执行其他线程
   2. yield()方法不是阻塞方法。让当前线程让位，让给其它线程使用。
   3. yield()方法的执行会让当前线程从“运行状态”回到“就绪状态”。
   4. 注意：在回到就绪之后，有可能还会再次抢到。
   
   ```java
   /*
   让位，当前线程暂停，回到就绪状态，让给其它线程。
   静态方法：Thread.yield();
    */
   public class Test {
       public static void main(String[] args) {
           Thread thread = new Thread(new MyRunnable());
           thread.setName("MyRunnableThread");
           thread.start();
           for (int i = 0; i < 100; i++) {
               System.out.println(Thread.currentThread().getName() + "------>" + i);
           }
       }
   }
   class MyRunnable implements Runnable{
       @Override
       public void run() {
           for (int i = 0; i < 100; i++) {
               //每100个让位一次。
               if(i % 10 == 0){
                   Thread.yield(); // 当前线程暂停一下，让给主线程。
               }
               System.out.println(Thread.currentThread().getName() + "------>" + i);
           }
       }
   }
   ```
   
5. 合并线程

   ```java
   void join() // 等待该线程终止。是实例方法
   ```
   线程合并，并不是将分支线程的栈销毁掉，而是栈的阻塞原理。

   ```java
   public class Test {
       public static void main(String[] args) {
           System.out.println("main begin");
           Thread thread = new Thread(new MyRunnable());
           thread.setName("MyRunnableThread");
           thread.start();
           // 合并线程
           try {
               thread.join(); // thread合并到当前线程中，当前线程受阻塞，thread线程执行直到结束。
           } catch (InterruptedException e) {
               e.printStackTrace();
           }
           System.out.println("main over");
       }
   }
   class MyRunnable implements Runnable{
       @Override
       public void run() {
           for (int i = 0; i < 100; i++) {
               System.out.println(Thread.currentThread().getName() + "------>" + i);
           }
       }
   }
   ```

   
