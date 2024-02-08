---
title: "JAVA的死锁" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 死锁

![006-死锁](./006-死锁.png)

###### 自己实现的死锁的代码

千万不要再程序中这样写，这样很难调试。

```java
public class Test {
    public static void main(String[] args) {
        Object obj1 = new Object();
        Object obj2 = new Object();
        // myThread1和myThread2两个线程共享obj1,obj2
        Thread myThread1 = new MyThread1(obj1,obj2);
        Thread myThread2 = new MyThread2(obj1,obj2);
        myThread1.setName("myThread1");
        myThread2.setName("myThread2");
        myThread1.start();
        myThread2.start();
    }
}
class MyThread1 extends Thread{
    Object obj1;
    Object obj2;
    public MyThread1(Object obj1, Object obj2) {
        this.obj1 = obj1;
        this.obj2 = obj2;
    }
    @Override
    public void run() {
        synchronized (obj1){
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            synchronized (obj2){

            }
        }
    }
}
class MyThread2 extends Thread{
    Object obj1;
    Object obj2;
    public MyThread2(Object obj1, Object obj2) {
        this.obj1 = obj1;
        this.obj2 = obj2;
    }

    @Override
    public void run() {
        synchronized (obj2){
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            synchronized (obj1){

            }
        }
    }
}
```

