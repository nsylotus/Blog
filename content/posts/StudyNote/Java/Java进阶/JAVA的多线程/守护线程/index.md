---
title: "JAVA的守护线程" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 守护线程

1. java语言中线程分为两大类：

   1. 一类是：用户线程
   2. 一类是：守护线程（后台线程）其中具有代表性的就是：垃圾回收线程（守护线程）。

2. 守护线程的特点：

   一般守护线程是一个死循环，所有的用户线程只要结束，守护线程自动结束。

3. 注意：主线程main方法是一个用户线程。

4. 当用户线程结束，守护线程自动终止。

5. 守护线程用在什么地方呢？

   例如：每天00:00的时候系统数据自动备份。这个需要使用到定时器，并且我们可以将定时器设置为守护线程。一直在那里看着，没到00:00的时候就备份一次。所有的用户线程如果结束了，守护线程自动退出，没有必要进行数据备份了。
   
6. 锁在目前知识范围内知道有两种：一种是排他锁，另一种是互斥锁。

```java
public class Test {
    public static void main(String[] args) throws Exception {
        Thread thread = new WardDataThread();
        thread.setName("MyThread");
        // 启动线程之前，将线程设置为守护线程,当主线程结束时，守护线程自动结束。
        // 若不设置的话则主线程结束，那个不是守护线程，分支线程则继续执行。
        thread.setDaemon(true);
        thread.start();
        for (int i = 0; i < 10; i++) {
            System.out.println(Thread.currentThread().getName() + "--->" + i);
            Thread.sleep(1000);
        }
    }
}
class WardDataThread extends Thread{
    int i = 0;
    @Override
    public void run() {
        // 即使是死循环，但由于该线程是守护者，当用户线程结束，守护线程自动终止。
        while (true) {
            System.out.println(Thread.currentThread().getName() + "--->" + (++i));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
```

