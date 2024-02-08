---
title: "JAVA定时器" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---


### 定时器

1. 定时器的作用：间隔特定的时间，执行特定的程序。
2. 在java中可以采用多种方式实现定时器：
   1. 可以使用sleep方法，睡眠，设置睡眠时间，没到这个时间点醒来，执行任务。这种方式是最原始的定时器。
   2. 在java的类库中已经写好了一个定时器：java.util.Timer，可以直接拿来用。

Timer类的常用方法：

```java
Timer() // 创建一个新计时器。
Timer(boolean isDaemon) // 创建一个新计时器，可以指定其相关的线程作为守护程序运行。
Timer(String name) // 创建一个新计时器，其相关的线程具有指定的名称。
Timer(String name, boolean isDaemon) // 创建一个新计时器，其相关的线程具有指定的名称，并且可以指定作为守护程序运行。
void schedule(TimerTask task, long delay, long period) // 安排指定的任务从指定的延迟后开始进行重复的固定延迟执行。schedule(定时任务, 第一次执行时间, 间隔多久执行一次);
```

###### 代码示例

```java
import java.text.SimpleDateFormat;
import java.util.*;
// 使用定时器指定定时任务。
public class Test {
    public static void main(String[] args) throws Exception{
        // 创建定时器对象
        Timer timer = new Timer();
        // Timer timer = new Timer(true); // 守护线程的方式
        // 指定定时任务
        // timer.schedule(定时任务, 第一次执行时间, 间隔多久执行一次);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date firstTime = sdf.parse("2020-03-14 09:30:30");
        // 也可以使用匿名内部类方式
        timer.schedule(new MyTimer() , firstTime, 1000 * 10);
    }
}
// 编写一个定时任务类
// 假设这是一个记录日志的定时任务
class MyTimer extends TimerTask{
    @Override
    public void run() {
        // 编写你需要执行的任务就行了。
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss SSS");
        String strTime = sdf.format(new Date());
        System.out.println(sdf + ":成功完成了一次数据备份！");
    }
}
```

