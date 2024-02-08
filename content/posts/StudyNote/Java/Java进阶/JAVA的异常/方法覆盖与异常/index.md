---
title: "Java方法覆盖与异常" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 方法覆盖与异常

重写之后的方法不能比重写之前的方法抛出更多（更宽泛）的异常，可以更少。

```java
class Animal {
    public void doSome(){}
    public void doOther() throws Exception{}
}

class Cat extends Animal {
    // 编译正常。
    public void doSome() throws RuntimeException{}
    // 编译报错。
    /*public void doSome() throws Exception{

    }*/

    // 编译正常。
    /*public void doOther() {

    }*/

    // 编译正常。
    /*public void doOther() throws Exception{

    }*/

    // 编译正常。
    public void doOther() throws NullPointerException{}
}
```