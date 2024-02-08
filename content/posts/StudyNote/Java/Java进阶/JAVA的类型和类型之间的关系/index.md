---
title: "JAVA类型和类型之间的关系" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 类型和类型之间的关系

#### is a（继承）

is a：
	Cat is a Animal（猫是一个动物）
	凡是能够满足is a的表示“继承关系”

```java
A extends B
```

#### has a（关联）

has a：
	I has a Pen（我有一支笔）
	凡是能够满足has a关系的表示“关联关系”
	关联关系通常以“属性”的形式存在。

```java
A{
	B b;
}
```

#### like a（实现）

like a:
	Cooker like a FoodMenu（厨师像一个菜单一样）
	凡是能够满足like a关系的表示“实现关系”
	实现关系通常是：类实现接口。

```java
A implements B
```

### package和import

#### package

1. package是一个关键字，后面加包名。例如：package com.javase;其中每一个以.分割的是目录的名字。

2. 注意：package语句只允许出现在java源代码的第一行。

3. 对于带有package的java程序怎么编译？怎么运行？
   	类名不再是：HelloWorld了。
   	类名是：com.javase.HelloWorld
   
4. 编译：
   	javac -d . HelloWorld.java
   	解释一下：
   		javac 负责编译的命令
   		-d		带包编译
   		.		代表编译之后生成的东西放到当前目录下（点代表当前目录）
   		HelloWorld.java  被编译的java文件名。
   
5. 运行：
   	java com.javase.HelloWorld
   
6. 以后说类名的时候，如果带着包名描述，表示完整类名。如果没有带包，描述的话，表示简类名。

   ​	java.util.Scanner 完整类名。

   ​	Scanner 简类名

#### import

1. import什么时候使用？
   	A类中使用B类。
   	A和B类都在同一个包下。不需要import。
   	A和B类不在同一个包下。需要使用import。

2. java.lang.*;这个包下的类不需要使用import导入。

3. import怎么用？
   	import语句只能出现在package语句之下，class声明语句之上。
   	import语句还可以采用星号的方式。

4. 怎么用？

   ​	import 完整类名;

   ​	import 包名.*;

   ​	import java.util.Scanner; // 完整类名。
