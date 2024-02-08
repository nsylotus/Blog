---
title: "MySQL的悲观锁和乐观锁" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA","MySQL"]
categories: ["JAVA"]
---

#### MySQL的悲观锁和乐观锁

![悲观锁（行级锁for update）和乐观锁机制](./悲观锁（行级锁for update）和乐观锁机制.jpg)

悲观锁：这个事务不结束，就无法解除对该事务的锁定，别的程序（线程）就无法对该数据库的行级数据进行修改。

乐观锁：拥有一个版本号。