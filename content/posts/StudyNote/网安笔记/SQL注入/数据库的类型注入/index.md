---
title: "SQL注入的提交方法和注入类型" # 文章标题.
date: 2022-10-22
draft: false
tags: ["WEB安全"] # 标签.
categories: ["WEB安全"] # 分类.
---

# 提交方法和注入类型

注入漏洞的原理：将数据带入数据库查询，查询出相应的内容，但是我们在这个基础上进行修改了。

## 提交方法

对于PHP的代码

```php
$name = $_GET['x'];
$sql = "select * from user where name = '$name'"; // 这是字符型的
```

在带入数据库查询的时候，加不加()都是一样的，在数据库中%是通配符。

```mysql
?x=myname and 1=1
select * from user where name = 'myname and 1=1' # 由于单引号的存在将这个and当作字符串处理
select * from user where name = （'myname and 1=1'） # 多尝试，数据库的查询语句不唯一
# Like语句,模糊查询
?x=mypage
select * from user where name like '%mypage%' # 使用%作为通配符类似于* 写法不唯一
```

### 简要明确请求方法

1. GET

   就是通过，浏览器的URL进行参数的传递。传输的数据一般较小。

   GET请求的话不考虑请求头是GET还是POST。

   ```
   /?get=123
   ```

2. POST

   POST请求可以传递很长的数据，不是通过URL进行传输的，传输的数据可以很大。

   post请求数据包，get请求数据包的话不变直接burpsuite提交即可

   POST请求需要间隔一行进行写数据

   ```
   post=数据
   ```

   POST数据注入提交注入测试=>sqlilabs less 11

3. COOKIE

   ```http
   Cookie: cookie=123123 # 在BurpSuite中需要这样写
   ```

   COOKIE数据注入提交测试=>sqlilabs less 20，这个就是绕过了POST请求。使用COOKIE注入的

   使用Cookie注入的话，会有奇效，有时候可以绕过有一些防护，例如相应的魔术引号，less 20就是这样的

4. REQUEST

   可以接受GET，POST，COOKIE请求的数据，但是在接受COOKIE数据的时候，需要在PHP的配置文件中开启request_order，默认是request_order="GP"，并不包含C也就是Cookie，需要加上C，才可以接收COOKIE传递的数据。

   由于我们大多数的情况下都是**黑盒测试**，如果对方使用request的方式进行提交数据的话，就不需要考虑对方相应的方式，因为get，post，cookie都可以。

   如果get和post分别提交，页面是一样的，那么就是request方式去请求

5. HTTP头等，例如：User-Agent等

   抓包之后直接修改数据即可。

   对于PHP来说，`$_SERVER`，是PHP内部的一个预定义变量，可以获取相应服务器的资源信息，进行注入，可以获取你的IP地址等等之类的。

   HTTP头注入，发生在HTTP头中，可以是User-Agant中，and so on只要是将注入语句插入到数据库中的地方都可以使用这种注入方式

   HTTP头部数据注入测试=>sqlilabs less 18

6. GET请求如何与POST请求相互转化：

   比较两个请求的不同：

   不同部位：头部GET/POST

   缺少的部位：Content-Type、Content-Length、Origin、post传参内容

   第一步：改请求头第一行,把GET改成POST

   第二步：中间添加2行参数

   ```http
   Content-Type: application/x-www-form-urlencoded
   Content-Length:（请求的内容长度）一般是8
   # 参数和值之间要有空格
   ```

   第三步：末尾空一行，写POST参数，结合实际情况，用参数名=参数值的格式构造参数（中间不能用空格），多个参数要用&隔开。

一般情况下修改提交方式进行的注入，不需要进行测试那么多，一般get，post测试就可以了，但是有时候为了绕过一些WAF之类的可以修改提交方式进行绕过。

## 注入类型

一般情况下都是字符型的，因为无论你类型，数字也好，字符也好，通过WEB的URL传递的数据都会变成字符。

注入类型有字符型和非字符型。

这两种是数字型的

```mysql
select * from user where id =1
select * from user where id = '1' # 这两个是相同的效果 
```

这种是字符型的

```mysql
select * from user where name = "Love"
```

### 简要明确参数类型

1. 数字

2. 字符

   参数字符型注入测试=>sqlilabs less 5 6

3. 搜索（就是%匹配的）

4. JSON等

   没有环境，但是和其他类型的注入是同一个方法。

   JSON方式的注入，直接注入就行了，和上面的方法类似，这种一般存在于APP中

   eg：`json={"username":"Dumb" and 1=2 union select 1,database(),3#}`
   
   eg：
   
   ```json
   a=1 and 1=1 & b=2 &c=3 // 普通的注入类型
   { // JSON注入类型
       "a":"1 and 1=1", // 这个""是不需要闭合的
       "b":"2",
       "c":"3"
   }
   ```
   

在注入的过程中可能会有干扰符号，其中SQL语句干扰的符号有'，"，%，），}等，具体绕过，需要看写法，自己多尝试，例如将`and 1=1`当作字符串处理了，如果对方的SQL语句中是`select * from user where id = '1'`将and 1=1当作字符串带入数据库进行查询就出错了，需要闭合`'`
