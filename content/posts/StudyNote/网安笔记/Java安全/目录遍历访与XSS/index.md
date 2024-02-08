---
title: "目录遍历访与XSS" # 文章标题.
date: 2023-04-09
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# 目录遍历访与XSS

![Java安全](./Java安全.png)

## 实践

### 文件上传（覆盖）

#### Less-1

![文件上传](./文件上传/文件上传.png)

抓包发现上传的路径。

![抓包分析](./文件上传/抓包分析.png)

分析代码，发现没有对上传的文件路径进行过滤。

![文件上传源码分析](./文件上传/文件上传源码分析.png)

所以进行这样的上传。

![成功](./文件上传/成功.png)

#### Less-2

这一个题目对`./`进行了过滤。

![题目](./有过滤/题目.png)

抓包分析源码。

![抓包](./有过滤/抓包.png)

对`../`进行了替换。

![分析源码](./有过滤/分析源码.png)

成功。

![成功](./有过滤/成功.png)

### 前端验证

![题目](./前端验证/题目.png)

抓包分析

![抓包分析](./前端验证/抓包分析.png)

源码分析，发现后端只是单纯的接受数据，不进行验证，那么验证就只会出现在前端。

![源码分析](./前端验证/源码分析.png)

拿到前端的JavaScript代码，进行验证，既账号密码就是CaptainJack与BlackPearl。

```javascript
function submit_secret_credentials() {
	var xhttp = new XMLHttpRequest();
	xhttp['open']('POST', '#attack/307/100', true);
	//sending the request is obfuscated, to descourage js reading
	var _0xb7f9 = [
        // CaptainJack的十六进制是4361707461696e4a61636b
        "/x43/x61/x70/x74/x61/x69/x6E/x4A/x61/x63/x6B", 
        // BlackPearl的十六进制是426c61636b506561726c
        "/x42/x6C/x61/x63/x6B/x50/x65/x61/x72/x6C", 			           				"/x73/x74/x72/x69/x6E/x67/x69/x66/x79", 
        "/x73/x65/x6E/x64"];
	xhttp[_0xb7f9[3]](JSON[_0xb7f9[2]]({
		username: _0xb7f9[0],
		password: _0xb7f9[1]
	}))
}
```

绕过成功。

![成功](./前端验证/成功.png)

### 不安全的直接对象引用

题目中已经给出了，账号是tom，密码是cat，登录之后让你继续。

![题目](./不安全的对象引用/题目.png)

继续之后发现，这个题目是让你将没有显示在页面上的数据提取出来。

![题目2](./不安全的对象引用/题目2.png)

抓包重放，发现的确是有些数据没有在页面中显示，那么没有显示的值就是`userId`与`role`

![抓包重放](./不安全的对象引用/抓包重放.png)

将role与userId输入，得到正确的结果。

![成功](./不安全的对象引用/成功.png)

### 查看他人资料

类似于`http://localhost/index.php?id=520`通过修改id的值，来查看不同用户的登录信息。

![题目](./查看他人资料/题目.png)

如何来获取用户的id，通过上一个题目获取到profile的内容。

![抓包重放](./不安全的对象引用/抓包重放.png)

成功。

![Payload](./查看他人资料/Payload.png)

### XSS

最好在服务器端进行验证数据。

![XSS题目](./XSS/XSS题目.png)

编写Payload。

![成功](./XSS/成功.png)
