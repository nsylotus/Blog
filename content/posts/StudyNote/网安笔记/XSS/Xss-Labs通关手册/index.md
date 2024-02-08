---
title: "XSS-Labs通关手册" # 文章标题.
date: 2023-02-25
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# XSS-Labs通关手册

## 第一关

![第一关](./第一关.png)

## 第二关

实体化标签函数

```php
htmlspecialchars() // 把预定义的字符 "<" （小于）和 ">" （大于）转换为 HTML 实体：
```

![第二关](./第二关.png)

## 第三关

这个只需要闭合一下标签。

![第三关](./第三关.png)

除了点击事件还有鼠标移动事件等等。

```javascript
onmouseover=alert(/xss/)
```

## 第四关

![第四关](./第四关.png)

## 第五关

![第五关](./第五关.png)

## 第六关

![第六关](./第六关.png)

## 第七关

![第七关](./第七关.png)

## 第八关

这个使用到了Unicode编码。

![第八关](./第八关.png)

## 第九关

![第九关](./第九关.png)

## 第十关

![第十关](./第十关.png)

## 第十一关

![第十一关页面](./第十一关页面.png)

这一关明显是Referer提交，绕过。

![第十一关BurpSuite](./第十一关BurpSuite.png)

请求从哪里来

CSRF：跨站点脚本攻击

XSS：跨站脚本攻击

SSRF：跨站请求伪造

跟注入一样，也是有post，get，user-agent，等等的XSS插的方式。