---
title: "Apache低版本解析漏洞" # 文章标题.
date: 2023-02-15
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# Apache低版本解析漏洞

`x.php.xxx.yyy`这种格式的文件名，在Apache低版本中最先识别的`yyy`，如果不识别向前解析，直到识别为止，将这个格式解析为php进而执行。

利用场景：

如果对方中间件Apache属于低版本，可以利用文件上传漏洞，上传一个不被识别的文件后缀，利用解析漏洞规则成功解析文件，其中后门代码被触发。