---
title: "操作系统漏洞探针" # 文章标题.
date: 2023-04-11
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# 操作系统漏洞探针

![漏洞发现](./操作系统.png)

## 漏洞探测工具

### Nmap

nmap检测漏洞的使用方法

```
nmap -sV --script=vulscan/vulscan.nse <target> # 默认nse插件
nmap -sV --script vuln <target>
nmap -sV --script vulners <target>
192.168.132.129
```

## 漏洞利用框架

### Searchsploit

### Metasploit