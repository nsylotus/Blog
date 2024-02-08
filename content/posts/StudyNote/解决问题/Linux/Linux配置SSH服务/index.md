---
title: "Linux配置SSH服务" # 文章标题.
date: 2022-07-12
draft: false
tags: ["Linux"]
categories: ["SSH"]
---

# Linux配置SSH服务

```
sudo apt install openssh-server 安装
sudo /etc/init.d/ssh start 启动服务
```

默认端口是22

```
sudo /etc/init.d/ssh resart 重启ssh服务
```

或者

```
重启ssh服务 service ssh restart
```

## 配置ROOT登录

修改配置文件

```
sudo nvim /etc/ssh/sshd_config
```

查找/修改/添加以下配置

```
PermitRootLogin yes #允许root登录
PermitEmptyPasswords no #不允许空密码登录
PasswordAuthentication yes # 设置是否使用口令验证。
```

如果以上还不行的话可以尝试修改root密码，然后输入两次密码重置

```
sudo passwd root
```

配置完成后记得要重启服务

## 连接SSH

连接SSH的工具非常多，例如XShell，Putty，等等这些工具，其实我们的下载的git工具也是可以连接SSH的。

```
ssh username@hostname
eg:ssh root@1.1.1.1
```

然后输入密码就可以了

## 使用SCP传输文件

从服务器上下载文件

```
scp username@servername:/path/filename /var/www/local_dir（本地目录）
```

上传本地文件到服务器

```
scp /path/filename username@servername:/path
scp -r /path/filename username@servername:/path # 传文件夹
```

传输文件夹的时候加上-r参数就可以了，参考上面的

切记不要连接到服务器的时候使用scp命令，scp和ssh一样是一个单独的命令，不然会出现

`ssh:could not resolve hostname X:Temporary failure in name resolution`的错误

这个原因是因为在没有找到这个文件/目录