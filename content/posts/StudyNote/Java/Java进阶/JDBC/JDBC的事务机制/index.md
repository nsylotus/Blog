---
title: "JDBC的事务机制" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### JDBC的事务机制

JDBC的事务机制：

JDBC中的事务是自动提交的，什么事自动提交？

只要执行任意一条DML语句，则自动提交一次，这是JDBC默认的事务行为。

但是在实际的业务中。通常都是N条DML语句共同联合才能完成的，必须保证

他们这些DML语句在同一个事务中同时成功或者同时失败。一下程序先验证JDBC的事务是否是自动提交的。

```java
import java.sql.*;

public class Test {
    public static void main(String[] args) {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            // 注册驱动
            Class.forName("com.mysql.jdbc.Driver");
            // 获取连接
            connection = DriverManager.getConnection("jdbc:mysql://;localhost/pentest","root","123456");
            String sql = "update news set title = ? where id = ?";
            // 3.获取预编译的数据库操作对象
            preparedStatement = connection.prepareStatement(sql);
            // 给?传值
            preparedStatement.setString(1,"Love");
            preparedStatement.setInt(2,3);
            int count = preparedStatement.executeUpdate();// 执行第一条update语句
            // 这里执行完执行第一条update语句买就直接提交到数据库了，这样遇到下面的空指针异常的时候整个程序就结束了，对于下面的第二条的SQL语句不能执行，如果这两条的SQL语句是在一起执行才有效果的话，因为出现了空指针异常第二条update语句不会执行，这样对数据库来说是错误的，原因就是JDBC的事务是自动提交的。要解决这种情况就必须修改这种事务的提交方式。不让自动提交。
            System.out.println(count);
            String str = null;// 空指针异常
            str.toString();
            preparedStatement.setString(1,"You");
            preparedStatement.setInt(2,2);
            count = preparedStatement.executeUpdate();// 执行第二条update语句
            System.out.println(count);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if(preparedStatement != null){
                try {
                    preparedStatement.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
            if(connection != null){
                try {
                    connection.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
        }
    }
}
```

#### 将JDBC的事务提交机制修改为手动提交事务

常用的函数有：

```java
void setAutoCommit(boolean autoCommit) // 将此连接的自动提交模式设置为手动提交:false
void commit() // 使所有上一次提交/回滚后进行的更改成为持久更改，并释放此 Connection 对象当前持有的所有数据库锁。 
void Connection.rollback() // 取消在当前事务中进行的所有更改，并释放此 Connection 对象当前持有的所有数据库锁。 
```

```java
import java.sql.*;
// 这是单机事务
public class Test {
    public static void main(String[] args) {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            // 注册驱动
            Class.forName("com.mysql.jdbc.Driver");
            // 获取连接
            connection = DriverManager.getConnection("jdbc:mysql://localhost/pentest","root","123456");
            // 将自动提交机制修改为手动提交
            connection.setAutoCommit(false);//开启事务
            String sql = "update t_act set balance = ? where actno = ?";
            // 给?传值
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setDouble(1,10000);
            preparedStatement.setInt(2,111);
            int count = preparedStatement.executeUpdate();
            String s = null;
            s.toString();
            // 给?传值
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setDouble(1,10000);
            preparedStatement.setInt(2,222);
            count += preparedStatement.executeUpdate();
            System.out.println(count == 2 ? "转账成功" : "转账失败");
            // 程序能够走到此处说明以上程序没有异常，事务结束，手动提交数据。
            connection.commit();//提交事务
        } catch (Exception e) {
            // 回滚事务
            if(connection != null){
                try {
                    connection.rollback();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
            e.printStackTrace();
        } finally {
            if(preparedStatement != null){
                try {
                    preparedStatement.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
            if(connection != null){
                try {
                    connection.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
        }
    }
}
```

这样就算出现了空指针异常，所有有关数据的操作没有完全执行完毕，数据库不会进行更新数据，这样保证了数据的安全性。出现了异常则会通过rollback()方法的回滚机制，进行回滚，保证数据的安全。
