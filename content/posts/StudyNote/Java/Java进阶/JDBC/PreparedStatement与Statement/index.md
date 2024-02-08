---
title: "JDBC解决SQL注入" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### 如何SQL注入的问题？

只要用户提供的信息不参与SQL语句的编译过程，问题就解决了。

即使用户提供的信息中含有SQL语句的关键字，但是没有参与编译，不起作用。

要想用户信息不参与SQL语句的编译，那么必须使用java.sql.PreparedStatement

PreparedStatement接口继承了java.sql.Statement

PreparedStatement是属于预编译的数据库操作对象。

PreparedStatement的原理是：预先对SQL语句的框架进行编译，然后再给SQL语句传“值”。

PreparedStatement与Statement对比？

PreparedStatement解决了SQL注入的问题，Statement存在SQL注入的问题

Statement编译一次执行一次，PreparedStatement是编译一次，可执行n次，PreparedStatement效率比较高一些

PreparedStatement会在编译阶段做类型的安全检查。

###### 这是使用Statement的代码，存在SQL注入

```java
import java.sql.*;
import java.util.*;

public class Test {
    public static void main(String[] args) {
        // 初始化界面
        Map<String,String> userLoginInfo = initUI();
        boolean loginSuccess = Login(userLoginInfo);
        System.out.println(loginSuccess ? "成功" : "失败");
    }

    /**
     * 用户登录
     * @param userLoginInfo 用户登录信息
     * @return false表示成功，true表示失败。
     */
    private static boolean Login(Map<String, String> userLoginInfo) {
        boolean loginSuccess = false;
        // JDBC代码
        Connection connection = null;
        Statement statement = null;
        ResultSet resultSet = null;
        try {
            // 1.注册驱动
            Class.forName("com.mysql.jdbc.Driver");
            // 2.获取连接
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/pentest","root","123456");
            // 3.获取数据库操作对象
            statement = connection.createStatement();
            // 4.执行SQL
            String sql = "select * from account where rest = '"+userLoginInfo.get("loginName")+"' and own = '"+userLoginInfo.get("loginPwd")+"'";
            resultSet = statement.executeQuery(sql);
            // 5.处理结果集
            if(resultSet.next()){
                loginSuccess = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 6.释放资源
            if(resultSet != null){
                try {
                    resultSet.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
            if(statement != null){
                try {
                    statement.close();
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
        return loginSuccess;
    }

    /**
     * 初始化用户界面
     * @return 用户输入的用户名和密码等信息。
     */
    private static Map<String, String> initUI() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("用户名:");
        String loginName = scanner.nextLine();
        System.out.println("密码：");
        String loginPwd = scanner.nextLine();
        Map<String,String> userLoginInfo = new HashMap<>();
        userLoginInfo.put("loginName",loginName);
        userLoginInfo.put("loginPwd",loginPwd);
        return userLoginInfo;
    }
}
```

###### 这是使用PreparedStatement的代码，解决了SQL注入

常用函数：

```java
PreparedStatement prepareStatement(String sql) // 创建一个 PreparedStatement 对象来将参数化的 SQL 语句发送到数据库。 
void setString(int parameterIndex, String x) // 将指定参数设置为给定 Java String 值。 
```

```java
import java.sql.*;
import java.util.*;
public class Test {
    public static void main(String[] args) {
        // 初始化界面
        Map<String,String> userLoginInfo = initUI();
        boolean loginSuccess = Login(userLoginInfo);
        System.out.println(loginSuccess ? "成功" : "失败");
    }

    /**
     * 用户登录
     * @param userLoginInfo 用户登录信息
     * @return false表示成功，true表示失败。
     */
    private static boolean Login(Map<String, String> userLoginInfo) {
        boolean loginSuccess = false;
        // JDBC代码
        Connection connection = null;
        PreparedStatement preparedStatement = null; // 这是使用PreparedStatement（预编译的数据库操作对象）
        ResultSet resultSet = null;
        try {
            // 1.注册驱动
            Class.forName("com.mysql.jdbc.Driver");
            // 2.获取连接
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/pentest","root","123456");
            // 3.获取预编译的数据库操作对象
            // ?是占位符，先写SQL的框架，其中一个?代表一个占位符，一个?将来接收一个“值”,注意：占位符不能使用单引号括起来。
            String sql = "select * from account where rest = ? and own = ?";
            // String sql = "insert into account(Id,rest,own) values(?,?,?)";
            // 程序执行到此处，会发送SQL语句框架给DBMS，然后DBMS进行sql语句的预先编译。
            preparedStatement = connection.prepareStatement(sql);
            // 给占位符?传值（第一个?下标是1，第二个?下标是2，JDBC中所有的下标从1开始）
            preparedStatement.setString(1,userLoginInfo.get("loginName"));// 按照属性进行set,有setInt()
            preparedStatement.setString(2,userLoginInfo.get("loginPwd"));
            // 4.执行SQL
            resultSet = preparedStatement.executeQuery();
            // 5.处理结果集
            if(resultSet.next()){
                loginSuccess = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 6.释放资源
            if(resultSet != null){
                try {
                    resultSet.close();
                } catch (SQLException throwables) {
                    throwables.printStackTrace();
                }
            }
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
        return loginSuccess;
    }

    /**
     * 初始化用户界面
     * @return 用户输入的用户名和密码等信息。
     */
    private static Map<String, String> initUI() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("用户名:");
        String loginName = scanner.nextLine();
        System.out.println("密码：");
        String loginPwd = scanner.nextLine();
        Map<String,String> userLoginInfo = new HashMap<>();
        userLoginInfo.put("loginName",loginName);
        userLoginInfo.put("loginPwd",loginPwd);
        return userLoginInfo;
    }
}
```

### JDBC的封装

模糊查询的使用

```java
import java.sql.*;
// 模糊查询的使用
public class Test {
    public static void main(String[] args) {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            // 获取连接
            connection = DBUtil.getConnection();
            // 获取预编译的数据库操作对象
            String sql = "select * from news where title like ?";
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1,"_o%");
            resultSet = preparedStatement.executeQuery();
            while (resultSet.next()){
                System.out.println(resultSet.getString("title"));
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        } finally {
            // 释放资源
            DBUtil.close(connection,preparedStatement,resultSet);
        }
    }
}
class DBUtil {
    /**
     * 工具类中的构造方法都是私有的
     * 因为工具类的所有方法都是静态的，不需要new对象，直接采用类名调用。
     * 为了防止调用构造方法，将构造方法私有化。
     */
    private DBUtil(){}
    //静态代码块，在类加载是执行，并且只执行一次
    static {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取数据库连接对象
     * @return 连接对象
     * @throws SQLException
     */
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost/pentest","root","123456");
    }

    /**
     * 关闭资源
     * @param connection 连接对象
     * @param statement 数据库操作对象
     * @param resultSet 结果集
     */
    public static void close(Connection connection,Statement statement,ResultSet resultSet){
        if(resultSet != null){
            try {
                resultSet.close();
            } catch (SQLException throwables) {
                throwables.printStackTrace();
            }
        }
        if(statement != null){
            try {
                statement.close();
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
```

