---
title: "Java数组的练习" # 文章标题.
date: 2022-06-29
draft: false
tags: ["JAVA"]
categories: ["JAVA"]
---

### Java数组的练习

#### 使用一维数组，模拟栈数据结构。

```java
public class Test {
    public static void main(String[] args) {
        MyStack myStack = new MyStack();
        myStack.push(new Object());
        myStack.push(new Object());
        System.out.println(myStack.pop());
    }
}
class MyStack{
    // 为什么选择Object类型数组？因为这个栈可以存储java中的任何引用类型的数据,因为所有类的父类是Object。
    // 包括String也可以存储进去。因为String父类也是Object。
    // 一维数组动态初始化,默认初始化容量是10.
    private Object[] elements = new Object[10];
    // 栈帧，永远指向栈顶部元素
    // 那么这个默认初始值应该是多少。注意：最初的栈是空的，一个元素都没有。
    // private int index = 0; // 如果index采用0，表示栈帧指向了顶部元素的上方。
    // private int index = -1; // 如果index采用-1，表示栈帧指向了顶部元素。
    // 给index初始化
    private int index = -1;
    public void push(Object obj){
        if(this.index >= this.elements.length-1){
            System.out.println("压栈失败，栈已满！");
            return;
        }
        // 程序能够走到这里，说明栈没满
        // 向栈中加1个元素，栈帧向上移动一个位置。
        this.elements[++index] = obj;
        // 在声明一次:所有的System.out.println()方法执行时，如果输出引用的话，自动调用引用的toString()方法。
        System.out.println("压栈" + obj + "元素成功，栈帧指向" + index);
    }
    public Object pop(){
        if(this.index < 0){
            System.out.println("弹栈失败，栈已空！");
            return null;
        }
        // 程序能够执行到此处说明栈没有空。
        System.out.print("弹栈" + elements[index] + "元素成功，");
        // 栈帧向下移动一位。
        this.index--;
        System.out.println("栈帧指向" + index);
        return elements[index];
    }
}
```

#### 实现一个简单的酒店管理系统

Room

```java
public class Room {
    private int no;
    private String type;
    private boolean status;
    public Room(){super();};
    public Room(int no, String type, boolean status){
        super();
        this.no = no;
        this.type = type;
        this.status = status;
    }
    public int getNo(){
        return this.no;
    }
    public String getType(){
        return this.type;
    }
    public void setStatus(boolean status){
        this.status = status;
    }
    public boolean getStatus(){
        return this.status;
    }

    @Override
    public String toString() {
        return "["+"房间号"+this.getNo()+","+"房间类型"+this.getType()+","+"状态"+(this.getStatus()?"空闲":"占用")+"]";
    }
}
```

Hotel

```java
public class Hotel {
    // 酒店对象,酒店中有二维数组,二维数组模拟大厦。
    private Room[][] rooms;
    // 盖楼通过构造方法来盖楼。
    public Hotel(){
        super();
        // 动态初始化
        rooms = new Room[3][4];
        // 创建12个Room对象，放到数组当中。
        for (int i = 0; i < this.rooms.length; i++) {
            for (int j = 0; j < this.rooms[i].length; j++) {
                // 一层
                if(i == 0){
                    rooms[i][j] = new Room(((i+1)*100+j+1),"单人间",true);
                }else if(i == 1){ // 二层
                    rooms[i][j] = new Room(((i+1)*100+j+1),"标准间",true);
                }else if(i == 2){ // 三层
                    rooms[i][j] = new Room(((i+1)*100+j+1),"总统套房",true);
                }
            }
        }
    }
    public void printRoomStatus(){
        for (int i = 0; i < this.rooms.length; i++) {
            for (int j = 0; j < this.rooms[i].length; j++) {
                Room room = this.rooms[i][j];
                System.out.print(room);
            }
            System.out.println();
        }
    }
    public void order(int roomNo){
        Room room = this.rooms[roomNo / 100 - 1][roomNo % 100 - 1];
        // 修改为占用。
        room.setStatus(false);
        System.out.println(roomNo + "已订房！");
    }
    public void exit(int roomNo){
        Room room = this.rooms[roomNo / 100 - 1][roomNo % 100 - 1];
        // 修改为空闲。
        room.setStatus(true);
        System.out.println(roomNo + "已退房！");
    }
}
```

Test

```java
import java.util.Scanner;

public class Test {
    public static void main(String[] args) {
        System.out.println("功能编号对应的功能：[1]表示查看房间列表。[2]表示订房。[3]表示退房。[0]表示退出系统。");
        Hotel hotel = new Hotel();
        Scanner scanner = new Scanner(System.in);
        while (true){
            System.out.print("请输入功能编号：");
            int input = scanner.nextInt();
            if(input == 1){
                hotel.printRoomStatus();
            }else if(input == 2){
                System.out.print("请输入订房编号：");
                int roomId = scanner.nextInt();
                hotel.order(roomId);
            }else if(input == 3){
                System.out.print("请输入退房编号：");
                int roomId = scanner.nextInt();
                hotel.exit(roomId);
            }else if(input == 0){
                System.out.println("再见，欢迎下次再来！");
                return;
            }else {
                System.out.println("输入功能编号有误，请重新输入！");
            }
        }
    }
}
```

