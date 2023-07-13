- #### 自己写爬虫爬取weblogic console的页面，从html中得到所有页面以及相应参数（即参数对应的当前页面），然后获取当前页面的提交参数，如post的参数或者get参数

​		爬取分析，由于爬虫是为了获取整个网站所有get和post请求，get请求相当方面，一般都是存储在a标签中的href属性中，而post请求分为两类，一种是写在form表单中，通过表单提交的post请求，一种是写在javascript中，通过按钮执行js脚本，通过js脚本提交的post请求一般都是对服务器的内容进行操作，如创建新服务器、创建新域之类的，所以主要提取form表单中的post即可。

​		爬取思路，通过爬虫程序get_spider对深度优先遍历爬取所有的a标签，提取所有url并把url输出到一个文件中，通过爬虫程序post_spider遍历url文件，然后提取每个url中的post表单，解析表单中的参数生成一个个的post请求，写入文件中

​		由于写入文件的格式和之前rad程序的输出保持一致，所以可以直接使用xss_scan程序检测是否存在xss漏洞

- #### weblogic 数据库是否存在sql注入等漏洞，查看它的内置数据库

  weblogic包含一个存储系统，是一个内置的持久化框架，用于存储各种类型的数据，包括事务日志，JMS消息，定时器等，存储系统可以配置为两种类型：

  文件存储：即将数据存储在文件系统上的存储系统。每个文件存储都有一个专用的目录，WebLogic在这个目录中创建文件以保存持久化数据。

  JDBC存储：即将数据存储在关系数据库中的存储系统。JDBC存储使用JDBC数据源连接到数据库，并在数据库中创建表来保存数据。JDBC存储提供了更高级的持久化选项，比如在不同的服务器或集群之间共享数据。

  如果需要用到JDBC存储，并产生写入过程，则需要一个具体的应用场景，如存储JMS消息：

  1. 创建一个数据源，数据源指定为mysql数据库，使用mysql创建一个本地数据，并给出用户名密码

     ![image-20230710234131629](.\images\image-20230710234131629.png)

  2. 创建一个持久化存储，持久化存储选择JDBC作为数据源

     ![image-20230710234242513](.\images\image-20230710234242513.png)

  3. 创建一个JMS服务器，持久化存储选择之前创建的持久化存储对象

     ![image-20230710234350047](.\images\image-20230710234350047.png)

  4. 创建一个JMS模块，并在这个模块新建两个资源，一个连接工厂，一个队列，并记录他们相应的JNDI名称

     ![image-20230710234714993](.\images\image-20230710234714993.png)

  5. 在weblogic服务中部署一个web项目，并使用这个连接工厂和队列，在队列中写入持久化存储的消息，weblogic将会把这个消息写入JDBC数据库

     ```java
     package Servlets;
     
     import javax.jms.*;
     import javax.naming.InitialContext;
     import javax.servlet.ServletException;
     import javax.servlet.annotation.WebServlet;
     import javax.servlet.http.HttpServlet;
     import javax.servlet.http.HttpServletRequest;
     import javax.servlet.http.HttpServletResponse;
     import java.io.IOException;
     
     @WebServlet("/jms")
     public class Servlet_JMS extends HttpServlet {
         @Override
         protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
             super.doGet(req, resp);
         }
     
         @Override
         protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
             try {
                 InitialContext ctx = new InitialContext();
                 Queue queue = (Queue) ctx.lookup("newqueue");
                 ConnectionFactory cf = (ConnectionFactory) ctx.lookup("newfactory");
                 try (Connection connection = cf.createConnection();
                      Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
                      MessageProducer producer = session.createProducer(queue)) {
                     String text = request.getParameter("message");
                     TextMessage message = session.createTextMessage(text);
                     producer.setDeliveryMode(DeliveryMode.PERSISTENT);
                     producer.send(message);
                 }
             } catch (Exception e) {
                 throw new ServletException(e);
             }
         }
     }
     
     ```

     6. 数据库中存储的内容发生了一些变化

        ![image-20230710235425199](.\images\image-20230710235425199.png)

  

- #### 创建服务器，执行命令等api进行分析，查看是否对命令进行过滤，是否存在可能的命令执行


rest api 无法命中断点，不确定在哪执行了命令以及对rest api进行解析

![image-20230711002837093](.\images\image-20230711002837093.png)