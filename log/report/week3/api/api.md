## weblogic常见通信模式

最常见：Web浏览器：服务器通过HTTP或HTTPS与Web浏览器进行交互

Java客户端：用Java编写客户端应用程序，如cve-2023-21839，就是用Java客户端

WLST客户端：WLST（WebLogic Scripting Tool）是用于管理WebLogic Server的脚本化工具。可编写WLST脚本来与WebLogic Server进行交互，执行各种管理任务

RESTful客户端：WebLogic Server还提供了支持RESTful架构风格的API，可使用任何支持HTTP请求的客户端框架或工具与这些API进行交互。常见的工具包括cURL、Postman、Swagger等

Web服务端之间通信：WebLogic Server支持使用SOAP协议通过Web服务进行通信。可使用任何支持SOAP的客户端框架或工具，如Apache Axis、Apache CXF等，与WebLogic Server上的Web服务进行交互

**后续主要研究RESTful API 和 SOAP协议**

## weblogic 的java客户端搭建

**java客户端需要把weblogic的作为依赖库，进行相关类和方法的调用**

weblogic 10之前，需要把核心的jar包搜索起来打包成一个package，将这个package整体作为模块依赖导入

weblogic10之后，通过命令java -jar jarbuilder.jar 去生成一个wlfullclient的jar文件，文件大小有100多M，创建java客户端之后导入这个jar包作为模块依赖

weblogic14之后，为了减少客户端大小，只保留weblogic thin t3 client的jar包，大小为9M，weblogic thin t3 client在server/lib目录下，创建java客户端之后导入这个jar包作为模块依赖，功能相对之前的客户端相对较少，但仍然保留了核心功能

## weblogic常见API划分

![image-20230620001439603](.\image-20230620001439603.png)

链接：[BEA WebLogic Server and WebLogic Express 8.1 Programming Documentation (oracle.com)](https://docs.oracle.com/cd/E13222_01/wls/docs81/api.html)

在weblogic12.1.3之后，支持RESTful API

weblogic14.1.1的API：

[Oracle WebLogic Server 14.1.1.0.0 - Reference](https://docs.oracle.com/en/middleware/standalone/weblogic-server/14.1.1.0/reference.html)

对于Java API，目前还没有完全把远程API和内部API划分出来，不过经过查找资料，jndi，management，rmi等包下的所有API应该都算是远程API，而jdbc，logging等包下的API则可能是内部API。

此外，如果需要账号密码登录认证的API，如管理类API，则更加安全，相反不需要认证的可直接调用的API则相对危险。

### java 客户端的一些demo代码：

**调用jms相关API**

```
import javax.jms.*;
import javax.naming.*;

public class test {
    public static void main(String[] args) {
        try {
            // 获取InitialContext，用于查找JMS连接工厂和队列
            System.setProperty(Context.INITIAL_CONTEXT_FACTORY, "weblogic.jndi.WLInitialContextFactory");
            Context context = new InitialContext();
            ConnectionFactory connectionFactory = (ConnectionFactory) context.lookup("jms/ConnectionFactory");
            Queue queue = (Queue) context.lookup("jms/MyQueue");

            // 创建JMS连接、会话和消息生产者
            Connection connection = connectionFactory.createConnection();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageProducer producer = session.createProducer(queue);

            // 创建消息
            TextMessage message = session.createTextMessage("Hello, WebLogic JMS!");

            // 发送消息
            producer.send(message);
            System.out.println("Message sent successfully.");

            // 关闭连接和会话
            session.close();
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

**调用management相关API**

```
import javax.management.*;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.lang.management.ManagementFactory;

public class manage {
    public static String getIpAndPort(){
        try {
            System.setProperty(Context.INITIAL_CONTEXT_FACTORY, "weblogic.jndi.WLInitialContextFactory");
            InitialContext initialContext = new InitialContext();
            MBeanServer tMBeanServer;
            MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
            tMBeanServer = (MBeanServer) initialContext.lookup("java:comp/env/jmx/runtime");
            ObjectName tObjectName = new ObjectName(
                    "com.bea:Name=RuntimeService,Type=weblogic.management.mbeanservers.runtime.RuntimeServiceMBean");
            ObjectName serverrt = (ObjectName) tMBeanServer.getAttribute(tObjectName, "ServerRuntime");
            String port = String.valueOf(tMBeanServer.getAttribute(serverrt, "ListenPort"));
            String listenAddr = (String) tMBeanServer.getAttribute(serverrt, "ListenAddress");
            String[] tempAddr = listenAddr.split("/");
            if (tempAddr.length == 1) {
                listenAddr = tempAddr[0];
            } else if (tempAddr[tempAddr.length - 1].trim().length() != 0) {
                listenAddr = tempAddr[tempAddr.length - 1];
            } else if (tempAddr.length > 2) {
                listenAddr = tempAddr[tempAddr.length - 2];
            }
            StringBuilder sBuilder = new StringBuilder(listenAddr);
            sBuilder.append(":");
            sBuilder.append(port);
            System.out.print(sBuilder);
            return sBuilder.toString();
        } catch (NamingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (MalformedObjectNameException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InstanceNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (AttributeNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ReflectionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (MBeanException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        System.out.println(getIpAndPort());
    }
}
```

**使用JNDI相关API**

```
import javax.naming.Context;
        import javax.naming.InitialContext;
        import javax.naming.NamingException;

public class JndiClientExample {
    public static void main(String[] args) {
        Context context = null;

        try {
            // 创建初始上下文
            context = new InitialContext();

            // 连接到命名服务，这里的 "jndi/provider/url" 是命名服务的 URL，根据实际情况进行设置
            context.addToEnvironment(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.fscontext.RefFSContextFactory");
            context.addToEnvironment(Context.PROVIDER_URL, "file:/path/to/jndi/provider/url");

            // 使用上下文查找并获取对象，这里的 "jndi/object/name" 是要查找的对象的名称，根据实际情况进行设置
            Object obj = context.lookup("jndi/object/name");

            // 根据实际情况对获取的对象进行类型转换和操作
            // ...
        } catch (NamingException e) {
            e.printStackTrace();
        } finally {
            // 关闭 JNDI 上下文连接
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```



### WLST客户端使用t3协议和服务器进行通信，并抓包查看数据：

WLST客户端的路径为Oracle\Middleware\Oracle_Home\oracle_common\common\bin\wlst.cmd，启动客户端之后可以通过connect 命令去连接weblogic服务器

![image-20230620144533105](C:\Users\Jack\Desktop\Doc\api\image-20230620144533105.png)

连接上服务器之后，可以在客户端中执行命令，部分命令内容如下：

![image-20230620144836891](C:\Users\Jack\Desktop\Doc\api\image-20230620144836891.png)

执行ls()命令，返回如下：

![image-20230620144959626](C:\Users\Jack\Desktop\Doc\api\image-20230620144959626.png)

在发起connect的时进行抓包，可以看到客户端和服务器通过t3协议通信：

![image-20230620145229752](C:\Users\Jack\Desktop\Doc\api\image-20230620145229752.png)

在发起执行ls()命令的时进行抓包，可以看到服务器以明文返回的目录内容(在tcp流中搜索的ManagedExecutorServiceTemplates是目录下的其中一个文件)：

![image-20230620145416547](C:\Users\Jack\Desktop\Doc\api\image-20230620145416547.png)

### 问题:

如何快速排除所有内部API

weblogic 14的文档说已经移除了wlfullclient，但是API中很多对象 在wlthint3client中并不包含   