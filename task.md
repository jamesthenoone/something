### 1.抓包分析客户端和weblogic的通信，尝试解密分析

### 2.系统分析weblogic开放哪些应用接口，这些接口具有什么功能，用户界面接口（黑盒），开放的外部API（半白盒测试），外部API通过查询文档了解 

- #### 把所有api的url路径按功能分类，如用户和管理员，导出json格式，至少包括rest和网页url两部分

- #### xss批量测试payload，dvwa先验证  

- #### 创建服务器，执行命令等api进行分析，查看是否对命令进行过滤，是否存在可能的命令执行

- #### weblogic 数据库是否存在sql注入等漏洞，查看它的内置数据库

- #### 自己写爬虫爬取weblogic console的页面，从html中得到所有页面以及相应参数（即参数对应的当前页面），然后获取当前页面的提交参数，如post的参数或者get参数

### 3.使用工具对这些所有接口进行扫描

### 4.熟悉weblogic 内存马运行原理

#### 



**Restful API功能已经基本了解**

**外部API 测试**

Restful API 测试

手动测试，使用postman，burpsuite等工具抓包，编写js脚本，测试响应结果

自动测试，使用工具扫描，如netsparker、vooki等

SOAP API 测试

手动测试 

自动测试

**用户界面API测试**

通过xray等工具扫描

**weblogic内存马运行原理**

