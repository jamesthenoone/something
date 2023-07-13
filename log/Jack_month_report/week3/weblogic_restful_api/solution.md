## 对RESTful API 进行测试：

### 1.手动测试：

**官方文档查到的API可以放到postman里发出不同类型的request，也可以和burpsuite一起测试**

使用burpsuite和postman可以对某些api进行单独测试，通过postman确定正常访问服务器API时的回应，通过burpsuite修改某些参数尝试得到不一样的结果

![image-20230625235352204](.\image-20230625235352204.png)



![image-20230625235456877](.\image-20230625235456877.png)

对于不使用Https，只使用基本认证的数据包，可以通过burpsuite暴力破解

![image-20230626000503120-1687709110951-1](.\image-20230626000503120-1687709110951-1.png)



![image-20230626000530890](.\image-20230626000530890.png)



**可以将API的swagger文件下载下来，导入postman，然后在postman中就可以看到所有的API以及相应的测试用例，但API太多，无法对每个都测试**

![image-20230626090557899](.\image-20230626090557899.png)

### 2.自动测试（使用扫描工具）：

大多数工具都不支持对RESTful API进行批量扫描

- Vooki可以对单个RESTful API扫描，无法设置认证方式，但basic  authentication认证可以通过url设置

  ![image-20230626004538635](.\image-20230626004538635.png)

  

- netsparker可能可以进行批量扫描，但操作相对复杂，且无法直接导入swagger文件，不过可以通过导入postman文件来获取所有API，在获取API之后好像无法设置认证方式，最后扫描效果不好[Netsparker Standard如何扫描RESTful API Web服务_「Netsparker Standard 中文汉化使用教程」 - 网安 (wangan.com)](https://www.wangan.com/docs/736)

![image-20230626004728338](.\image-20230626004728338.png)



- veracode scan可以对多个RESTful API进行批量扫描，并可以设置认证，不过属于商业软件需要收费[How to Scan an API | Veracode Docs](https://docs.veracode.com/r/api-scanning)
- 尚未测试：w3af、[Astra](https://github.com/flipkart-incubator/Astra)



