### 通过爬虫，列出url中所有api，并按照功能分类

通过awvs对weblogic进行扫描，但是只能得到网站的目录结构，无法直接获取所有url

![image-20230707165918072](.\image-20230707165918072.png)

通过rad爬虫得到的json文件，得到的json文件中只有4个url路径，实际通过点击发现所有参数都是提交到console.portal路径下，所有页面的变化都只是提交的参数发生变化（但是rad对dvwa的测试表现正常，可以爬取dvwa的所有url）

尝试crawlgo对weblogic进行扫描，但由于登录原因无法完整获取weblogic所有url



### 编写XSS payload，先用dvwa测试

**xss检测程序设计：**

xss检测程序的输入为两个文件，第一个文件是url文件，每一行代表一个url，可能是get类型或者post类型，第二个文件是xss payload，每一行都是一个要测试的xss payload

程序有两个模块，输入模块，用于处理所有的url和xss payload输入，检测模块，检测模块将访问构造好的url，并根据响应来判断该url是否存在xss

程序会首先读取xss payload文件，并将所有payload存在列表payload_list中，然后读取所有url，并将所有url存在列表url_list中，然后对于每一个url，都分析url是post型还是get型， 并得到url的参数，然后用payload_list去替换url中的参数，并发出request请求，再从收到的response中的html中判断该url是否存在xss，如此对每个url进行这样的测试

**dvwa测试**

通过rad对dvwa.com进行扫描，扫描得到的结果放入dvwa_scan.json文件中，代表所有可以访问的url，xss payload可以在网上查找，放入txt中即可，直接运行扫描程序即可测试出dvwa中存在xss的url

![image-20230706235553430](.\image-20230706235553430-16886589581691.png)

### Rest API测试

**批量测试工具：**

apisec\veracode scan这两个商业软件提供api批量扫描的功能，但是只能对公网ip的api进行扫描，只能将weblogic上线公网，才能使用这种工具开始扫描

astra是开源测试工具，从功能页面上看可以导入swagger文件

原版astra无法正常安装，容器中启动的是python2，但是运行程序却提示要python3,网上相关教程非常少，最后根据其他人的pull request摸索出了安装astra的步骤：

1. 参考[flipkart-incubator/Astra: Automated Security Testing For REST API's (github.com)](https://github.com/flipkart-incubator/Astra/pull/136)的pull request
2. 从[naturedamends/Astra at add-dev-containers (github.com)](https://github.com/naturedamends/Astra/tree/add-dev-containers)下载文件，进入到.devcontainer中，运行docker-compose up -d, 等待所有文件安装完成
3. docker ps 列出devcontainer的容器id，docker exec -it id /bin/bash 进入容器，运行python celery_app.py，创建app/logs/scan.log文件，运行celery -A celery_app worker --loglevel=INFO，退出终端，该终端作用为执行命令之后的日志输出
4. docker exec -it id /bin/bash 进入容器，查看当前容器的ip，运行python app.py 启动flask服务，在外部可以通过localhost:8094访问；或者在容器内部通过python astra.py运行命令行版本程序

![image-20230707003822320](C:.\image-20230707003822320-16886615039433.png)

![image-20230707004530025](.\image-20230707004530025.png)

![image-20230707004003968](.\image-20230707004003968.png) 



