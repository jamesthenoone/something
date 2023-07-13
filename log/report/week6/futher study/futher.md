## post请求分析

### 地址不为主页的post请求分析

经过测试，所有post地址不为主页http://127.0.0.1:7001/console/console.portal的post请求的body都具有类似的格式，格式为

```json
要post的参数&
_nfpb=true&
xxx_actionOverride=%2FSharedPreferencesUpdatedAction&
_windowLabel=xxx&
xxxPortletfrsc=0xed5f19555386e73fd70e6369b352d82505977d700da36015

几个实际的例子：
SharedPreferencesPortletpreferences.serverInvokeTimeout=200&SharedPreferencesPortletpreferences.followChanges=false&_nfpb=true&SharedPreferencesPortlet_actionOverride=%2FSharedPreferencesUpdatedAction&_windowLabel=SharedPreferencesPortlet&SharedPreferencesPortletfrsc=0xed5f19555386e73fd70e6369b352d82505977d700da36015

GlobalPreferencesPortletpreferences.showInlineHelp=on&GlobalPreferencesPortletpreferences.showInlineHelp=true&GlobalPreferencesPortletpreferences.fileBrowserStart=%5C&GlobalPreferencesPortletpreferences.rememberLastPath=on&GlobalPreferencesPortletpreferences.rememberLastPath=true&GlobalPreferencesPortletpreferences.rememberedPathCount=4&GlobalPreferencesPortletpreferences.showAdvanced=false&GlobalPreferencesPortletpreferences.refreshinterval=10&GlobalPreferencesPortletpreferences.confirmationExplicit=on&GlobalPreferencesPortletpreferences.confirmationExplicit=true&GlobalPreferencesPortletpreferences.warnUserHoldsLock=false&GlobalPreferencesPortletpreferences.activationTimeout=300&GlobalPreferencesPortletpreferences.warnUserTakingLock=false&GlobalPreferencesPortletpreferences.optionalFeatures=&_nfpb=true&_windowLabel=GlobalPreferencesPortlet&GlobalPreferencesPortlet_actionOverride=%2FUserPreferencesUpdatedAction&GlobalPreferencesPortletfrsc=0xed5f19555386e73fd70e6369b352d82505977d700da36015

SharedPreferencesPortletpreferences.serverInvokeTimeout=200&SharedPreferencesPortletpreferences.followChanges=false&_nfpb=true&SharedPreferencesPortlet_actionOverride=%2FSharedPreferencesUpdatedAction&_windowLabel=SharedPreferencesPortlet&SharedPreferencesPortletfrsc=0x5585f36d87f065ae44614b0091c7adb94a2335ff538f6be2

ExtensionPreferencesPortletpreferences.displayDefinitionLabels=false&_nfpb=true&ExtensionPreferencesPortlet_actionOverride=%2FExtensionPreferencesUpdatedAction&_windowLabel=ExtensionPreferencesPortlet&ExtensionPreferencesPortletfrsc=0x5585f36d87f065ae44614b0091c7adb94a2335ff538f6be2
```

对于最后三个参数，如果对其中某些值进行修改则会对最终的post请求结果产生影响

```
xxx_actionOverride=%2FSharedPreferencesUpdatedAction&
_windowLabel=xxx&
xxxPortletfrsc=0xed5f19555386e73fd70e6369b352d82505977d700da36015
```

**xxx_actionOverride**

xxx_actionOverride这个字段对应是提交的路由，对xxx_actionOverride对应的值进行修改时，服务器就会报错，如果直接删除这个字段，那么post请求的提交将不会成功（没有saved successfully），例如post请求包如下：

```
POST /console/console.portal?_nfpb=true&_pageLabel=SharedPreferencesPageGeneral&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29 HTTP/1.1
Host: 127.0.0.1:7001
Content-Length: 318
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:7001
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:7001/console/console.portal?_nfpb=true&_pageLabel=SharedPreferencesPageGeneral&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: ADMINCONSOLESESSION=zgdCesVKymWvqvFnbCata2anMG-9iwT7SjqqwQdqVk478oFAYTjA!-936241992
Connection: close

SharedPreferencesPortletpreferences.serverInvokeTimeout=300&SharedPreferencesPortletpreferences.followChanges=false&_nfpb=true&SharedPreferencesPortlet_actionOverride=%2FSharedPreferencesUpdatedAction&_windowLabel=SharedPreferencesPortlet&SharedPreferencesPortletfrsc=0xed5f19555386e73fd70e6369b352d82505977d700da36015
```

如果把SharedPreferencesPortlet_actionOverride=%2FSharedPreferencesUpdatedAction内容改为SharedPreferencesPortlet_actionOverride=%2FSharedPreferencesUpdated的话，console中会报错Invalid Path

![image-20230712111209599](C:\Users\Jack\Documents\report\week6\futher study\image-20230712111209599.png)

**_windowLabel**

_windowLabel这个参数似乎并不重要，无论是修改值还是直接删除都不影响返回的结果

**xxxPortletfrsc**

xxxPortletfrsc对应的值似乎是服务器启动之后产生的唯一标识（可能与用户的cookie相关），每次启动weblogic产生的这个值都不一样，但是在启动之后每个post请求附带的这个值都是相同的。如果修改这个参数或者删除这个参数，那么post请求将提交失败，并且直接会重定向到登录页面。

#### 尝试白盒测试，但无法找到准确的入口

![image-20230713164912220](C:\Users\Jack\Documents\report\week6\futher study\image-20230713164912220.png)

#### 对console的其他分析

console的实际web应用程序应该放在E:\Oracle\Middleware\Oracle_Home\wlserver\server\lib\consoleapp\webapp目录下，之前通过awvs对weblogic console进行扫描，得到了网站的文件目录结构

![image-20230707165918072](C:\Users\Jack\Documents\report\week6\futher study\1.png)



访问[127.0.0.1:7001/console/css/login.css](http://127.0.0.1:7001/console/css/login.css)，可以获得相应的css文件，在weblogic安装目录中的E:\Oracle\Middleware\Oracle_Home\wlserver\server\lib\consoleapp\webapp\css\下找到相同文件

![image-20230713170429873](C:\Users\Jack\Documents\report\week6\futher study\image-20230713170429873.png)

同时E:\Oracle\Middleware\Oracle_Home\wlserver\server\lib\consoleapp\webapp\layouts目录下存在着jsp文件，访问网页[127.0.0.1:7001/console/layouts/configBaseLayoutWithButtons_netui.jsp](http://127.0.0.1:7001/console/layouts/configBaseLayoutWithButtons_netui.jsp)可以执行其中的jsp文件，但是自己创建hello.jsp并在网址中访问会显示资源不存在，应该是所有的jsp文件都要通过某种注册才能在网页中显示

