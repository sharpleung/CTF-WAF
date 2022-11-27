## CTF-WAF
## 描述

项目年久失修，直接重构了，删除原有的过滤功能，毕竟规则不够完善拦截是没法拦截了，因此修改为黑名单BAN-IP功能。在比赛前可以将选手的IP都放在black.txt中，如果是选手的IP对我们靶机访问则返回404.同时优化了了日志记录功能可以记录文件上传等信息。

~~该项目针对CTF线下AWD比赛临时开发的WAF，能够拦截XSS、SQl、反序列化、菜刀/蚁剑、以及一些CTF常见的危险函数流量。可以绕过对页面检测的check,拦截返回正常页面的html。并且能够对简单payload进行流量转发，自动反打设置好的IP。如果比赛禁止使用通防也可以一键关闭通防，作为流量监控审计所用。欢迎各位大佬对项目进行改进。使用时候可以使用.user.ini将其包含于所有php文件。~~

## 联系方式
- ![](https://img.shields.io/badge/%E4%BD%9C%E8%80%85-Gqleung-brightgreen.svg)  

- [![](https://img.shields.io/badge/%E5%8D%9A%E5%AE%A2-xiao%20leung's%20Blog-blueviolet)](https://www.plasf.cn)
##  目录结构

```http
CTF_WAF.php(WAF主要文件)
log.php(日志审计系统)
```

## 使用方法

- 将`CTF_WAF.php`包含进需要保护的文件

### 设置黑名单IP以及日志地址

#### 方法一

在代码`CTF_WAF.php`第二行直接设置IP即可，第一行即可设置日志地址，建议设置绝对路径如:`/tmp/log.txt`

![image-20221126004745717](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260048967.png)

#### 方法二

批量设置，在同文件夹新建一个`black.txt`存放要BAN的IP地址。

![image-20221126004845378](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260049258.png)

#### 效果

封禁前：

![image-20221126005215483](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260052352.png)

封禁后：

![image-20221126005322868](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211272013500.png)

显示404

![image-20221126005355454](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260053844.png)

### 日志审计系统

日志审计系统与上一版基本一致：

![image-20221126005630822](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260056957.png)

输入账号密码即可登录，密码在`log.php`膝盖即可，同理需要设置日志路径。

![image-20221126005729676](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211272013681.png)

使用效果，匹配到疑似攻击事件，上传事件均会告警。

![image-20221126005850831](https://gqleung.oss-cn-guangzhou.aliyuncs.com/img/202211260059553.png)

