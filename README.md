## CTF-WAF
## 描述
该项目针对CTF线下AWD比赛临时开发的WAF，能够拦截XSS、SQl、反序列化、菜刀/蚁剑、以及一些CTF常见的危险函数流量。可以绕过对页面检测的check,拦截返回正常页面的html。并且能够对简单payload进行流量转发，自动反打设置好的IP。如果比赛禁止使用通防也可以一键关闭通防，作为流量监控审计所用。欢迎各位大佬对项目进行改进。使用时候可以使用.user.ini将其包含于所有php文件。
## 联系方式
- ![](https://img.shields.io/badge/%E4%BD%9C%E8%80%85-Gqleung-brightgreen.svg)  

- [![](https://img.shields.io/badge/%E5%8D%9A%E5%AE%A2-xiao%20leung's%20Blog-blueviolet)](https://www.plasf.cn)
##  目录结构

```http
CTF_WAF.php(WAF主要文件)
waflog(文件夹)
	.........ip.txt(需要反打的ip)
	.........log.php(日志审计系统)
```

## 使用方法

- 将`CTF_WAF.php`包含进需要保护的文件

- 开启`WAF`开关（`CTF_WAF.php`代码27行），设置返回页面（`CTF_WAF.php`代码26行）,

```php
$this->Waf_switch=1;//通防开启
$this->Waf_switch=0;//通防关闭
$this->resultPage="http://127.0.0.1/";//返回页面
```

- 设置需要反打（流量转发）的主机，在`waflog/ip.txt`

![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/15688766013040.png)

- 模拟对本地主机进行攻击，可以发现并不会返回flag，说明对payload拦截成功

![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/pic2.png)

- 查看`waflog`文件夹下发现生成了logs.txt和flag.txt说明生成了日志文件和flag文件，打开即可看到ip对应的flag

**![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/pic3.bmp)**

- 修改日志系统密码`/waflog/log.php`代码4行，修改密码

```php
$passwd="admin";//修改密码
```

-   登陆后台发现记录了攻击payload。

![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/pic4.png)

