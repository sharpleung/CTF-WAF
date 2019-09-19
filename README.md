## CTF-通防日志审计系统

##  目录结构

```http
CTF_WAF.php(WA主要文件)
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

**![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/pic1.bmp)**

- 修改日志系统密码`/waflog/log.php`代码4行，修改密码

```php
$passwd="admin";//修改密码
```

-   登陆后台发现记录了攻击payload。

![img](https://raw.githubusercontent.com/sharpleung/CTF-WAF/master/picture/pic4.png)

