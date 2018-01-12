---
layout: post
title: Wechall WriteUp
date: 2018-1-12
author: Qiqi
catlog: true
header-img: img/write-up.png
catalog: true
tag:
   - write up
---

# We Chall WriteUp

本人特别菜，刚刚入门不久，无意中发现了这个国外的网站，感觉题目很有意思，可以学到不少东西，wp持续更新

## Prime Factory

直接上python

```python
  1 import math
  2
  3 results = []
  4 def sushu(num):
  5     for i in range(2, num):
  6     ¦   if num % i == 0:
  7     ¦   ¦   return False
  8     return True
  9
 10 def digit_sum(num):
 11     sum = 0
 12     divide = 1000000
 13     while divide > 0:
 14     ¦   sum += num / divide
 15     ¦   num %= divide
 16     ¦   divide /= 10
 17     return sum
 18
 19 cnt = 0
 20 for i in range(1000000, 2000000):
 21     print "trying", i
 22     if sushu(i) and sushu(digit_sum(i)):
 23     ¦   results.append(i)
 24     ¦   cnt += 1
 25     if cnt == 2:
 26     ¦   break
 27
 28 print str(results[0]) + str(results[1])
```



## Training: Get Sourced

查看源代码

拉到最下方，有一行注释`<!-- You are looking for this password: html_sourcecode -->`



## Training: Stegano I

用0xED打开图片，查看16进制码

![](https://ws1.sinaimg.cn/large/006Vib6xly1fnclscoz31j30ki01mmxg.jpg)



## Crypto - Caesar I

还是用python跑一下，看看哪个长得像答案

```Python
  1 #coding:utf-8
  2
  3 s = raw_input('input the ciphertxt:')
  4 for i in range(26):
  5     flag = ''
  6     for j in s:
  7     ¦   if j != ' ':
  8     ¦   ¦   flag += chr((ord(j) - ord('A') + i) % 26 + ord('A'))
  9     ¦   else:
 10     ¦   ¦   flag += ' '
 11     print flag
```

```
THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG OF CAESAR AND YOUR UNIQUE SOLUTION IS LESIAGFMGLLG
```



## Training: WWW-Robots

没什么好说的，robots协议，<a href='https://en.wikipedia.org/wiki/Robots_exclusion_standard'>Robots exclusion standard</a>(不了解的可以看一下)

直接访问http://www.wechall.net/robots.txt

获得下一个URLhttp://www.wechall.net/challenge/training/www/robots/T0PS3CR3T



## Training: ASCII

这题太直白，直接ASCII码转字符`The solution is: sshcbslrspcf`



## Encodings - URL

同样直白的一道题，URL编码和Unicode编码

解码得到

```
Yippeh! Your URL is challenge/training/encodings/url/saw_lotion.php?p=rosmidrpmpgl&cid=52#password=fibre_optics Very well done!

```

或者用python

```Python
>>> import urllib
>>> url = '%59%69%70%70%65%68%21%20%59%6F%75%72%20%55%52%4C%20%69%73%20%63%68%61%6C%6C%65%6E%67%65%2F%74%72%61%69%6E%69%6E%67%2F%65%6E%63%6F%64%69%6E%67%73%2F%75%72%6C%2F%73%61%77%5F%6C%6F%74%69%6F%6E%2E%70%68%70%3F%70%3D%73%68%67%73%61%6D%6F%67%6D%73%6C%72%26%63%69%64%3D%35%32%23%70%61%73%73%77%6F%72%64%3D%66%69%62%72%65%5F%6F%70%74%69%63%73%20%56%65%72%79%20%77%65%6C%6C%20%64%6F%6E%65%21'
>>> print urllib.unquote(url)
Yippeh! Your URL is challenge/training/encodings/url/saw_lotion.php?p=shgsamogmslr&cid=52#password=fibre_optics Very well done!
```



## Training: Encodings I

ascii是七位的编码,总共用8个bit存储,最高位恒为0

而本题是7的倍数，所以将其7个一组划分后进行解码

得到`This text is 7-bit encoded ascii. Your password is easystarter.`



## Guesswork

这题居然就是单纯的猜密码，我也是很醉

我一开始猜wechall，发现不对，然后又瞎试了一些，根据错误信息来看，还是wechall更接近，但实在是猜不出黎，于是去看了别人的writeup，发现密码是wechallbot，bot是wechall的身份。。。我表示很无语



## No Escape

看一下代码关键处

```php
function noesc_voteup($who)
{
        if ( (stripos($who, 'id') !== false) || (strpos($who, '/') !== false) ) {
                echo GWF_HTML::error('No Escape', 'Please do not mess with the id. It would break the challenge for others', false);
                return;
        }
 
 
        $db = noesc_db();
        $who = GDO::escape($who);
        $query = "UPDATE noescvotes SET `$who`=`$who`+1 WHERE id=1";
        if (false !== $db->queryWrite($query)) {
                echo GWF_HTML::message('No Escape', 'Vote counted for '.GWF_HTML::display($who), false);
        }
        
        noesc_stop100();
}
```

关键语句

```php
$query = "UPDATE noescvotes SET `$who`=`$who`+1 WHERE id=1";
```
是一道简单的sql注入题
闭合`号，加#或者—+注释，注意，#需要URL编码（%23）
最终构造的url为

```
http://www.wechall.net/challenge/no_escape/index.php?vote_for=bill`=111--+
```



## Training: Regex

### Level 1

匹配一个空字符串，学习匹配匹配字符串开头结尾的两个符号：`/^$/`

### Level 2

匹配"wechall"，`/^wechall$/`

### Level 3

匹配以wechall或wechall4位文件名，并以.jpg/.gif/.tiff/.bmp/.png为后缀的文件名，`/^wechall4?\\.(?:jpg|gif|tiff|bmp|png)$/`

### Level 4

捕获文件名，`/^(wechall4?)\\.(?:jpg|gif|tiff|bmp|png)$/`



## Training: PHP LFI

这是一道php文件包含漏洞的题，<a href=https://en.wikipedia.org/wiki/File_inclusion_vulnerability>LFI vulnerability</a>

```php
1 $filename = 'pages/'.(isset($_GET["file"])?$_GET["file"]:"welcome").'.html';
2 include $filename;
```

题目已经给出了关键信息，而参数file也没有任何过滤

直接访问http://www.wechall.net/challenge/training/php/lfi/up/index.php?file=../solution.php

报错信息如下：

```
PHP Warning(2): include(pages/../solution.php.html): failed to open stream: No such file or directory in www/challenge/training/php/lfi/up/index.php(54) : eval()'d code line 1
```

提示说找不到`../solution.php.html`这个文件

所以我们用00截断，过滤掉后面的`.html`

```
PHP Warning(2): include(pages/../solution.php): failed to open stream: No such file or directory in www/challenge/training/php/lfi/up/index.php(54) : eval()'d code line 1
```

依然提示说找不到`../solution.php`

于是，添加一个目录，访问http://www.wechall.net/challenge/training/php/lfi/up/index.php?file=../../solution.php%00



## PHP 0817

这应该算不上文件包含

php中如果switch是数字类型的case的判断时，switch会将其中的参数转换为int类型

所以我们让参数which的值等于solution就好



## Training: Crypto - Transposition I

这题一眼就能出来吧，每两个字符颠倒一下顺序



## Training: Crypto - Substitution I

替换密码，<a href=https://en.wikipedia.org/wiki/Substitution_cipher>Substitution cipher</a>

直接上在线工具就好，<a href=https://quipqiup.com/>quipquip</a>



## Training: MySQL I

最简单的SQL注入，闭合加注释，让Username等于admin'#即可



## Training: MySQL II

看一下源码

```php
        $db = auth2_db();
        
        $password = md5($password);
        
        $query = "SELECT * FROM users WHERE username='$username'";
        
        if (false === ($result = $db->queryFirst($query))) {
                echo GWF_HTML::error('Auth2', $chall->lang('err_unknown'), false);
                return false;
        }
        
        
        #############################
        ### This is the new check ###
        if ($result['password'] !== $password) {
                echo GWF_HTML::error('Auth2', $chall->lang('err_password'), false);
                return false;
        } #  End of the new code  ###
        #############################
```

是拿Username去获取结果，将获得的password与输入的password的md5值进行比较

这样思路就很明确了，让`Username=‘ union select 1, 'admin', 'c4ca4238a0b923820dcc509a6f75849b'#` `Password=1`

其中md5(1) == c4ca4238a0b923820dcc509a6f75849b

成功绕过判断



## Training: Register Globals

还是看一下源码

```php
if (isset($login))
{
        echo GWF_HTML::message('Register Globals', $chall->lang('msg_welcome_back', array(htmlspecialchars($login[0]), htmlspecialchars($login[1]))));
        if (strtolower($login[0]) === 'admin') {
                $chall->onChallengeSolved(GWF_Session::getUserID());
        }
}
```

注意到只需要满足$login[0] == admin就可以了，所以我们在url上加上?login[0]=admin即可



## Training: Math Pyramid

这题真的坑，出题人太坏了，故意给出sqrt来误导你，其实这题十分简单，就是a^3/18^.5



## Training: LSB 

直接上神器Stegsolve，看一下各个通道就能找到答案



## Stegano Attachment

链接打开是一张图片，不管先扔到binwalk下看看`binwalk attachment.jpg`

发现

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
20230         0x4F06          Zip archive data, at least v2.0 to extract, compressed size: 12, uncompressed size: 12, name: solution.txt
20342         0x4F76          End of Zip archive
```

从偏移量为20230开始，隐藏了一个zip压缩包

分离一下`dd if=attachment.jpg of=solution.zip skip=20230 bs=1`

打开压缩包，有一个叫`solution.txt`的文件，打开就是答案
