---
layout: post
title: "MotionGPT: Finetuned LLMs are General-Purpose Motion Generators"
author: Qiqi
date: 2023-5-26
header-img: img/post-bg-blog.jpg
catalog: true
tag:
   - Crypto
   - Writeup
---

# MotionGPT: Finetuned LLMs are General-Purpose Motion Generators

有一个加密的压缩包，需要获得密码

打开`known.txt`

```
plaintext:ciphertext
jYj0ApA8korwFrDKhkBsyAfcklX81hYr:IB8hBnIHFQkRBAERABwFCDsPe0AadDEZJVkIbWMyFzo=
cneHLYmfgGRgrTg1AvOaSwH3h0B16EAq:KSgufn8uOVcdLCEBNDomchISdlIwQh9JJgUSZGQfDzk=
aLErGX34qivXaOyg91E3DPCMYZgBRH5O:KwoORHQvZwULAgU+JyE4JGpVfAAnZRQ3F283FwASewc=
```

大致长这样

尝试对`ciphertext`base64解码，发现解码后的长度为32，和`plaintext`一样，容易想到亦或

随便选取一行进行亦或，得到`JFK63wT1zksfFnACSd93c5WzN5PURZNH`

没什么意义

文件夹中还有一个`password.enc`文件，打开也有一个base64编码的字符串，尝试解码发现也是32位，再亦或

代码如下：

```python
import base64

cipher = base64.b64decode('ExcKewcfFkdOWEYpISUbFSseXX8wQB0Le3kDByMcLQQ=')
plain = 'YQAM4hBv435OgKZVxzdLSuJq5LSRqFcL'
passwd = base64.b64decode('CzVrT1wCdFoUBARGMgYgN3McVkFDQzIINxUjPD8qIi0=')
key = ''
result = ''
for i in range(len(plain)):
    key += chr(ord(plain[i])^ord(cipher[i]))

for i in range(len(key)):
    result += chr(ord(key[i])^ord(passwd[i]))

print result
```

得到密码：`As you know that xor very simple`

成功解压，得到两个文件

`known.txt`

```
plaintext:ciphertext
RL{2B6r}PjD4bW0sQLU5pDxKjh77msLK:zwX4G1C8MgE0QK{yDwI5VEOtgb33nywt
BR08l4n0Pzxit9D}sZQSbCUxJaHjCFB4:Gz{2A0p{MBOsS9E8y}DxQTIOfmLgTPG0
RLLFnQZcOxBKG2TRUnpZ9XwgpEfjHxcf:zwwPpD}aHOGtW4FzIpV}9eJUVhugLOau
vzPTSaPL4u5PKJBxxMHUIgiyC9mek}4v:rBMFxmMw0j5MtfGOOcLINUsRT9nYq80r
```

`flag.enc`:`uAmUXk{jW{Stp{JpMA0spF7OS0SS0aq8`

经过观察发现是替换密码

得到flag：`flag{Y0uG0tKn0wnPl4inT3xt4tt4ck}`
