---
layout: post
title: 搭建OWASP Juice Shop测试环境，并搭建CTF环境
subtitle: 一个Web漏洞测试环境，包含了最常见的10大漏洞
date: 2018-2-3
author: Qiqi
header-img: img/tag-bg-o.jpg
catalog: true
tag:
   - Mac
   - Web安全
   - CTF
---

# 搭建OWASP Juice Shop测试环境，并搭建CTF环境

> 安装环境：Mac OS X

##  本地安装

首先要安装Node.js，直接用homebrew安装

在命令行上运行

```Shell
git clone https://github.com/bkimminich/juice-shop.git
```

进入克隆的文件夹

```shell
 cd juice-shop
```

运行

```Shell
npm install
```

这只需在第一次启动之前或者在更改源代码之后完成

运行

```shell
npm start
```

以启动应用程序

浏览到[http://localhost:3000](http://localhost:3000/)，如果能正常访问到OWASP Juice Shop的页面，那么恭喜你，安装成功了

## 为Juice Shop设立CTFd

Juice Shop提供了[方便的`juice-shop-ctf-cli`工具](https://github.com/bkimminich/juice-shop-ctf) 来简化使用开源[CTFd](https://ctfd.io/)框架的CTF的托管 

### 用C＃生成CTFd挑战 juice-shop-ctf-cli

安装juice-shop-ctf-cli:

```shell
 npm install -g juice-shop-ctf-cli
```

然后运行该工具

```Shell
juice-shop-ctf
```

这个工具现在会问一系列的问题。所有问题都有默认答案，您可以通过简单的选择`ENTER`来完成

1. **果汁店网址来检索挑战？**

   默认 `https://juice-shop.herokuapp.com`

2. **密钥 ctf.key文件的URL？**

   默认为`https://raw.githubusercontent.com/bkimminich/juice-shop/master/ctf.key`

3. **插入一个文字提示以及每个CTFd挑战？**

   * `No text hints`将不会向CTFd挑战添加任何提示文本，这是默认选择

   * `Free text hints`将从Juice Shop数据库中添加`Challenge.hint`

     作为提示添加到CTFd服务器上相应的挑战，查看这个提示是免费的

   * `Paid text hints`如上所述添加每个挑战的提示，查看这个提示会使团队花费10％的挑战得分值

4. **在每个CTFd挑战中插入一个提示URL？**

   * `No hint URLs`不会向CTFd挑战添加任何提示URL，这是默认选择

   * `Free hint URLs`将从Juice Shop数据库中添加`Challenge.hintUrl`

     作为提示给CTFd服务器上相应的挑战，查看这个提示是免费的

   * `Paid hint URLs`如上所述添加每个挑战的提示，查看这个提示花费20％的挑战的分数值的团队

每个挑战的类别与Juice Shop数据库中的类别相同。每个挑战的得分值由`juice-shop-ctf-cli`程序计算：

- 一星级挑战= 100分
- 2星级挑战= 250分
- 三星级挑战赛= 450分
- 四星级挑战= 700分
- 五星级的挑战= 1000点

该工具的整个输出将最终写入 `OWASP_Juice_Shop.YYYY-MM-DD.zip`程序启动的文件夹中

### 运行CTFd

获取CTFd:

 ```shell
git clone https://github.com/CTFd/CTFd.git
 ```

安装Flask：

```Shell
sudo pip install flask
```

安装完成后需要的环境就好了！下面安装CTFd

```shell
cd CTFd #进入目录
sudo ./prepare.sh #安装依赖
sudo python serve.py #运行程序
```

这里可能需要用python3来运行（总之，我用python2安装dataset库的时候，一直出错，没找到解决办法）

浏览到[http://localhost:4000](http://localhost:4000/)，如果运行成功的话，应该是管理员账号注册的界面

我们创建一个管理员账号，并给CTF起个名字

提交后可能会有报错，根据报错提示，安装相应的库（我这里安装的是bcrypt库）

进入到刚才安装完成的CTFd环境后台中，选择【Config】-【Backup】-【Import】导入安装包（这里注意，我们只选择challenge选项）

完成之后，查看Challenges即可看到已经安装成功

![](https://ws1.sinaimg.cn/large/006Vib6xgy1fo3gct9yuij30xy0j7wg2.jpg)

测试平台默认是不显示flag的，所以我们在要设置一下

```shell
export NODE_ENV=ctf
npm start
```

这样，就大功告成了

快来开启你的游戏之旅吧

> 参考文章：https://www.gitbook.com/book/bkimminich/pwning-owasp-juice-shop
