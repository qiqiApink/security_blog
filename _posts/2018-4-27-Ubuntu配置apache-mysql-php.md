---
layout: post
title: Ubuntu配置Apache+MySQL+多版本PHP
date: 2018-4-27
author: Qiqi
header-img: img/CQUecTuFuRg.jpg
catalog: true
tag:
   - Ubuntu
   - Apache
   - MySQL
   - PHP
---

# Ubuntu 配置apache+mysql+多版本php

> 环境：ubuntu LTS 16.04

### 安装apache2

`sudo apt-get install -y apache2`

### 安装mysql

ubuntu16.04自带mysql5.7

```
sudo apt install -y mysql-server mysql-client libmysqlclient-dev mysql-workbench
```

### 安装多版本php

#### 安装php5.6

```
sudo add-apt-repository ppa:ondrej/php
sudo apt-get update
sudo apt-get install -y php5.6-common php5.6-mbstring php5.6-mcrypt php5.6-mysql php5.6-xml php5.6-gd php5.6-curl php5.6-json php5.6-fpm php5.6-zip php5.6-mcrypt libapache2-mod-php5.6 --allow-unauthenticated
```

#### 安装php7.0

```
sudo apt-get install -y php7.0-common php7.0-mbstring php7.0-mcrypt php7.0-mysql php7.0-xml php7.0-gd php7.0-curl php7.0-json php7.0-fpm php7.0-zip php7.0-mcrypt libapache2-mod-php7.0 --allow-unauthenticated
```

#### 安装php7.1

```
sudo apt-get install -y php7.1-common php7.1-mbstring php7.1-mcrypt php7.1-mysql php7.1-xml php7.1-gd php7.1-curl php7.1-json php7.1-fpm php7.1-zip php7.1-mcrypt libapache2-mod-php7.1 --allow-unauthenticated
```

#### 开启重写转向

```
sudo a2enmod rewrite
sudo a2enmod headers
```

然后我们重启一下apache2`sudo service apache2 restart`

#### 自定义命令切换php版本

编辑`.bashrc`，加入自定义命令，方便不同版本的php切换

```
alias php56='sudo a2dismod php7.0 && sudo a2dismod php7.1 && sudo a2enmod php5.6 && sudo service apache2 restart'
alias php70='sudo a2dismod php5.6 && sudo a2dismod php7.1 && sudo a2enmod php7.0 && sudo service apache2 restart'
alias php71='sudo a2dismod php5.6 && sudo a2dismod php7.0 && sudo a2enmod php7.1 && sudo service apache2 restart'
```

如果你还安装了其他版本的php，同理仿照上面的方式改写一下就好

编辑完成后`source .bashrc`即可

现在默认是运行5.6版本的php（命令行下php -v查看版本，默认显示最高版本）

命令行下使用`php70`即可切换至php7.0版本，`php71`也是同理

如果你对不同版本的php有配置要求，在`/etc/php`，目录下有对应版本号的文件夹，编辑相应的`php.ini`即可

### 让不同网站加载不同的php版本

编辑`httpd.conf`如下：

```
<VirtualHost *:80>
    ServerName my.aaa.com
    DocumentRoot "/var/www/html/aaa"
    ErrorLog "/var/log/error_log"
    CustomLog "/var/log/access_log" common
    <FilesMatch \.php$>
         SetHandler "proxy:unix:/run/php/php5.6-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>

<VirtualHost *:80>
    ServerName my.bbb.com
    DocumentRoot "/var/www/html/bbb"
    Errorlog "/var/log/error_bbb_log"
    CustomLog "/var/log/acess_bbb_log" common
    <FilesMatch \.php$>
         SetHandler "proxy:unix:/run/php/php7.1-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
```

有可能会遇到找不到`httpd.conf`的情况

`vim /etc/apache2/apache2.conf`

添加

```
# Include all the user configurations: 
Include /etc/apache2/httpd.conf 
```

然后我们去`/etc/apache2`目录下创建一个`httpd.conf`文件就可以了
