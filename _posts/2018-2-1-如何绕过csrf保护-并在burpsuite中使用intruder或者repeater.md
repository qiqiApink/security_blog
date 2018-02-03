---
layout: post
title: 如何绕过csrf保护，并在burp suite中使用intruder或者repeater？
subtitle: 转载一篇不错，很实用的文章
date: 2018-2-1
author: Qiqi
header-img: img/post-bg-blog.jpg
catalog: true
tag:
   - CSRF
   - Web安全
   - Burp Suite
---

# 如何绕过csrf保护，并在burp suite中使用intruder或者repeater？

> 转载一篇不错很实用的文章，也根据自己的实践作出了细微的补充

我使用burp suite已经很多年了，但是我使用intruder模块时几乎不会使用宏设置。直到几个星期前，我在爆破某表单时，使用了这一功能。需要爆破的页面中使用了JavaScript生成CSRF token并写入表单中，那么我就需要从JavaScript代码中取出token的值，然后每次发出请求时，带上这一变量。我查阅了相关文档，找到了解决方法。在真实环境测试之前，我搭建了一个模拟真实环境的页面，在这个页面进行测试。以下就是我的测试步骤。

## 配置环境

以下代码就是我们用于测试的代码，你可以在本地搭建起来或者使用<a href="https://vuln-demo.com/burp_macro/macro.php">我搭建好的环境</a>

```php+HTML
<?php
session_start();

$message = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
 if (array_key_exists ("token", $_POST) && array_key_exists ("token", $_SESSION)) {
 if (array_key_exists ("token", $_SESSION)) {
 if ($_POST['token'] == $_SESSION['token']) {
 $message = "Success";
 } else {
 $message = "Tokens don't match";
 }
        } else {
 $message = "Token not in session";
 }
    } else {
 $message = "Token not sent in POST";
 }
}
$token = md5(mt_rand());
$_SESSION['token'] = $token;
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title>Burp Suite Macro Demo Test Page</title>
    <meta name="Description" content="A page to use to practice with Burp Suite macros and session handling" />
</head>
<body>
<h1>Burp Suite Macro Test Form</h1>
<p>This form is designed to be used alongside the <a href="https://digi.ninja/blog/burp_macros.php">Burp Macros and Session Handling</a> blog post by <a href="https://digi.ninja/">Robin Wood</a>.</p>
<p><?=$message?></p>
<form method="post" action="<?=htmlentities ($_SERVER['PHP_SELF'])?>">
    <input type="submit" value="Submit" name="submit" />
    <input type="hidden" value="" name="token" id="token" />
</form>
<script>
 document.getElementById("token").value = "<?=htmlentities ($token)?>";
</script>
</body>
</html>
```

从代码中可以看到：

GET请求情况下，一旦访问页面，会话就会开始，并且token就会生成存储到session中。token的生成过程是这样的，首先在输入框中生成一个空的token，然后利用JavaScript将生成的token写入到输入框当中，并提交。如果javascript不运行，那么token的值就是空。

POST请求下，提交的token值会和session中存储的值进行比较，如果它们能够匹配，那么就会得到成功的信息。要不就会提示出错，然后生成一个新的token值存储到session当中去。

因为Burpsuite不会运行JavaScript，所以Repeater和Intruder模块运行过程中都会提交空的或者之前的token值，然后得到token不匹配的错误。需要解决这一问题，我在这里用到了几乎没有用过的宏模块。

## 攻击过程

首先，打开burp并且在浏览器中设置代理，确保所有的请求都会经过burp。我假设你已经完成了这一步骤。如果你没有使用过burp，我建议你去了解一些关于burp的基础知识。完成此操作后，浏览测试页面，并且提交几次表单，然后在代理记录中找到这些记录。

我们已经完成了基本设置，现在我们要做的是生成一个宏。打开”Project Options”选项栏，然后切换到Sessions选项中，在Macros模块中点击Add：

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14bo40iij30k00mt0uf.jpg)

点击之后会弹出”Macro Editor”(宏编辑)对话框，在对话框中点击”Macro Recorder”(宏录制)模块:

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14dw0q1jj30k00ic40g.jpg)

上图中你可以看到，我发出了三个POST请求和一个GET请求。选择其中一个POST请求点击ok，返回宏编辑对话框中。

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14ejvwewj30k00ddq43.jpg)

为宏命名(Macro description)之后，点击”Configure Item”(配置项目)。

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14fsyqgwj30k00ghjs1.jpg)

> 我在实践的时候，Parameter handling选项中没有submit这一项，不过并不影响

上图中，burp大概完成了我们需要完成的工作，但是这里发生了一些错误，因为当前显示的token内容是从已经使用的POST请求中取出来的值，因此是不正确的token值。我们要做的是从javascript代码中取出不断变化的token，然后提交。那么我们现在点击ADD按钮，然后会弹出一个名为”自定义参数”新的对话框。

在这个对话框中要求我们提供变量名字，在实例中我们将这一变量命名为token。然后在请求包中，标记出来token的值，这就告诉burp我们需要提取的变量值在哪个位置。

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14lx9e1fj30k00m0jt8.jpg)

至此，你已经创建出来符合条件的宏，它会在每个请求中将token填充到合适的位置。接下来点击确定，然后关闭所有的对话框，回到burp的主窗口。

在”Marco Editor”对话框中有一个”Test macro”(测试宏)的按钮，用来测试捕获得到的token是否符合我们的预期，在这里没有发生什么特殊情况，完全正确。

在”Session Handling Rules”(会话处理规则)选项栏中，点击Add按钮，会弹出”Session handling rule editor”(会话处理规则编辑器)对话框。这里填写名称，然后点击Add添加规则动作。这里会给出一个下拉菜单，显示可以执行的不同类型的规则：

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14puza8jj30hl0f7gm5.jpg)

> 这里我们选择Run a macro

下方图片是”Session Handling Action Editor”(会话处理规则编辑器)界面，在这里你可以选择你要运行的宏，然后指定哪些参数和哪些cookies会被更新。我们选择了之前创建的”Macro Demo”宏，并且将其他参数作为默认值。

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14qfwazhj30jw0at74z.jpg)

点击ok会返回”会话规则处理编辑器”页面进行最后一步设置，切换到Scope栏框：

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14r1nn2sj30gq0fa751.jpg)

在这里我对宏的适用范围进行了自定义设置，将我测试的url填写到里面。

现在所有的设置已经完成，为了测试设置是否正确，我们重新发送了之前的POST请求，如果设置是正确的，那么就会返回success信息。并且你会发现token这一变量每次发送请求都会自己变化：

![](https://ws1.sinaimg.cn/large/006Vib6xly1fo14rtjxvmj30k00brt9w.jpg)

这就是我测试的全部步骤，Repeater以及intruder都可以无视csrf的保护进行使用。

> 本文翻译自：<a href="https://digi.ninja/blog/burp_macros.php">digi.ninja</a>，如若转载，请注明原文地址：，如若转载，请注明原文地址：http://www.4hou.com/technology/10134.html
