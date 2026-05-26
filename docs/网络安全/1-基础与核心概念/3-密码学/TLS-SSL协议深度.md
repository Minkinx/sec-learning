# TLS-SSL协议深度

> TLS（传输层安全协议）是互联网上应用最广泛的加密通信协议，保证HTTP、FTP、SMTP等应用层协议的数据机密性和完整性。理解TLS对安全从业者至关重要。

## 协议版本演进

| 版本 | RFC | 发布时间 | 状态 | 说明 |
|------|-----|---------|------|------|
| SSL 1.0 | 未发布 | 1994（内部） | ❌ 从未公开发布 | 存在严重安全缺陷 |
| SSL 2.0 | 无 | 1995 | ❌ **禁止使用** | 多个安全缺陷（无证书校验、MAC弱） |
| SSL 3.0 | RFC 6101 | 1996 | ❌ **禁止使用** | POODLE攻击影响 |
| TLS 1.0 | RFC 2246 | 1999 | ❌ **禁止使用** | CBC模式缺陷（BEAST攻击） |
| TLS 1.1 | RFC 4346 | 2006 | ❌ **已废弃** | 改进了CBC向量初始化 |
| TLS 1.2 | RFC 5246 | 2008 | ✅ **使用中** | 当前主流，支持AEAD |
| TLS 1.3 | RFC 8446 | 2018 | ✅ **强烈推荐** | 减少握手延迟、移除不安全算法 |

## TLS 1.2 vs TLS 1.3 对比

| 特性 | TLS 1.2 | TLS 1.3 |
|------|---------|---------|
| 握手往返次数 | 2-RTT | 1-RTT（0-RTT可选） |
| 支持的密码套件 | 30+种 | 5种（均为AEAD） |
| 前向安全性 | 可选（部分密码套件不支持） | **强制**（所有套件） |
| 静态RSA密钥交换 | 支持（无前向安全性） | **已移除** |
| 压缩 | 支持（CRIME攻击） | **已移除** |
| 重协商 | 支持（复杂，安全风险） | **已移除** |
| 会话恢复 | Session ID/Ticket | PSK + 0-RTT |
| 加密告警 | 部分 | 所有告警加密 |
| 签名算法 | 在Certificate消息中协商 | 在ClientHello中协商 |
| 虚假启动 | 非标准扩展 | 内建支持 |

### TLS 1.3 密码套件（仅5种）

| 套件 | 认证 | 密钥交换 | AEAD |
|------|------|---------|------|
| TLS_AES_128_GCM_SHA256 | 任意 | (EC)DHE | AES-128-GCM |
| TLS_AES_256_GCM_SHA384 | 任意 | (EC)DHE | AES-256-GCM |
| TLS_CHACHA20_POLY1305_SHA256 | 任意 | (EC)DHE | ChaCha20-Poly1305 |
| TLS_AES_128_CCM_SHA256 | 任意 | (EC)DHE | AES-128-CCM |
| TLS_AES_128_CCM_8_SHA256 | 任意 | (EC)DHE | AES-128-CCM-8 |

## TLS 1.3 握手流程

```
ClientHello（支持密码套件、Key Share）
  │ 包含：支持的版本、密码套件、Client Random、
  │       ECDHE公钥（Key Share扩展）
  ▼
ServerHello（选择套件、Key Share）
  │ 包含：选择的版本、密码套件、Server Random、
  │       ECDHE公钥、服务器证书链
  │
  │ ← 双方已通过ECDHE计算出共享密钥 →
  │
EncryptedExtensions
Certificate（已加密）
CertificateVerify（对握手消息签名）
Finished（HMAC认证）
  │
  ▼
Client → 服务器：
  Certificate（如有需要）
  CertificateVerify
  Finished

**此时已建立加密连接：1-RTT完成握手**
```

**0-RTT**（Early Data）：
- 允许客户端在第一个消息中发送应用数据
- 用于重复连接（使用PSK恢复会话）
- 安全风险：不具备前向安全性（若PSK泄露，0-RTT数据被解密）

## 常见攻击与漏洞

| 攻击 | 目标版本 | 原理 | 防御 |
|------|---------|------|------|
| **BEAST** | TLS 1.0 | CBC IV预测，逐字节解密HTTP Cookie | 升级至TLS 1.1+ |
| **POODLE** | SSL 3.0 | 利用填充oracle解密数据 | 禁用SSL 3.0 |
| **CRIME** | TLS压缩 | 利用压缩率差异窃取会话Cookie | 禁用TLS压缩（TLS 1.3已移除） |
| **Heartbleed** | OpenSSL实现 | 心跳扩展缓冲区过度读取（泄露内存） | 升级至OpenSSL 1.0.1g+ |
| **FREAK** | 导出级密码套件 | 强制降级至弱RSA-512 | 禁用FREAK导出套件 |
| **Logjam** | DHE交换 | 强制降级至弱DH参数（512位） | 使用≥2048位DH参数 |
| **Downgrade** | 跨版本 | 拦截握手强制使用较低版本 | TLS 1.3内建降级保护 |
| **BREACH** | HTTP压缩 | 类似CRIME的攻击 | 禁用HTTP压缩或使用CSRF token随机化 |
| **ROBOT** | RSA-KEM | Bleichenbacher oracle变体 | 使用ECDHE、禁用RSA加密 |

## 最佳实践

### 服务器配置建议
```
# nginx + TLS 1.3 配置示例
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305;

ssl_prefer_server_ciphers on;

# 严格安全头
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

# 会话缓存（TLS 1.2兼容）
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

### HSTS（HTTP Strict Transport Security）
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```
- `max-age`：该站点仅可通过HTTPS访问的时间（秒）
- `includeSubDomains`：子域名同样生效
- `preload`：提交至浏览器内置HSTS预加载列表

### 证书验证链
```
Root CA（自签名）→ Intermediate CA → 服务器证书
         ↓                    ↓
  浏览器信任锚             包含AI扩展指向Issuer
```

### 证书类型
| 类型 | 验证级别 | 适用场景 |
|------|---------|---------|
| DV | 域名验证 | 个人网站、测试 |
| OV | 组织验证 | 商业网站 |
| EV | 扩展验证 | 金融、政府（浏览器显示绿色） |

## 检测与排错工具

### testssl.sh
```bash
# 安装
git clone https://github.com/drwetter/testssl.sh.git

# 全面测试
./testssl.sh --full example.com

# 测试特定漏洞
./testssl.sh --heartbleed example.com
./testssl.sh --poodle example.com
./testssl.sh --freak example.com

# 列出支持的密码套件
./testssl.sh --ciphers example.com
```

### OpenSSL CLI
```bash
# 查看远程服务器证书
openssl s_client -connect example.com:443 -servername example.com

# 测试TLS 1.3连接
openssl s_client -connect example.com:443 -tls1_3

# 查看证书详情
openssl s_client -connect example.com:443 -showcerts

# 生成CSR
openssl req -new -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr
```

## 参考

- RFC 8446: TLS Protocol Version 1.3
- RFC 5246: TLS Protocol Version 1.2
- OWASP: Transport Layer Protection Cheat Sheet
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org
- Qualys SSL Labs: SSL Server Test
