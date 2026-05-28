# TLS/SSL 最佳实践

## 概述

TLS（Transport Layer Security）是数据传输安全的基础保障。随着 TLS 1.0/1.1 的弃用，企业需要及时迁移到 TLS 1.2/1.3，并遵循密码学最佳实践进行配置。

## TLS 1.2 vs TLS 1.3 对比

| 特性 | TLS 1.2 (RFC 5246) | TLS 1.3 (RFC 8446) |
|------|---------------------|---------------------|
| 握手轮次 | 2-RTT | 1-RTT (0-RTT for resumption) |
| 已淘汰算法 | — | 移除 RC4、3DES、CBC 模式 |
| 密钥交换 | 多种可选 | 仅支持 (EC)DHE |
| 签名算法 | RSA/ECDSA/EdDSA | 同左 |
| 会话恢复 | Session ID/Ticket | PSK + 0-RTT |
| 前向安全性 | 可选配置 | 强制要求 |
| 密码套件数量 | 30+ | 5 (TLS_AES_128_GCM_SHA256 等) |

## 密码套件选择

### 推荐的密码套件优先级 (TLS 1.2)

```
1. TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (P-256/256)
2. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (P-256/256)
3. TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (P-384/384)
4. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (P-384/384)
```

### 需禁用的密码套件

| 密码套件 | 风险 | 替代方案 |
|----------|------|----------|
| TLS_RSA_WITH_AES_128_CBC_SHA | 无 PFS, CBC padding oracle | ECDHE + GCM |
| TLS_ECDH_anon_WITH_AES_128_CBC_SHA | 无认证 | 禁用 |
| TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA | 3DES 强度不足 | AES-GCM |
| TLS_RSA_WITH_RC4_128_SHA | RC4 已破解 | AES-GCM/ChaCha20 |

## 证书管理

### 公钥基础设施 (PKI)

```
Root CA (Offline, HSM 保护)
  └── Intermediate CA (Online, 签发服务器证书)
       ├── Server Cert A (example.com)
       ├── Server Cert B (api.example.com)
       └── Server Cert C (*.example.com)
```

- 使用 2048+ bit RSA 或 ECDSA P-256/P-384 密钥
- 证书有效期建议不超过 1 年（90 天更优，如 Let's Encrypt）
- 实施 Automated Certificate Management Environment (ACME)

### Certificate Pinning

- **HPKP (Deprecated)**：已废弃，不再使用
- **静态 pinning**：在客户端硬编码证书哈希（适用于自有设备）
- **动态 pinning**：通过信任 on-first-use (TOFU) 建立

## HSTS (HTTP Strict Transport Security)

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `max-age`：至少 1 年（31536000 秒）
- `includeSubDomains`：覆盖所有子域
- `preload`：提交至浏览器 preload list
- **注意**：确保所有子域均支持 HTTPS，否则导致不可访问

## OCSP Stapling

- 服务器定期从 CA 获取 OCSP 响应并缓存
- 在 TLS 握手中将 OCSP 响应发送给客户端
- 减少客户端直接查询 OCSP responder 的延迟
- 增强隐私（CA 无法追踪客户端访问的站点）

## 性能优化

| 优化技术 | 效果 | 说明 |
|----------|------|------|
| TLS 1.3 0-RTT | 减少 1 RTT | 需防重放攻击 |
| Session Resumption | 减少 1 RTT | 使用 Session Ticket |
| OCSP Stapling | 减少 1 RTT | 消除客户端 OCSP 查询 |
| False Start | 减少 1 RTT | TLS 1.2 优化 |
| TCP Fast Open | 减少 1 RTT | TCP 层优化 |
| HTTP/2 Multiplexing | 减少连接数 | 单连接复用 |

## Mutual TLS (mTLS)

mTLS 实现双向认证，适用于零信任网络和服务间通信：

```
客户端                         服务端
  │                               │
  │──── ClientHello ────────────→ │
  │←── ServerHello + Cert + Verify─│
  │──── Client Certificate + ───→ │
  │      CertificateVerify        │
  │←── Server Finished ────────── │
  │──── Client Finished ────────→ │
  │←──── Encrypted Data ────────→ │
```

- 在微服务架构中广泛使用（Istio/Linkerd 默认启用）
- 配合 SPIFFE 实现 workload identity
- 证书轮换通过 sidecar proxy 自动完成

## 服务器配置示例

### Nginx 安全配置

```nginx
# /etc/nginx/conf.d/tls.conf
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # 证书路径
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # TLS 协议配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;  # TLS 1.3 不需要此选项

    # 推荐的密码套件顺序 (TLS 1.2 兼容)
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

    # DH 参数 (2048 bit 以上)
    ssl_dhparam /etc/ssl/dhparam.pem;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout 5s;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Session 缓存
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets off;
}
```

### Apache 安全配置

```apache
# /etc/httpd/conf.d/tls.conf
<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    # TLS 协议
    SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
    SSLProxyProtocol        all -SSLv3 -TLSv1 -TLSv1.1

    # 密码套件
    SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    SSLHonorCipherOrder     on

    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    # OCSP Stapling
    SSLUseStapling          on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache        shmcb:/var/run/ocsp(128000)

    # Session 缓存
    SSLSessionCache         shmcb:/var/run/ssl_cache(512000)
    SSLSessionCacheTimeout  300
</VirtualHost>
```

### AWS ALB (Application Load Balancer) 配置

AWS ALB 通过 AWS CLI 或 Console 配置 TLS 策略：

```bash
# 使用 AWS CLI 创建 HTTPS 监听器，引用安全策略
aws elbv2 create-listener \
    --load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123 \
    --protocol HTTPS \
    --port 443 \
    --certificates CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/abc123 \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
    --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/xyz789
```

**推荐的 AWS 安全策略**：

| 策略名称 | TLS 1.3 | TLS 1.2 | 前向安全 | 适用场景 |
|----------|---------|---------|----------|----------|
| ELBSecurityPolicy-TLS13-1-2-2021-06 | 支持 | 支持 | 强制 | 通用推荐（PCI DSS 合规） |
| ELBSecurityPolicy-TLS13-1-2-Res-2021-06 | 支持 | 支持 | 强制 | 更高安全需求 |
| ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06 | 支持 | 支持 | 强制 | 兼容遗留客户端 |
| ELBSecurityPolicy-2016-08 | 不支持 | 支持 | 可选 | 仅兼容旧客户端 |

### 配置安全性检查清单

| 检查项 | 检查方法 | 通过标准 |
|--------|----------|----------|
| TLS 协议版本 | nmap --script ssl-enum-ciphers | 仅 TLSv1.2+ |
| 弱密码套件 | testssl.sh 扫描 | 无 RC4/3DES/CBC |
| 证书有效性 | openssl verify | 未过期，链完整 |
| HSTS 配置 | curl -I | max-age ≥ 31536000 |
| OCSP Stapling | openssl s_client -status | OCSP response present |
| 前向安全性 | testssl.sh -P | 所有套件支持 PFS |
| CRIME/BREACH 攻击 | testssl.sh 扫描 | 不脆弱 |

## 证书生命周期管理

### Let's Encrypt + Certbot 自动化

```bash
# 安装 Certbot (Nginx 插件)
sudo certbot --nginx -d example.com -d www.example.com

# DNS-01 挑战 (通配符证书)
sudo certbot certonly --manual --preferred-challenges dns \
    -d example.com -d *.example.com

# 自动续期 (默认 Certbot 自动执行)
sudo certbot renew --dry-run  # 验证续期流程
```

### Kubernetes cert-manager 集成

```yaml
# Issuer 定义 (Let's Encrypt 生产环境)
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
    - http01:
        ingress:
          class: nginx
---
# 证书申请
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-tls
  namespace: default
spec:
  secretName: example-com-tls
  duration: 2160h   # 90 天
  renewBefore: 360h # 提前 15 天续期
  dnsNames:
  - example.com
  - www.example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

### 证书类型选型指南

| 证书类型 | 验证层级 | 适用场景 | 成本 |
|----------|----------|----------|------|
| DV (Domain Validation) | 域名控制权验证 | 一般 Web 服务 | 免费（Let's Encrypt） |
| OV (Organization Validation) | 组织身份验证 | 企业官网、API 服务 | 中等 |
| EV (Extended Validation) | 严格组织验证 | 金融机构、政务网站 | 高 |
| 通配符 (Wildcard) | 覆盖子域名 | 多子域统一管理 | 中-高 |
| 私有 CA | 内部信任链 | 内部服务 mTLS | 自建成本 |

## 参考标准

- NIST SP 800-52 Rev.2 (TLS Implementation)
- IETF RFC 8446 (TLS 1.3)
- OWASP Transport Layer Protection Cheat Sheet
- Mozilla TLS Guidelines (https://wiki.mozilla.org/Security/Server_Side_TLS)
- Let's Encrypt ACME Protocol (RFC 8555)
- cert-manager.io 官方文档
