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

## 参考标准

- NIST SP 800-52 Rev.2 (TLS Implementation)
- IETF RFC 8446 (TLS 1.3)
- OWASP Transport Layer Protection Cheat Sheet
- Mozilla TLS Guidelines (https://wiki.mozilla.org/Security/Server_Side_TLS)
