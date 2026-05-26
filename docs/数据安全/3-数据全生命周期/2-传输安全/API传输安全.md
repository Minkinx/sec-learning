# API 传输安全

## 概述

API 是现代应用的核心通信方式，REST、gRPC、GraphQL 各有不同的安全考量。API 传输安全需要在传输层、消息层和应用层建立多层次的保护机制。

## REST/gRPC/GraphQL 安全对比

| 安全维度 | REST | gRPC | GraphQL |
|----------|------|------|---------|
| 传输层安全 | TLS (HTTPS) | TLS (HTTP/2) | TLS (HTTPS) |
| 认证方式 | OAuth2/JWT/API Key | SSL/TLS mTLS + Token | OAuth2/JWT |
| 授权粒度 | URL + Method | Service/Method | Field-level (Resolver) |
| 请求验证 | JSON Schema | Protocol Buffers | Schema validation |
| 查询复杂度 | 固定 endpoint | 固定 RPC | 可变 query（需分析深度） |
| 审计 | 标准 HTTP logging | Interceptor 实现 | Resolver logging |

## TLS Enforcement

### 强制 TLS

```nginx
# Nginx 配置：拒绝非 TLS 请求
server {
    listen 80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    # TLS 配置...
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
}
```

### API Gateway 层面的 TLS 终止与传递

```
Client ───TLS──→ API Gateway ───TLS/mTLS──→ Backend Service
                    │
                TLS Termination     TLS Re-encryption
```

- 外部使用标准 TLS 连接 API Gateway
- 内部服务间使用 mTLS 或应用层加密
- 避免"TLS 终止后明文传输"的中间暴露

## API Gateway 安全策略

| 策略 | 说明 | 实现 |
|------|------|------|
| 认证聚合 | 统一处理多种认证方式 | Kong/APISIX Auth Plugin |
| 限流 | 按 client/tier/endpoint 限流 | Rate Limiting Plugin |
| IP 白名单 | 限制调用来源 | IP Restriction Plugin |
| 请求体验证 | Schema 校验 | Request Validation Plugin |
| 敏感数据过滤 | 自动脱敏响应字段 | Response Transformer |
| 审计日志 | 全量请求/响应记录 | Logging Plugin |

## 请求签名 (AWS SigV4 / HMAC)

### AWS Signature V4 流程

```
1. 构造 Canonical Request
   HTTPMethod + CanonicalURI + CanonicalQueryString + Headers + SignedHeaders + PayloadHash

2. 生成 StringToSign
   Algorithm + RequestDateTime + CredentialScope + HashedCanonicalRequest

3. 计算 Signing Key
   HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(AWS4SecretKey, date), region), service), "aws4_request")

4. 生成 Signature
   Hex(HMAC-SHA256(SigningKey, StringToSign))
```

### HMAC 请求签名方案（通用）

```http
POST /api/v1/data HTTP/1.1
Host: api.example.com
Date: Mon, 15 May 2024 10:30:00 GMT
Authorization: HMAC-SHA256 
  api_key=ak_xxx, 
  signature=base64(hmac_sha256(string_to_sign, secret)),
  algorithm=HMAC-SHA256
Content-Type: application/json
```

- **防重放**：`Date` header + `nonce` 检测
- **防篡改**：签名覆盖关键 header 和请求体
- **密钥管理**：每个 client 独立 API Secret，定期轮换

## 消息级加密

当传输层加密不足以满足安全要求时（如中间件可见明文），实施消息级加密：

```json
{
  "encrypted_payload": "base64(ciphertext)",
  "encryption_algorithm": "AES-256-GCM",
  "key_id": "kms://key/msg-key-001",
  "iv": "base64(iv)",
  "auth_tag": "base64(tag)"
}
```

- **端到端加密**：发送方加密，接收方解密，中间节点不可见
- **字段级加密**：仅加密敏感字段，保留可搜索字段明文
- **信封加密**：使用 DEK 加密数据，KMS 加密 DEK

## API Key 轮换策略

| 阶段 | 操作 | 说明 |
|------|------|------|
| 生成 | CSPRNG 生成 32 字节密钥 | 存储 SHA-256 哈希 |
| 分发 | 带外传输（TLS + 用户认证） | 避免明文存储在代码库 |
| 使用 | 服务端验证哈希 | 客户端保留原始 key |
| 轮换 | 90 天自动轮换 | 新旧 key 7 天共存期 |
| 吊销 | 密钥吊销列表 | 即时阻断 |

### 自动轮换实现

```python
# 新旧 key 共存期验证逻辑
def verify_api_key(api_key):
    key_hash = sha256(api_key.encode())
    if key_hash in active_keys:
        return True, key_hash
    if key_hash in rotating_keys:
        # 使用轮换期 key 仍可访问
        return True, key_hash
    return False, None
```

## 参考标准

- OWASP API Security Top 10 (2023)
- AWS Signature V4 (https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html)
- IETF RFC 7515 (JSON Web Signature)
- NIST SP 800-210 (General Access Control Guidance for Cloud Systems)
