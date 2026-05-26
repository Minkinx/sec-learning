# 采集接口 API 安全

## 概述

数据采集接口是企业的数据入口，也是攻击者的首要目标。API 安全设计直接关系到数据采集链路的整体安全性，需要在认证、授权、限流、审计等层面建立纵深防御。

## API 认证机制

### OAuth 2.0

| 授权模式 | 适用场景 | 安全考量 |
|----------|----------|----------|
| Authorization Code + PKCE | 前端/移动端采集 | 防 authorization code interception |
| Client Credentials | 服务间采集 | 需配合 client secret 轮换 |
| Device Authorization Grant | 无浏览器设备 | 用户确认机制 |

### JWT 安全要点

- 使用强签名算法（RS256/ES256 而非 HS256）
- 设置合理的过期时间（建议采集 token 15-30 分钟）
- 实现 token refresh 机制避免频繁采集 credential
- 校验 `aud`、`iss`、`nbf` 等标准声明
- 不在 JWT payload 中存储敏感数据（payload 仅 base64 编码）

### API Key 管理

```
生成: 使用 CSPRNG (如 /dev/urandom) 生成 32+ 字节密钥
存储: 存储 SHA-256 哈希值，不存明文
轮换: 每 90 天强制轮换，新旧 key 有 7 天重叠期
吊销: 实现即时吊销能力 (如 Redis 黑名单)
```

## 限流策略

| 策略 | 说明 | 典型配置 |
|------|------|----------|
| Rate Limiting | 基于时间窗口的请求计数 | 1000 req/min per client |
| Burst Control | 允许短时突发 | 2000 req burst, 恢复至 1000/min |
| Concurrency Limiting | 并发连接数限制 | 50 concurrent per client |
| Resource Quota | 按数据量限制 | 100MB/min per client |

## 输入验证

- 对所有输入字段执行白名单验证（而非黑名单）
- JSON Schema / XML Schema 校验请求体结构
- 防止 injection 攻击（SQL/NoSQL/Command Injection）
- 限制字段长度和数据类型
- 使用 parameterized queries 处理数据库查询

## API 响应数据最小化

```json
// 错误做法：返回完整数据对象
{ "user": { "id": 123, "name": "张三", "phone": "138****0000", "id_card": "110****" } }

// 正确做法：仅返回必需字段
{ "user": { "id": 123, "name": "张三" }, "masked": ["phone", "id_card"] }
```

- 使用 GraphQL 精确控制返回字段
- 响应中自动过滤敏感字段（配置化 sensitivity labels）
- 实现 Field-Level Access Control

## Audit Logging

采集接口必须记录以下审计信息：

- **谁**：client_id, user_id (if authenticated)
- **什么**：请求的 endpoint, 请求体摘要 (hash)
- **何时**：精确到毫秒的 timestamp
- **何处**：源 IP, 地理位置, User-Agent
- **结果**：HTTP 状态码, 错误信息, 响应大小

## Webhook 安全

接收 Webhook 时的安全实践：

- **签名验证**：使用 HMAC-SHA256 签名请求体，接收方验证 signature header
- **IP 白名单**：限制发送方 IP 范围
- **幂等性**：Webhook ID 去重，防止重放攻击
- **超时处理**：设置合理的处理超时（建议 < 5 秒）
- **失败重试**：指数退避重试策略

## 参考标准

- OWASP API Security Top 10
- NIST SP 800-63B (Digital Identity Guidelines)
- IETF RFC 7519 (JWT), RFC 6749 (OAuth 2.0)
