# OAuth-SAML-OIDC

> OAuth 2.0、SAML 2.0和OpenID Connect是当前最主流的认证授权协议。三者各自针对不同场景设计，理解其区别和适用场景对安全架构师至关重要。

## OAuth 2.0

OAuth 2.0是一个**授权框架**（Authorization Framework），允许第三方应用获取用户资源的有限访问权限，而无需获取用户的凭据。

### 核心角色

```
资源所有者（Resource Owner）——用户
    │
    ▼
客户端（Client）——第三方应用（如：打印服务访问Google Drive）
    │
    ├─→ 授权服务器（Authorization Server）——发放Token
    │
    └─→ 资源服务器（Resource Server）——验证Token，提供API
```

### 授权类型（Grant Types）

| 授权类型 | 适用场景 | 访问令牌 | 刷新令牌 | 推荐度 |
|----------|---------|---------|---------|--------|
| Authorization Code | Web服务端应用 | ✅ | ✅ | **推荐** |
| Authorization Code + PKCE | 移动端/SPA | ✅ | ✅ | **强烈推荐** |
| Client Credentials | 机器对机器（M2M） | ✅ | ❌（非必要） | **推荐** |
| Resource Owner Password | 高度信任的第一方应用 | ✅ | ✅ | **不推荐**（获取用户密码） |
| Implicit（隐式） | SPA（已废弃） | ✅ | ❌ | **已废弃**（OAuth 2.1已移除） |

### Authorization Code + PKCE 流程

```
1. 用户 → 客户端：点击"使用Google登录"
2. 客户端 → 授权服务器：Authorization Request（code_challenge=S256(code_verifier)）
3. 用户：在授权服务器页面登录并授权
4. 授权服务器 → 客户端（redirect_uri）：Authorization Code
5. 客户端 → 授权服务器：Token Request（code + code_verifier）
6. 授权服务器：验证code_verifier与code_challenge匹配
7. 授权服务器 → 客户端：Access Token + Refresh Token
8. 客户端：使用Access Token调用API
```

### PKCE（Proof Key for Code Exchange）
```python
# 客户端生成（用于SPA/移动端）
import hashlib, base64, secrets

# 1. 生成随机的code_verifier
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip('=')

# 2. 计算code_challenge（S256方法）
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip('=')

# 发送登录请求时携带code_challenge
# 换取Token时携带code_verifier供服务器验证
```

## OAuth 2.1

OAuth 2.1（2023年草案）整合了OAuth 2.0 + 多年安全最佳实践：

| 变更 | 说明 |
|------|------|
| 移除Implicit Grant | 建议使用Authorization Code + PKCE |
| 移除Password Grant | Client Credentials和Authorization Code已覆盖所有场景 |
| PKCE必须 | Authorization Code必须始终使用PKCE |
| Refresh Token Rotation | 每次使用刷新令牌后轮换新令牌 |
| Sender-Constrained | 建议使用DPoP或mTLS绑定令牌到客户端 |
| 限定Redirect URI | 不允许通配符重定向URI |

## SAML 2.0

SAML（Security Assertion Markup Language）是一个基于XML的认证授权协议，主要用于企业级单点登录（SSO）。

### 核心组件

- **IdP（Identity Provider）**：身份提供者（如：Azure AD、Okta、Keycloak）
- **SP（Service Provider）**：服务提供者（如：Salesforce、Confluence）
- **断言（Assertion）**：IdP签名的XML文档，包含用户的认证信息和属性

### SAML SSO流程（SP-Initiated）

```
用户 → SP：访问受保护资源
SP → 用户：重定向至IdP（Request = SAMLRequest XML）
用户 → IdP：登录（输入凭据）
IdP → 用户：生成SAML断言（签名XML，包含NameID、属性、SessionIndex）
用户 → SP：POST SAML断言
SP：验证IdP签名 → 提取用户身份 → 创建会话 → 授权访问
```

### SAML断言示例（简化）
```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_abc123" IssueInstant="2026-05-26T12:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      alice@company.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
          Recipient="https://sp.example.com/acs"
          NotOnOrAfter="2026-05-26T12:10:00Z"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>
```

## OpenID Connect（OIDC）

OIDC建立在OAuth 2.0之上，增加**身份认证**层（OAuth 2.0本身只做授权）。

### OIDC核心概念

| 概念 | 说明 |
|------|------|
| ID Token | JWT格式的身份断言，包含sub（用户ID）、iss（签发者）、aud（受众）、exp（过期时间） |
| UserInfo Endpoint | 获取用户附加属性的API端点 |
| scope=openid | 必须的scope，触发OIDC流程 |
| Claims | 用户属性（name、email、picture等） |
| Discovery | /.well-known/openid-configuration 提供配置信息 |

### OIDC ID Token（JWT格式）
```json
// Header
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "abc123"
}

// Payload
{
  "iss": "https://accounts.example.com",
  "sub": "110169484474386276334",
  "aud": "client_id_123",
  "exp": 1620000000,
  "iat": 1619996400,
  "nonce": "n-0S6_WzA2Mj",
  "auth_time": 1619996400,
  "at_hash": "MTIzNDU2Nzg5MDEyMzQ1Ng",
  "email": "alice@example.com",
  "email_verified": true,
  "preferred_username": "alice"
}
```

### OIDC认证流程
```
1. 用户 → 客户端：点击"使用Google登录"
2. 客户端：构建认证请求（scope=openid profile email, response_type=code）
3. 用户 → 授权服务器：登录授权
4. 授权服务器 → 客户端：Authorization Code
5. 客户端 → Token端点：code + client_secret
6. Token端点 → 客户端：Access Token + ID Token（JWT）
7. 客户端：验证ID Token签名、iss、aud、exp、nonce
8. 客户端：提取sub/email → 创建本地会话
9. 客户端（可选）：使用Access Token调用UserInfo端点
```

## OAuth 2.0 vs SAML 2.0 vs OIDC

| 维度 | OAuth 2.0 | SAML 2.0 | OIDC |
|------|-----------|----------|------|
| **本质** | 授权框架 | 认证+授权协议 | 认证协议 |
| **数据格式** | JSON（JWT） | XML | JSON（JWT） |
| **传输方式** | HTTPS + Bearer Token | HTTP-Redirect/POST | HTTPS + Bearer Token |
| **架构** | 轻量、RESTful | 重量级、SOAP风格 | 轻量、RESTful |
| **移动端支持** | ✅ 优秀（PKCE） | ⚠️ 较差 | ✅ 优秀 |
| **API授权** | ✅ 核心能力 | ❌ 不适用 | ✅ 好 |
| **企业SSO** | ⚠️ 需扩展 | ✅ 行业标准 | ✅ 快速增长 |
| **联邦/跨域** | 需额外协议 | ✅ 内建 | ✅ 内建 |
| **去中心化** | ✅ 可 | ❌ 集中式IdP | ✅ 可 |
| **成熟度** | 2012年至今 | 2005年至今 | 2014年至今 |
| **当前版本** | 2.0（→2.1） | 2.0 | 1.0 |

## 安全注意事项

| 攻击类型 | 相关协议 | 防护措施 |
|----------|---------|---------|
| CSRF（跨站请求伪造） | OAuth 2.0 | state参数（必须） + nonce（OIDC） |
| Authorization Code拦截 | OAuth 2.0 | PKCE + 验证redirect_uri |
| Token重放 | OAuth 2.0 | Token绑定到TLS（令牌内绑定客户端ID） |
| XML签名包裹 | SAML | 验证完整断言，禁用XML外部实体 |
| IdP混淆 | SAML/OIDC | 验证预期Issuer，拒绝未知IdP |
| 证书篡改 | SAML | 严格验证XML数字签名 |

## 参考

- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7636: PKCE for OAuth 2.0
- Draft: OAuth 2.1 Authorization Framework
- OASIS SAML V2.0 Standard
- OpenID Connect Core 1.0 Specification
- NIST SP 800-63C: Federation & Assertions
