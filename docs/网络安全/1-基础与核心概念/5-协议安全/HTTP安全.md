# HTTP安全

> HTTP是Web的基石协议，但其设计存在若干固有问题：明文传输、无状态、缺乏内建认证机制。现代Web安全实践通过HTTPS、安全头部、同源策略等机制弥补这些不足。

## HTTP协议的固有问题

| 问题 | 说明 | 攻击类型 |
|------|------|---------|
| 明文传输 | 所有数据以明文形式在网络中传输 | 窃听、中间人攻击（MITM） |
| 无状态 | 每个请求独立，需通过Cookie/Session维持状态 | 会话劫持、会话固定 |
| 无内建认证 | 服务器不知道请求者的身份 | 身份冒充、CSRF |
| 无完整性保护 | 数据在传输中可被篡改而不被察觉 | 内容注入、响应篡改 |

**解决方案**：HTTPS = HTTP over TLS，解决了明文传输和完整性保护问题。

## HTTPS vs HTTP

| 特性 | HTTP | HTTPS |
|------|------|-------|
| 传输加密 | ❌ | ✅ TLS |
| 数据完整性 | ❌ | ✅ MAC校验 |
| 服务器身份验证 | ❌ | ✅ CA证书 |
| 默认端口 | 80 | 443 |
| SEO影响 | 低（浏览器标记"不安全"） | 高 |
| 性能 | 无TLS握手开销 | 额外1-RTT（TLS 1.3） |
| HTTP/2支持 | ✅ | ✅（实际通过TLS实现） |

## 安全头部

安全头部是Web应用防御纵深的重要组成部分。

### 核心安全头部

| 头部 | 推荐值 | 作用 | 不支持时的风险 |
|------|--------|------|---------------|
| **Content-Security-Policy** | `default-src 'self'` | 限制可加载的资源来源 | XSS、数据注入 |
| **X-Frame-Options** | `DENY` 或 `SAMEORIGIN` | 禁止页面被嵌入iframe | 点击劫持（Clickjacking） |
| **Strict-Transport-Security** | `max-age=63072000; includeSubDomains` | 强制HTTPS连接 | SSL剥离攻击 |
| **X-Content-Type-Options** | `nosniff` | 禁止MIME类型嗅探 | MIME类型混淆攻击 |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | 控制Referer头发送范围 | 敏感URL在Referer中泄露 |
| **Permissions-Policy** | `camera=(), microphone=(), geolocation=()` | 限制浏览器API访问 | 恶意页面滥用设备权限 |
| **X-XSS-Protection** | `0`（已废弃） | 已废弃（现代浏览器已移除） | — |
| **Cross-Origin-Embedder-Policy** | `require-corp` | 跨域嵌入策略 | Spectre相关数据泄露 |

### CSP（Content Security Policy）详解
```http
Content-Security-Policy: 
  default-src 'self';                        # 默认只允许同源资源
  script-src 'self' https://cdn.example.com;  # 允许从指定CDN加载脚本
  style-src 'self' 'unsafe-inline';          # 允许内联样式
  img-src *;                                  # 允许任何来源的图片
  connect-src 'self' https://api.example.com; # 允许API请求
  frame-ancestors 'none';                     # 禁止被嵌入iframe（同X-Frame-Options）
  base-uri 'self';                            # 限制<base>标签
  form-action 'self';                         # 限制表单提交目标
```

### CSP指令中危险的配置
```http
# ❌ 极度危险——几乎无保护
Content-Security-Policy: default-src *; script-src *; 

# ⚠️ 'unsafe-inline' 可能仍允许XSS
Content-Security-Policy: script-src 'unsafe-inline' https://cdn.example.com;

# ✅ 推荐的严格CSP（基于nonce）
Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic';
```

### HSTS预加载
```
# HTTP响应头部
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

# 提交域名到浏览器预加载列表
# https://hstspreload.org/
# 一旦加入预加载列表，浏览器在首次访问前即知该域名强制HTTPS
# ⚠️ 撤销非常困难——请确保做好HTTPS长期支持准备
```

## 同源策略（Same-Origin Policy, SOP）

SOP是浏览器最基础的安全机制：

### 同源定义
```
两个URL同源的条件：协议 + 主机 + 端口 完全相同

http://example.com:80/page1.html
  ✅ http://example.com:80/page2.html（同源）
  ❌ https://example.com:80/page1.html（协议不同）
  ❌ http://www.example.com:80/page1.html（主机不同）
  ❌ http://example.com:8080/page1.html（端口不同）
```

### SOP限制下允许的操作
- 同源页面之间可以自由读写DOM
- 跨域资源嵌入（`<script>`, `<img>`, `<link>`, `<iframe>`）允许读取响应
- **跨域读访问默认被阻止**（如使用fetch或XMLHttpRequest）

## CORS（跨域资源共享）

CORS是SOP的受控例外，允许服务器声明哪些跨域请求可接受。

### 简单请求 vs 预检请求

| 特征 | 简单请求 | 预检请求 |
|------|---------|---------|
| HTTP方法 | GET、HEAD、POST | 其他（PUT、DELETE、PATCH） |
| Content-Type | application/x-www-form-urlencoded, multipart/form-data, text/plain | 其他（如application/json） |
| 自定义头部 | 无 | 有 |
| 浏览器行为 | 直接发送请求 | 先发OPTIONS预检请求 |

### CORS头部
```http
# 服务器响应头部
Access-Control-Allow-Origin: https://trusted-site.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400

# 预检响应专用
Access-Control-Allow-Origin: https://trusted-site.com
```

### CORS配置风险
```http
# ❌ 高风险——允许任意源 + 凭据（无法控制）
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
# * 和 凭据 不能同时使用（浏览器会拒绝）

# ⚠️ 动态 Origin 回显（反射）——危险
# 如果服务器直接将请求的 Origin 头反映到响应中
# 攻击者可在任意域构造页面发送跨域请求

# ✅ 安全配置
Access-Control-Allow-Origin: https://specific-trusted-domain.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

### JSONP（已废弃的跨域方案）
```javascript
// JSONP利用<script>标签不受SOP限制的特性
<script>
function handleData(data) {
  console.log(data.user.email);
}
</script>
<script src="https://api.example.com/user?callback=handleData"></script>
// 服务器返回：handleData({"user": {"email": "alice@example.com"}})
// ⚠️ 风险：CSRF、注入攻击、回调函数劫持
```
**替代方案**：CORS（标准方案）、postMessage（iframe通信）

## HTTP安全相关攻击

| 攻击 | 原理 | 防护 |
|------|------|------|
| **SSL剥离** | 将HTTPS降级为HTTP | HSTS、HSTS预加载 |
| **会话劫持** | 窃取Cookie/Token | Secure+HttpOnly Cookie、SameSite |
| **CSRF** | 利用用户已认证的会话发起跨站请求 | SameSite Cookie、CSRF Token、Referer验证 |
| **Clickjacking** | 透明iframe覆盖诱使用户点击 | X-Frame-Options、CSP frame-ancestors |
| **MIME混淆** | 浏览器将文件按错误类型解析 | X-Content-Type-Options: nosniff |

### CSRF防护示例
```python
# Django CSRF防护（默认启用）
# 1. 模板中的CSRF Token
<form method="post">
  {% csrf_token %}
  <input type="submit" value="转账">
</form>

# 2. 使用SameSite Cookie（现代浏览器）
Set-Cookie: sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax

# SameSite取值：
# Strict：完全阻止跨站Cookie（拒绝链接跳转）
# Lax（推荐）：允许GET的顶级导航带Cookie
# None：必须配合Secure，允许所有跨站请求带Cookie
```

## 参考

- RFC 7230-7235: HTTP/1.1 Protocol
- RFC 6454: The Web Origin Concept
- Fetch Standard: CORS Protocol (WHATWG)
- OWASP: HTTP Security Headers Cheat Sheet
- OWASP: CSRF Prevention Cheat Sheet
- Mozilla MDN: Content Security Policy
- SameSite Cookies RFC 6265bis
