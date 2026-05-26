# 授权模型RBAC-ABAC

> 授权是身份认证之后的第二步——确定"用户能做什么"。RBAC（基于角色的访问控制）和ABAC（基于属性的访问控制）是目前最主流的授权模型。

## RBAC（基于角色的访问控制）

RBAC将权限分配给角色，再将角色分配给用户，实现用户与权限的解耦。

### NIST RBAC标准定义

RBAC标准（INCITS 359-2012）定义了四个核心要素：

```
用户（User）──关联──→ 角色（Role）──授权──→ 权限（Permission）
                            │                        │
                      角色继承（RH）            操作（Operation）× 对象（Object）
```

### RBAC基本原则

| 原则 | 说明 |
|------|------|
| **角色继承** | 高级角色自动继承低级角色的权限（如admin继承editor权限） |
| **最小权限** | 用户只获得完成工作所必需的最小角色集 |
| **职责分离（SoD）** | 敏感操作需要多个角色共同完成（如：提交与审批不能同一人） |

### RBAC实施示例（数据库模型）
```sql
-- 五张核心表
CREATE TABLE users (
    user_id INT PRIMARY KEY,
    username VARCHAR(64) UNIQUE
);

CREATE TABLE roles (
    role_id INT PRIMARY KEY,
    role_name VARCHAR(64) UNIQUE,  -- admin, editor, viewer
    description TEXT
);

CREATE TABLE permissions (
    perm_id INT PRIMARY KEY,
    perm_code VARCHAR(64) UNIQUE,  -- document:create, document:delete
    description TEXT
);

CREATE TABLE user_roles (
    user_id INT REFERENCES users(user_id),
    role_id INT REFERENCES roles(role_id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id INT REFERENCES roles(role_id),
    perm_id INT REFERENCES permissions(perm_id),
    PRIMARY KEY (role_id, perm_id)
);

-- 查询用户权限
SELECT p.perm_code
FROM users u
JOIN user_roles ur ON u.user_id = ur.user_id
JOIN role_permissions rp ON ur.role_id = rp.role_id
JOIN permissions p ON rp.perm_id = p.perm_id
WHERE u.username = 'alice';
```

### RBAC优缺点

| 优势 | 劣势 |
|------|------|
| 模型简单，容易理解 | 角色膨胀（小型组织 → 数百个角色） |
| 管理直观（用户加入/离开团队只需增减角色） | 细粒度控制不足（无法表达"仅在工作时间访问"） |
| 审计清晰（谁有什么角色一目了然） | 角色定义需合理设计，否则权限过度授予 |
| 广泛支持（成熟且工具化程度高） | 动态权限变更困难（需人工调整角色分配） |

## ABAC（基于属性的访问控制）

ABAC使用一系列属性组合来做出授权决策，比RBAC粒度更细。

### ABAC属性分类

| 属性类别 | 示例 |
|----------|------|
| **主体属性** | 用户ID、部门、职级、安全许可等级、地理位置 |
| **资源属性** | 资源类型、分类级别、所属部门、创建时间 |
| **环境属性** | 当前时间、IP地址、设备类型、网络位置 |
| **操作属性** | 操作类型（读取/写入/删除/导出） |

### ABAC策略示例

使用XACML或ALFA（Axiomatics）策略语言表达：

```
策略：高级工程师可在地点=内网 且 时间=工作时间 内 修改 分类=内部 的文档

规则：
  PERMIT IF
    subject.role = "senior_engineer" AND
    subject.location = "internal_network" AND
    resource.classification = "internal" AND
    action.name = "modify" AND
    environment.current_time >= "09:00" AND
    environment.current_time <= "18:00"
```

### ABAC工作流程（PDP/PEP架构）
```
用户请求访问资源
    │
    ▼
PEP（Policy Enforcement Point）——拦截请求
    │
    ▼ 转发请求属性
PDP（Policy Decision Point）——评估策略
    │
    ├─ 检索策略（Policy Store）
    ├─ 获取上下文属性（PIP - Policy Information Point）
    └─ 返回 Permit / Deny
    │
    ▼
PEP → 允许/拒绝用户操作
```

### ABAC优缺点

| 优势 | 劣势 |
|------|------|
| 细粒度控制（支持复杂的业务规则） | 策略管理复杂（需要专门工具和分析） |
| 动态生效（属性变化 → 策略立即适用） | 性能开销（每次访问需评估策略集合） |
| 支持上下文感知（时间、地点、设备） | 策略冲突需要明确定义优先级 |
| 减少角色数量 | 审计困难（需了解策略组合后才能理解决策） |

## 其他授权模型

### DAC（自主访问控制）
- 资源所有者决定谁能访问
- 例子：Linux文件权限（chmod）
- 问题：用户可能误授予权限

### MAC（强制访问控制）
- 系统根据标签规则强制决定
- 例子：SELinux、Windows MIC
- 用于高安全环境

### ReBAC（关系型访问控制）
- 基于资源之间的关系网络做授权决策
- Google Zanzibar范式（Google Drive、YouTube的权限系统）
- SpiceDB、Ory Keto等开源实现
- 典型用例：组织层级、文档共享、多租户SaaS

```
Google Zanzibar（2019年公开论文）：
- 为Google Drive、Gmail、YouTube等提供统一授权服务
- 核心模型：Namespace（资源类型）/ Object / Relation / User
- 例子：doc:123#viewer@user:alice（用户alice对文档123有查看者关系）
- 性能：全球化部署，P99延迟 < 10ms
```

## 授权模型选择指南

| 组织规模 | 复杂度 | 推荐模型 | 说明 |
|----------|--------|---------|------|
| 小型（<100人） | 低 | RBAC | 简单直接，角色清晰 |
| 中型（100-1000人） | 中 | RBAC + ABAC混合 | 基础权限用RBAC，特殊策略用ABAC |
| 大型企业（>1000人） | 高 | ABAC / NGAC | 细粒度控制，大量策略规则 |
| 云原生/多租户SaaS | 高 | ReBAC（Zanzibar） | 关系型权限模型，适合社交/协作应用 |

### RBAC+ABAC混合模式
```
大部分权限通过RBAC分配（如：销售团队可以查看客户信息）
特殊约束通过ABAC策略叠加（如：只有在工作时间才允许导出客户数据）
```
```json
{
  "user": "alice",
  "roles": ["sales_manager"],
  "abac_rules": [
    {
      "effect": "DENY",
      "condition": "action == 'export' AND environment.time NOT BETWEEN '09:00' AND '18:00'"
    }
  ]
}
```

## 参考

- INCITS 359-2012: RBAC Standard (NIST)
- NIST SP 800-162: Guide to ABAC Definition and Considerations
- Google Zanzibar: Consistent, Global Authorization System (2019, USENIX ATC)
- OWASP: Access Control Cheat Sheet
- XACML 3.0 (OASIS Standard)
- Ory Keto / SpiceDB (开源ReBAC实现)
