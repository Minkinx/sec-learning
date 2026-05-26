# 动态数据脱敏 (DDM)

## 概述

动态数据脱敏 (Dynamic Data Masking, DDM) 在数据被查询时实时对敏感信息进行遮蔽，不改变底层存储数据。与静态脱敏 (Static Data Masking, SDM) 不同，DDM 根据访问者的角色和权限动态调整脱敏策略，在提供数据可用性的同时保护敏感信息。

## DDM vs SDM 对比

| 维度 | 动态脱敏 (DDM) | 静态脱敏 (SDM) |
|------|----------------|----------------|
| 处理时机 | 查询时实时处理 | 离线批量处理 |
| 数据副本 | 不创建副本 | 创建脱敏数据副本 |
| 存储数据 | 原始数据不变 | 脱敏数据独立存储 |
| 策略变更 | 实时生效 | 需重新生成脱敏数据集 |
| 性能影响 | 查询延迟增加 | 仅 ETL 阶段有性能消耗 |
| 适用场景 | 生产库实时查询 | 开发/测试/培训环境 |
| 逆转风险 | 低（原始数据隔离存储） | 低（脱敏后不可逆） |
| 实现复杂度 | 高（需代理层） | 中（ETL 管道） |

## 代理级 vs 数据库级 DDM

### 代理级 DDM (Proxy-Based)

```
Client App → [DDM Proxy / API Gateway] → Database
                    ↓
             Masking Engine
    (策略: 角色级/用户级/上下文级)
```

| 优点 | 缺点 |
|------|------|
| 数据库无关，支持多数据源 | 增加网络延迟一跳 |
| 统一策略管理 | 单点故障/性能瓶颈 |
| 非侵入式部署 | 需要网络架构调整 |
| 支持多协议 (JDBC/REST/GraphQL) | 对某些数据库特有功能兼容性差 |

### 数据库级 DDM (DB-Level)

直接在数据库中配置脱敏策略：

```sql
-- SQL Server Dynamic Data Masking
ALTER TABLE employees
ALTER COLUMN ssn ADD MASKED WITH (FUNCTION = 'partial(0,"XXX-XX-",4)');

ALTER TABLE employees
ALTER COLUMN email ADD MASKED WITH (FUNCTION = 'email()');

ALTER TABLE employees
ALTER COLUMN salary ADD MASKED WITH (FUNCTION = 'default()');

-- PostgreSQL 通过扩展实现
CREATE MASKING POLICY mask_ssn
  ON employees USING (substring(ssn, 1, 3) || '-XX-XXXX');

-- GRANT UNMASK 给有权限的用户
GRANT UNMASK TO sec_admin;
```

| 优点 | 缺点 |
|------|------|
| 低延迟，数据库原生支持 | 功能依赖特定数据库 |
| 无需额外基础设施 | 策略管理分散 |
| 与数据库权限体系集成 | 跨数据库策略迁移困难 |

## 基于角色的脱敏策略定义

### 策略模型

```yaml
角色层级:
  Admin (CRM 管理员):
    - ssn: 明文 (NO_MASKING)
    - salary: 明文
    - email: 明文

  Manager (业务主管):
    - ssn: 显示后 4 位 (SHOW_LAST_4)
    - salary: 向下取整千位 (ROUND_DOWN_1000)
    - email: 域名保留 (MASK_EMAIL)

  Analyst (数据分析师):
    - ssn: NULL (DEFAULT_NULL)
    - salary: 范围 (RANGE_10000)
    - email: 遮蔽 (MASK_ALL)

  Support (客服):
    - ssn: 显示后 4 位
    - salary: 隐藏 (DEFAULT_NULL)
    - email: 明文
  ```

### 策略引擎

DDM 策略引擎需要支持：

| 能力 | 说明 | 示例 |
|------|------|------|
| 角色解析 | 从认证系统获取用户角色 | LDAP Group, JWT claim |
| 字段映射 | 敏感字段 ↔ 脱敏算法 | ssn → SHOW_LAST_4 |
| 上下文感知 | 根据访问上下文调整策略 | VPN 内 = 宽松, 外网 = 严格 |
| 动态字段发现 | 自动识别新敏感字段 | 正则匹配 + ML 分类 |
| 策略版本管理 | 策略变更审计 | Git-based 配置管理 |

## 实时脱敏技术

### 脱敏算法

| 算法 | 说明 | 适用字段 | 数据保真度 |
|------|------|----------|-----------|
| Substitution (替换) | 随机替换为相似格式值 | 姓名、地址 | 格式保真 |
| Shuffling (洗牌) | 同列内行级随机置换 | 非关联字段 | 统计分布保持 |
| Masking (遮蔽) | 替换字符为 `*` | 信用卡、SSN | 显示最后几位 |
| Nullify (空值) | 替换为 NULL | 非必需字段 | 低 |
| Ranging (范围) | 显示近似范围 | 工资、年龄 | 统计描述可用 |
| Hashing (哈希) | SHA-256 + Salt | ID、用户名 | 可关联但不可逆 |

### 性能优化

| 优化方法 | 说明 | 预期效果 |
|----------|------|----------|
| 预编译脱敏规则 | 编译脱敏表达式为执行计划 | 减少解析时间 50%+ |
| 缓存脱敏策略 | 策略缓存到本地内存 | 减少策略查询延迟至微秒级 |
| 查询改写优化 | 在 SQL 层面嵌入脱敏函数 | 减少数据传输量 |
| 智能脱敏引擎 | 选择性脱敏（非全字段脱敏） | 减少 CPU 消耗 |
| 连接池分离 | 按脱敏等级分离连接池 | 避免策略切换开销 |

## 使用场景

### 生产查询

```
业务场景: 客服查询用户信息时根据等级显示不同数据
前端 → DDM Proxy (客服角色) → Database
  └── 显示 SSN 后 4 位, 完整姓名, 隐藏地址

审计场景: 合规官需要查看完整数据
前端 → DDM Proxy (auditor 角色) → Database
  └── 显示完整 SSN, 完整地址, 完整薪资
```

### 开发测试环境

```
生产数据库 → DDM Proxy → 开发查询（实时脱敏）
  └── 开发人员即使查询生产库也只能看到脱敏数据
  └── SDM 用于批量导出脱敏数据集
```

### 报表与分析

```
BI 工具 → DDM Proxy → 数据仓库
  └── 按报告受众调整脱敏级别
  └── 高管报告显示聚合后脱敏数据
  └── 运营报告显示颗粒度更细的数据
```

## 参考标准

- NIST SP 800-53 (Access Control, SC-28)
- PCI DSS Requirement 3.4
- GDPR Article 25 (Data Protection by Design)
- OWASP Data Masking Cheat Sheet
