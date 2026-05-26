# SSPM

## 概述

SaaS 安全态势管理（SaaS Security Posture Management, SSPM）专注于检测和修复 SaaS 应用中的错误配置和安全风险，补充了 CASB 在配置安全层面的不足。SSPM 通过 API 持续监控 SaaS 应用的安全配置状态。

## 配置检查维度

SSPM 覆盖的核心配置维度包括：

- **身份与访问管理**：SSO 配置状态、MFA 启用率、服务账号权限、外部用户共享策略、密码策略（复杂度/过期时间/历史记录）
- **数据存储安全**：默认分享链接权限（公开/组织内/指定人员）、外部来宾访问设置、数据保留策略
- **网络与端点**：IP 白名单配置、API 端点暴露情况、第三方应用 OAuth 授权范围
- **日志与监控**：审计日志启用状态、日志保留时长、管理员操作告警配置

## CIS SaaS 基准

CIS（Center for Internet Security）发布了适用于主流 SaaS 应用的配置基准，包括 CIS Microsoft 365 Foundations Benchmark、CIS Google Workspace Foundations Benchmark、CIS Salesforce Benchmark 等。SSPM 工具应支持映射企业配置至 CIS 基准，量化合规评分。

## 常见错误配置

根据云安全联盟（CSA）统计，SaaS 应用中最常见的错误配置包括：

1. 外部用户可公开访问组织内部文档（如 Google Drive 公共链接）
2. 未启用 MFA 或允许旧版认证协议（IMAP/POP3 不要求认证）
3. 服务账号和 API Token 长期未轮换
4. 离职员工账号未及时禁用
5. 审计日志配置未开启或保留期限不足

## 自动修复

SSPM 的修复流程应尽可能自动化，通过 API 直接修改配置实现：自动关闭公共分享链接、禁用不合规的旧版协议、强制开启审计日志记录。对于无法自动修复的配置项（如需要业务审批的权限变更），集成工单系统生成修复任务，分配给对应的管理员。

## CSPM 集成

SSPM 与 CSPM（云安全态势管理）协同形成完整的云安全态势管理视图：CSPM 覆盖 IaaS/PaaS 层配置（如 AWS S3 权限、安全组规则），SSPM 覆盖 SaaS 层配置（如 Office 365 共享策略），两者共同输出统一的安全态势评分和整改建议。
