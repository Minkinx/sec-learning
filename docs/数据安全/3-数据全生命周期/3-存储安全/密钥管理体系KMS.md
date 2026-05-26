# 密钥管理体系 (KMS)

## 概述

密钥管理是加密体系的基石。KMS (Key Management System) 提供密钥的集中生成、存储、轮换、分发和销毁能力。HSM 与软件 KMS 的选择直接影响系统的安全性与成本。

## KMS 架构

### 核心组件

```
[Application/Service]
       │ API Calls (KMS SDK/SDK)
       ▼
[KMS Service]
  ├── Key Store (Encrypted DB/HSM)
  ├── Key Management API (Create/Encrypt/Decrypt/Rotate)
  ├── Access Control (IAM/Policy Engine)
  ├── Audit Logging (CloudTrail/自建)
  └── HSMs (可选, 用于主密钥保护)
       │
       ▼
[Hardware Security Module (HSM)]
  └── FIPS 140-2 Level 3 认证硬件
```

### KMS 的核心功能

| 功能 | 说明 | 重要性 |
|------|------|--------|
| 密钥生成 | 使用 CSPRNG 生成密钥 | 高 |
| 密钥存储 | 安全存储（加密 + ACL） | 高 |
| 密钥轮换 | 定期自动轮换 | 高 |
| 密钥分发 | 安全的密钥传输机制 | 高 |
| 密钥销毁 | 密钥安全删除 | 高 |
| 密钥审计 | 密钥使用全记录 | 中 |
| 访问控制 | 细粒度权限管理 | 高 |

## HSM vs 软件 KMS

| 维度 | HSM | 软件 KMS |
|------|-----|-----------|
| 安全级别 | FIPS 140-2 Level 3+ | FIPS 140-2 Level 1 |
| 密钥隔离 | 硬件级隔离 | 操作系统隔离 |
| 性能 | 专有硬件加速 | 依赖 CPU AES-NI |
| 吞吐量 | 数千 TPS | 数万 TPS |
| 成本 | 高（$10K-$100K+） | 低（开源/云服务） |
| 管理复杂度 | 高 | 中 |
| 适用场景 | PCI-DSS、金融核心 | 企业通用加密 |
| 可用性 | 集群化部署 | 高可用架构 |

### HSM 部署模式

- **On-premises HSM**：Thales Luna、Utimaco 物理设备
- **Cloud HSM**：AWS CloudHSM、Azure Dedicated HSM
- **Cloud KMS + HSM Backend**：AWS KMS (FIPS)、Azure Key Vault (Premium)

## 密钥生命周期管理

```
                    生成
                     │
                 分发使用
                     │
  ┌──────────────────┼──────────────────┐
  │                  │                  │
 ▼                  ▼                  ▼
激活             轮换              退休
  │                  │                  │
  │                  │              安全销毁
  ▼                  ▼                  │
使用中             退役密钥         永久删除
  │                  │                  │
  ▼                  ▼                  │
停用 ──────────→ 归档密钥 ───────→ 完全销毁
```

### 关键生命周期阶段

| 阶段 | 操作 | 安全控制 |
|------|------|----------|
| Generation | CSPRNG 或 HSM 生成 | 拆分存储 (Split Knowledge) |
| Distribution | 安全信道分发 | 双人控制 (Dual Control) |
| Rotation | 按策略自动轮换 | 新旧密钥共存期 |
| Retirement | 标记为只读/不可用 | 密钥状态迁移审批 |
| Destruction | 零化 (Zeroization) | 销毁证书 + 双人确认 |

## 主流云 KMS 对比

| 特性 | AWS KMS | Azure Key Vault | GCP Cloud KMS |
|------|---------|-----------------|---------------|
| FIPS 认证 | FIPS 140-2 Level 3 | FIPS 140-2 Level 2-3 | FIPS 140-2 Level 1-3 |
| HSM 选项 | CloudHSM | Dedicated HSM | Cloud HSM |
| 自动轮换 | 支持（1-365 天） | 支持 | 支持（按版本） |
| BYOK | 支持 (AWS CloudHSM) | 支持 | 支持 |
| 访问控制 | IAM + KMS Policies | RBAC + Access Policies | IAM + CMEK |
| 审计 | CloudTrail | Azure Monitor | Cloud Audit Logs |
| 密钥类型 | Sym/Asym/ECC | Sym/Asym/ECC/HMAC | Sym/Asym/ECC |
| Pricing | $1/key/month + API | $0.03/10K ops | $0.06/key/month + API |

## BYOK / HYOK

### BYOK (Bring Your Own Key)

- 客户创建密钥并导入云 KMS
- 密钥在客户 HSM 中生成
- 导入后由云 KMS 管理使用
- 云服务商无法导出明文密钥

### HYOK (Hold Your Own Key)

- 密钥完全保留在客户基础设施中
- 云服务调用客户 HSM 进行加解密
- 云服务商即使被攻破也无法获取密钥
- 更高的合规要求（如主权数据）

### 实现对比

```yaml
BYOK:
  key_generation: Customer HSM
  key_storage: Cloud KMS (encrypted)
  key_usage: Cloud KMS
  control: Shared (customer owns, cloud manages)

HYOK:
  key_generation: Customer HSM
  key_storage: Customer HSM
  key_usage: Customer HSM (cloud uses via API)
  control: Full (customer owns and manages)
```

## 参考标准

- NIST SP 800-57 Part 1-3 (Key Management)
- FIPS 186-5 (Digital Signature Standard)
- PCI DSS Requirement 3.5-3.6
- OASIS KMIP (Key Management Interoperability Protocol)
- ISO/IEC 11770 (Key Management)
