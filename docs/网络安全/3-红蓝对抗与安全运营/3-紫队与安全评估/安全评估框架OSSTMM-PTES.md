# 安全评估框架OSSTMM-PTES

## 概述

安全评估需要系统化的方法论指导。OSSTMM 和 PTES 是两个最广泛使用的安全测试框架，各有侧重。OSSTMM 更关注度量和合规，而 PTES 更注重渗透测试的执行流程。理解两者的差异和适用场景有助于规划更有效的安全评估活动。

## OSSTMM — 开源安全测试方法论

### 背景

OSSTMM（Open Source Security Testing Methodology Manual）由 ISECOM（Institute for Security and Open Methodologies）发布和维护，目前最新版本为 v3。OSSTMM 提供了经过科学验证的安全测试方法论。

### 通道分类

OSSTMM 将安全测试分为五大通道（Channels）：

| 通道 | 编号 | 覆盖范围 | 评估内容 |
|------|------|---------|---------|
| 人类安全 | HUM | 心理学、社会工程学 | 员工安全意识、物理访问意识 |
| 物理安全 | PHY | 物理设施 | 门禁、监控、锁具、机房 |
| 无线安全 | WLS | 无线通信 | WiFi、蓝牙、RFID、NFC |
| 电信安全 | TEL | 通信基础设施 | PBX、VoIP、调制解调器 |
| 数据网络安全 | DCN | 网络基础设施 | 防火墙、IDS/IPS、网络架构 |

### 控制类型 (Controls)

OSSTMM 定义了三类安全控制：

| 控制类型 | 说明 | 评估例子 |
|---------|------|---------|
| Interaction（交互控制） | 与目标交互时的可见性和认证 | 端口扫描响应、服务指纹 |
| Process（流程控制） | 流程和程序的完善度 | 变更管理流程、访问审批流程 |
| Access（访问控制） | 对信息的物理或逻辑访问限制 | ACL 配置、拨入策略 |

### OSSTMM 安全测试流程

```
1. 定义范围 (Defining Scope)
   ├── 测试目标边界
   ├── 测试深度等级
   └── 测试限制条件

2. 信息收集 (Information Gathering)
   ├── 公开源情报 (OSINT)
   ├── 物理勘查
   └── 人力资源情报

3. 测试执行 (Testing Phase)
   ├── 按五大通道分类的执行测试
   ├── 每个通道使用标准化的测试用例
   └── 记录所有交互和结果

4. 结果分析 (Analysis)
   ├── 量化: RAV (Risk Assessment Values) 计算
   ├── 事实分析 (Factoring): 标准化结果
   └── 真实性调整 (False Controls Analysis)

5. 报告 (Reporting)
   ├── 按通道的详细发现
   ├── RAV 评分
   └── 安全等级评级
```

### OSSTMM RAV 计算

OSSTMM 的核心创新在于 RAV（Risk Assessment Values）的量化评估方法：

```
RAV = (True Controls - False Controls) × Operational Security

True Controls   = 实际有效的安全控制
False Controls  = 名义上存在但实际无效的控制
Operational Security = 安全操作的效率系数

最终 RAV 范围: -100 到 +100
+100 表示完全安全
0 表示不确定
-100 表示完全不安全
```

## PTES — 渗透测试执行标准

### 背景

PTES（Penetration Testing Execution Standard）由安全社区专家共同制定，专注于渗透测试的实际操作流程。PTES 包含七个阶段，是目前渗透测试领域最实用的指南之一。

### 七阶段模型

| 阶段 | 名称 | 核心活动 | 交付物 | 时间占比 |
|------|------|---------|--------|---------|
| 1 | Pre-engagement (前置交互) | 合同签署、范围定义、规则确认 | 测试范围文档、NDA | 10% |
| 2 | Intelligence Gathering (情报收集) | OSINT、域名枚举、社会工程学 | 资产清单 | 20% |
| 3 | Threat Modeling (威胁建模) | 威胁识别、攻击路径分析 | 威胁模型图 | 10% |
| 4 | Vulnerability Analysis (漏洞分析) | 扫描、手动验证、fuzzing | 漏洞清单 | 15% |
| 5 | Exploitation (漏洞利用) | 漏洞验证、获取访问 | 渗透记录 | 20% |
| 6 | Post-Exploitation (后渗透利用) | 权限维持、横向移动、数据泄露评估 | 后渗透报告 | 15% |
| 7 | Reporting (报告) | 发现汇总、修复建议、风险评估 | 最终渗透测试报告 | 10% |

### PTES 阶段详解

#### 前置交互 (Pre-engagement)

```markdown
# 前置交互检查清单
- [ ] 测试范围定义 (目标IP、域名、应用范围)
- [ ] 测试规则 (测试时间窗口、允许/禁止技术)
- [ ] 紧急联系人 (事件升级流程)
- [ ] 数据保护 (数据处理和销毁方案)
- [ ] 第三方通知 (ISP、云服务商、托管商)
- [ ] 保险确认 (专业责任保险)
- [ ] 渗透测试授权书 (Permission to Test)
```

#### 情报收集 (Intelligence Gathering)

```
被动情报收集:
  ├── DNS 枚举 — dig, nslookup, dnsrecon
  ├── 子域名枚举 — subfinder, amass, sublist3r
  ├── 搜索引擎 — Google dork, Shodan, Censys
  ├── 社交网络 — LinkedIn, Twitter, Facebook
  ├── 技术栈识别 — BuiltWith, Wappalyzer
  ├── 泄露凭据 — DeHashed, Have I Been Pwned
  └── Git 泄露 — GitHound, truffleHog

主动情报收集:
  ├── 端口扫描 — nmap, masscan, rustscan
  ├── 服务识别 — nmap -sV, amap
  ├── 漏洞扫描 — Nessus, OpenVAS, Qualys
  └── 目录枚举 — Gobuster, dirsearch, ffuf
```

#### 威胁建模 (Threat Modeling)

```
威胁建模方法论可选用:
  - STRIDE (Microsoft): 欺骗(S)、篡改(T)、抵赖(R)、信息泄露(I)、拒绝服务(D)、权限提升(E)
  - DREAD: 损害、可复制性、可利用性、受影响用户、可发现性
  - PASTA: 应用安全流程攻击模拟与分析
  - OCTAVE: 运营关键威胁、资产和漏洞评估
```

#### 漏洞利用与后渗透 (Exploitation & Post-Exploitation)

```
利用阶段:
  ┌─────────────────────────────────┐
  │   1. 漏洞验证                     │
  │   2. 选择 exploitation 方法       │
  │   3. 执行 exploitation            │
  │   4. 维持访问 (建立后门/隧道)      │
  │   5. 清理痕迹 (清理日志/还原配置)  │
  └─────────────────────────────────┘
                    ↓
后渗透阶段:
  ┌─────────────────────────────────┐
  │   1. 信息收集 (whoami, ipconfig) │
  │   2. 权限提升                   │
  │   3. 凭据窃取                   │
  │   4. 横向移动                   │
  │   5. 数据识别与收集 (目标数据)   │
  │   6. 数据渗出 (证明影响)         │
  └─────────────────────────────────┘
```

## OSSTMM vs PTES 对比

| 维度 | OSSTMM | PTES |
|------|--------|------|
| 发布机构 | ISECOM | 社区志愿者 |
| 最新版本 | v3 | 1.0 (2010) |
| 覆盖范围 | 全量安全测试（含物理/人员） | 渗透测试为主 |
| 方法论特点 | 科学化、可量化、可重复 | 实操导向、工程化 |
| 结果量化 | RAV 评分体系 | 定性分析为主 |
| 适合场景 | 合规审计、保险评估 | 渗透测试实战 |
| 学习曲线 | 较陡（术语多） | 适中 |
| 社区活跃度 | 中 | 低（已不再更新） |

## 如何选择框架

| 场景 | 推荐框架 | 理由 |
|------|---------|------|
| 金融行业合规审计 | OSSTMM | 量化评估、可审计性强 |
| 红队渗透测试项目 | PTES | 实操流程完善 |
| SOC 2 / ISO 27001 审计 | OSSTMM | 覆盖全面控制评估 |
| Web 应用渗透测试 | PTES | 聚焦技术测试 |
| 安全意识评估 | OSSTMM (HUM) | 社会工程学测试方法论 |
| 内部蓝队能力验证 | PTES + MITRE ATT&CK | 结合攻防实战视角 |
| 保险安全评估 | OSSTMM | RAV 量化评分兼容性好 |

## 综合评估策略建议

现代安全评估通常不局限于单一框架，而是综合多种方法论：

```
安全评估计划 = OSSTMM (范围 + 流程 + 量化)
              + PTES (渗透测试执行方法)
              + ATT&CK (攻击行为映射 + 检测验证)
              + NIST CSF (组织级安全能力评估)
```

具体而言：

1. 使用 OSSTMM 定义评估范围和安全控制分类
2. 使用 PTES 指导渗透测试具体操作流程
3. 使用 ATT&CK 映射和验证检测能力覆盖
4. 使用 NIST Cybersecurity Framework 进行组织级安全成熟度评估
