# NIST网络安全框架

> NIST Cybersecurity Framework（CSF），由美国国家标准与技术研究院发布，是全球广泛采用的风险导向型网络安全框架。最新版本为CSF 2.0（2024年2月发布）。

## CSF核心功能（CSF 1.1 -> 2.0）

| 功能 | 说明 | 关键类别示例 |
|------|------|-------------|
| 识别（Identify） | 理解资产、风险、治理结构 | 资产治理、风险评估、供应链管理 |
| 保护（Protect） | 实施防护措施 | 身份管理、数据安全、培训、维护 |
| 检测（Detect） | 及时发现安全事件 | 异常检测、监控、事件分析 |
| 响应（Respond） | 事件应急处置 | 响应计划、分析、缓解、改进 |
| 恢复（Recover） | 恢复正常运营 | 恢复计划、改进、沟通 |
| **治理（Govern）**（2.0新增） | 贯穿所有功能的治理层 | 风险管理策略、监督、责任 |

## 实施层级（Tiers）

| 层级 | 描述 |
|------|------|
| Tier 1  Partial（部分） | 被动应对，风险管理非正式 |
| Tier 2  Risk-Informed（风险知情） | 有意识但非组织级 |
| Tier 3  Repeatable（可重复） | 组织级一致执行 |
| Tier 4  Adaptive（自适应） | 持续改进，主动应对 |

## NIST隐私框架

NIST Privacy Framework（2020年发布）与CSF互补，聚焦隐私风险：

| 功能 | 说明 |
|------|------|
| Identify-P（识别） | 数据处理生态系统和隐私风险 |
| Govern-P（治理） | 隐私治理策略 |
| Control-P（控制） | 管理隐私风险 |
| Communicate-P（沟通） | 透明披露 |
| Protect-P（保护） | 数据保护措施 |

## NIST SP 800-53

NIST SP 800-53（安全与隐私控制目录）提供超过1000项安全控制：

- 20个控制族（Access Control, Audit, Assessment, Configuration Management 等）
- 基础控制（Baseline）根据系统影响级别（Low/Moderate/High）分级推荐
- **控制增强**（Control Enhancements）：在基础控制上加设更严格措施

## 整合应用

- CSF提供战略框架和沟通语言
- 800-53提供具体的控制目录和配置基线
- 隐私框架补充隐私风险管理
- 联邦机构须遵循OMB A-130通函，强制采用NIST框架
