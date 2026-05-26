# ATT&CK框架

## 概述

MITRE ATT&CK（Adversarial Tactics, Techniques, and Common Knowledge）是一个基于真实世界观察的敌对战术与技术知识库。它是红蓝双方共同的语言体系，也是安全评估与防御能力度量的行业标准框架。

## Enterprise Matrix 14 大战术

ATT&CK Enterprise Matrix 覆盖了攻击链的完整生命周期，共包含 14 个战术阶段：

| 战术 | 战术ID | 描述 | 典型技术数量 |
|------|--------|------|-------------|
| Reconnaissance | TA0043 | 信息收集 | 10+ |
| Resource Development | TA0042 | 攻击资源建设 | 8+ |
| Initial Access | TA0001 | 初始访问 | 10+ |
| Execution | TA0002 | 执行恶意代码 | 12+ |
| Persistence | TA0003 | 持久化驻留 | 20+ |
| Privilege Escalation | TA0004 | 权限提升 | 13+ |
| Defense Evasion | TA0005 | 防御规避 | 40+ |
| Credential Access | TA0006 | 凭据访问 | 17+ |
| Discovery | TA0007 | 发现探测 | 30+ |
| Lateral Movement | TA0008 | 横向移动 | 10+ |
| Collection | TA0009 | 信息收集与窃取 | 17+ |
| Command and Control | TA0011 | 命令与控制 | 16+ |
| Exfiltration | TA0010 | 数据渗出 | 9+ |
| Impact | TA0040 | 影响破坏 | 14+ |

## 技术与子技术

每个战术下包含具体的技术（Techniques）和子技术（Sub-techniques）。例如：

**T1569 系统服务执行 (System Services)**:
- T1569.001 Launch Agent（macOS Launch Agent）
- T1569.002 Service Execution（通过PsExec/WMIC远程创建服务）
- T1569.003 Service Stop（Windows Service Control Manager）

**T1059 命令与脚本解释器 (Command and Scripting Interpreter)**:
- T1059.001 PowerShell
- T1059.002 AppleScript
- T1059.003 Windows Command Shell
- T1059.004 Unix Shell
- T1059.005 Visual Basic
- T1059.006 Python
- T1059.007 JavaScript/JScript
- T1059.008 Network Device CLI

## 红队如何使用 ATT&CK

### 模拟敌手行为

红队通过 ATT&CK 构建 TTP 矩阵来模拟真实威胁。例如模拟 APT29 (Cozy Bear)：

| 阶段 | 技术 | 说明 |
|------|------|------|
| 初始访问 | T1566.001 Spearphishing Attachment | 发送带恶意附件的邮件 |
| 执行 | T1059.001 PowerShell | PowerShell 执行 payload |
| 持久化 | T1053.005 Scheduled Task | 创建计划任务 |
| 防御规避 | T1027 Obfuscated Files or Information | 代码混淆 |
| C2 | T1071.001 Web Protocols | HTTPS 通信 |
| 数据渗出 | T1048 Exfiltration Over Alternative Protocol | DNS/DOH 隧道 |

### 差距分析

通过 ATT&CK Navigator 将红队能力映射到矩阵，快速识别覆盖不足的战术阶段。

- 红色：已覆盖（可以执行）
- 绿色：已检测（可以检测）
- 灰色：未覆盖（无法执行/无法检测）

### 检测规则映射

每个 ATT&CK 技术都可以关联检测规则：

| 技术 | 技术ID | 检测推荐 | 相关Event ID |
|------|--------|---------|-------------|
| Valid Accounts | T1078 | Event ID 4624 登录分析，账户异常行为 | 4624, 4625, 4672 |
| PowerShell | T1059.001 | Script Block Logging (EID 4104) | 4104, 4103, 400 |
| Scheduled Task | T1053.005 | Event ID 4698 (创建计划任务) | 4698, 106 (Sysmon) |
| Process Injection | T1055.001 | CreateRemoteThread (Sysmon EID 8) | 8 (Sysmon) |
| Service Execution | T1569.002 | 服务创建事件 (EID 7045) | 7036, 7045 |

## 常用工具

### ATT&CK Navigator

Web 应用，用于可视化 ATT&CK 矩阵。支持：
- 分层展示技术和子技术
- 导入/导出 heatmap 配置（JSON 格式）
- 创建自定义层标记覆盖状态
- 生成报告和截图

```json
{
  "name": "Red Team Coverage",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "score": 1,
      "color": "#e63946",
      "comment": "PowerShell payload delivery ready"
    },
    {
      "techniqueID": "T1566.001",
      "score": 1,
      "color": "#e63946",
      "comment": "Spearphishing attachment capability"
    }
  ]
}
```

### Atomic Red Team

开源测试库，每个测试用例对应一个 ATT&CK 技术：

```powershell
# 测试 T1059.001 - PowerShell 执行
Invoke-AtomicTest T1059.001

# 测试 T1569.002 - PsExec 服务执行
Invoke-AtomicTest T1569.002

# 列出所有可用测试
Get-AtomicTechnique
```

### Caldera

MITRE 开发的自动化红队平台，基于 ATT&CK 构建 adversary profiles，支持插件扩展和 REST API。

## 框架局限性

虽然 ATT&CK 是目前最广泛使用的攻击行为知识库，但仍存在以下局限：

1. **不覆盖所有真实技术**：ATT&CK 基于已公开的观察数据，许多高级 APT 使用的私有技术未被收录
2. **工具导向 vs 行为导向**：某些技术描述偏向特定工具实现，弱化了行为本质
3. **更新滞后**：新技术出现到被收录存在时间差（ETA通常3-6个月）
4. **上下文缺失**：没有描述技术之间的优先级和概率权重，所有技术被视为同等可能
5. **检测难度分级缺失**：没有评估每个技术被检测的难度或需要的数据源级别

## 最佳实践

1. **不要试图覆盖所有技术**：根据企业实际威胁面选择相关技术子集
2. **结合 ATT&CK 与防御框架**：将 ATT&CK 映射到 NIST CSF 或 ISO 27001 控制项
3. **定期更新 matrix 版本**：ATT&CK 每年发布多次更新（v14 → v15），持续跟踪新添加的技术
4. **自定义扩展**：在 ATT&CK Navigator 中添加自有的技术和数据源
