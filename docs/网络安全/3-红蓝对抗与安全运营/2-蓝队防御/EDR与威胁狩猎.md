# EDR与威胁狩猎

## 概述

端点检测与响应（EDR）和威胁狩猎是现代防御体系的核心能力。EDR 提供持续的端点可见性和自动响应能力，而威胁狩猎则是从被动告警处理转向主动搜索威胁的思维转变。两者结合构成主动防御的基础。

## EDR vs AV vs NGAV

| 维度 | 传统杀毒 (AV) | 下一代杀毒 (NGAV) | EDR |
|------|--------------|-------------------|-----|
| 检测方法 | 签名匹配 | ML + 行为分析 | 行为分析 + 关联 + 实时监控 |
| 检测能力 | 已知恶意软件 | 已知 + 变种恶意软件 | 已知 + 未知 + 无文件攻击 |
| 响应能力 | 自动隔离/删除 | 自动隔离/删除 | 隔离、回滚、取证、狩猎 |
| 可见性 | 文件扫描 | 文件 + 进程 | 进程+网络+文件+注册表+内存 |
| 调查能力 | 无 | 有限 | 丰富（搜索、回溯、分析） |
| 典型产品 | McAfee, Symantec | CrowdStrike Falcon | CrowdStrike, Defender ATP |
| 部署复杂度 | 低 | 中 | 中-高 |

## EDR 核心能力

### 数据采集维度

```
EDR Agent ──┬── 进程创建/终止 (Process)
            ├── 网络连接 (Network)
            ├── 文件操作 (File Create/Write/Delete/Rename)
            ├── 注册表修改 (Registry Set/Delete)
            ├── 模块加载 (DLL/Library Load)
            ├── 计划任务创建 (Scheduled Task)
            ├── WMI/Access 持久化 (WMI Persistence)
            ├── 服务创建/修改 (Service)
            ├── PowerShell 脚本记录 (ScriptBlock)
            ├── 内存扫描 (Memory Scan)
            └── DNS 查询记录 (DNS Query)
```

### 自动响应动作

| 响应动作 | 说明 | 影响级别 |
|---------|------|---------|
| 隔离主机 | 将端点从网络中隔离，仅允许与 EDR 云通信 | 高 |
| 终止进程 | 强制终止恶意进程 | 中 |
| 删除文件 | 删除检测到的恶意文件 | 中 |
| 回滚注册表 | 恢复被恶意修改的注册表键值 | 中 |
| 限制执行 | 禁止特定进程或签名的文件执行 | 低-中 |
| 收集取证包 | 自动收集内存转储和系统快照 | 低 |
| 禁用账户 | 临时禁用被攻陷的用户账户 | 高 |

## Sysmon — Windows 高级日志

Sysmon（System Monitor）是微软 Sysinternals 提供的 Windows 系统监控驱动，是 EDR 和威胁狩猎的重要数据源。

### 安装与配置

```cmd
# 安装 Sysmon
sysmon64.exe -accepteula -i sysmon-config.xml

# 更新配置
sysmon64.exe -c sysmon-config.xml

# 查看状态
sysmon64.exe -s
```

### 关键事件类型

Sysmon 注册在 `Microsoft-Windows-Sysmon/Operational` 事件日志中，Event ID 映射如下：

| Event ID | 事件类型 | 安全价值 | 狩猎用途 |
|----------|---------|---------|---------|
| 1 | 进程创建 (Process Creation) | 高 | 所有进程执行记录，含命令行 |
| 2 | 进程变更 (Process Change) | 中 | 进程权限调整 |
| 3 | 网络连接 (Network Connect) | 高 | 出站连接，检测 C2 |
| 4 | Sysmon 状态变更 | 低 | 服务启停 |
| 5 | 进程终止 (Process Terminated) | 低 | 进程结束时间 |
| 6 | 驱动加载 (Driver Loaded) | 高 | 内核模块加载 |
| 7 | 镜像加载 (Image Loaded) | 中 | DLL 加载跟踪 |
| 8 | CreateRemoteThread | 极高 | 跨进程注入检测 |
| 9 | RawAccessRead | 高 | 磁盘原始读取（Mimikatz 特征） |
| 10 | ProcessAccess | 高 | 进程句柄打开 |
| 11 | 文件创建 (FileCreate) | 高 | 文件写入事件 |
| 12 | 注册表对象增删 | 中 | 注册表 Key 操作 |
| 13 | 注册表值设置 (Registry Set) | 高 | Run 键值等持久化操作 |
| 14 | 注册表对象重命名 | 中 | 注册表改名 |
| 15 | FileCreateStreamHash | 高 | NTFS 备用数据流检测 |
| 16 | SysmonConfigStateChange | 低 | 配置变更 |
| 17 | PipeEvent (命名管道创建) | 中 | 进程间通信管道 |
| 18 | PipeEvent (命名管道连接) | 中 | 管道连接记录 |
| 19 | WmiEventFilter | 高 | WMI 持久化检测 |
| 20 | WmiEventConsumer | 高 | WMI 消费器检测 |
| 21 | WmiEventConsumerToFilter | 高 | WMI 绑定检测 |
| 22 | DNS 查询 (DNS Query) | 极高 | DNS 请求记录 (Win 8.1+) |

### Sysmon 配置示例

```xml
<Sysmon>
  <!-- 事件过滤配置: 排除正常操作，减少日志量 -->
  <EventFiltering>
    <!-- 排除正常系统进程 -->
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      <Image condition="is">C:\Windows\System32\conhost.exe</Image>
    </ProcessCreate>

    <!-- 仅监控特定端口的网络连接 -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">53</DestinationPort>
    </NetworkConnect>

    <!-- 监控特定文件创建路径 -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\AppData\</TargetFilename>
      <TargetFilename condition="contains">\Startup\</TargetFilename>
      <TargetFilename condition="contains">\Temp\</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

## Windows 事件日志关键 EID

| Event ID | 日志来源 | 描述 | 狩猎价值 |
|----------|---------|------|---------|
| 4688 | Security | 进程创建 (含命令行参数，需审计策略) | 检测异常进程执行 |
| 4689 | Security | 进程终止 | 结合 4688 分析进程生命周期 |
| 4698 | Security | 计划任务创建 | 检测持久化行为 |
| 4700/4701 | Security | 计划任务启用/禁用 | 攻击者操作计划任务 |
| 4104 | PowerShell (Operational) | PowerShell 脚本块记录 | 检测 PowerShell 攻击 |
| 4103 | PowerShell (Operational) | PowerShell 管道执行 | 记录详细 PowerShell 命令 |
| 4624 | Security | 登录成功 | 正常登录审计、异常登录检测 |
| 4625 | Security | 登录失败 | 暴力破解检测 |
| 4648 | Security | 使用显式凭据登录 | Runas 操作检测 |
| 4672 | Security | 分配特权 (管理员登录) | 管理员账户登录记录 |
| 4768 | Security | Kerberos TGT 请求 | Kerberos 攻击分析 |
| 4769 | Security | Kerberos 服务票据请求 | Kerberoasting 检测 |
| 4776 | Security | NTLM 凭据验证 | Pass-the-Hash 检测 |
| 5140 | Security | 网络共享对象访问 | 横向移动检测 |
| 5156 | Security | Windows 防火墙连接 | 出站连接记录 |
| 7036 | System | 服务状态变更 | 服务启动/停止监控 |
| 7045 | System | 新服务安装 | 服务型木马检测 |

## 威胁狩猎方法论

### 狩猎流程

```
假设形成 ──→ 数据采集 ──→ 分析调优 ──→ 发现/排除 ──→ 改进/响应
    ↑                                              │
    └──────────────────────────────────────────────┘
```

### 典型狩猎假设

| 假设 | 数据源 | 查询逻辑 | 预期发现 |
|------|--------|---------|---------|
| 编码 PowerShell 执行 | Event 4104 | `*EncodedCommand*` | 无文件攻击 |
| 异常 Rundll32 行为 | Sysmon EID 1 | `rundll32.exe` 调用非标准 DLL | DLL 劫持 |
| LSASS 异常访问 | Sysmon EID 10 | ProcessAccess to lsass.exe | 凭据窃取 |
| 可疑计划任务创建 | Event 4698 | 非管理员创建的任务 | 持久化后门 |
| DNS 查询异常 | Sysmon EID 22 | 高熵域名、长域名 | DNS 隧道 |

### Sigma 规则

Sigma 是一种通用的签名格式，可以转换为多种 SIEM 查询语言：

```yaml
title: PowerShell Encoded Command Execution
id: d6f9b7f1-8e1a-4a7d-a4f7-9a3f2e1d0b8c
status: test
description: Detects execution of PowerShell with -EncodedCommand parameter
author: Security Team
date: 2026/01/15

logsource:
  product: windows
  category: ps_classic_start
  definition: 'PowerShell logging must be enabled'

detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - '-enc'
      - 'FromBase64String'
      - 'IEX(New-Object Net.WebClient)'
      - '([System.Text.Encoding]::UTF8.GetString'
      - 'System.Convert]::FromBase64String'
  condition: selection

falsepositives:
  - Administrative scripts using legitimate encoding
level: high

tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

### YARA 规则

YARA 用于文件或内存中的模式匹配：

```yara
rule Mimikatz_Detection {
   meta:
      description = "Detect Mimikatz binary in memory or on disk"
      author = "Security Team"
      reference = "https://github.com/gentilkiwi/mimikatz"
   strings:
      $s1 = "mimikatz" fullword wide ascii
      $s2 = "sekurlsa::logonpasswords" fullword wide ascii
      $s3 = "\\_kuhl\_" wide ascii
      $s4 = "kuhl\_m\_sekurlsa\_" wide ascii
      $s5 = "wdigest" wide ascii
      $s6 = "kerberos" wide ascii
      $s7 = "crypto::" wide ascii
      $s8 = "privilege::debug" ascii
   condition:
      any of them
}
```

## Velociraptor — 高级狩猎与取证

Velociraptor 是开源的端点监控、狩猎和取证平台：

| 特性 | 说明 |
|------|------|
| 客户端-服务器架构 | Server 管理多个客户端 |
| VQL 查询语言 | Velociraptor Query Language 用于灵活的数据搜索 |
| 实时狩猎 | 多主机并行执行查询 |
| 取证采集 | 内存、磁盘、注册表、事件日志采集 |
| 自动化响应 | 基于事件的自动响应动作 |

```vql
-- 在所有主机上搜索可疑 PowerShell 进程
SELECT Name, Pid, Ppid, CommandLine, CreateTime
FROM pslist()
WHERE Name =~ "powershell" AND
      CommandLine =~ "EncodedCommand"
      OR CommandLine =~ "FromBase64String"

-- 搜索可疑 DNS 查询
SELECT *
FROM dns()
WHERE Query =~ "\.(xyz|top|club|work)$" AND
      len(string=Query) > 30
```

## 威胁狩猎成熟度

| 级别 | 名称 | 特征 | 数据源 |
|------|------|------|--------|
| 1 | IOCs 驱动 | 基于已知威胁指标搜索 | FireEye/VT hits, IP/Domain |
| 2 | 日志分析 | 基于事件日志搜索 | Sysmon, Windows Event Log |
| 3 | 数据分析 | 统计异常检测，基线偏离 | 全量遥测 + ML 模型 |
| 4 | TTP 驱动 | 基于 ATT&CK 框架系统性狩猎 | 全量遥测 + 关联分析 |
| 5 | 预测性 | AI 驱动的预测性威胁发现 | 全量遥测 + 图分析 + AI |
