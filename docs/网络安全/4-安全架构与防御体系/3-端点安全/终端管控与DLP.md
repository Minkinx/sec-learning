# 终端管控与DLP

> 终端管控（Endpoint Management）和数据防泄漏（Data Loss Prevention, DLP）是防止敏感数据通过端点外泄的关键技术。USB控制、应用白名单、内容感知DLP共同构成了终端数据安全防线。

## USB外设管控

### USB设备识别与分类

```
USB设备分类：
├── 大容量存储设备（U盘、移动硬盘）→ 高风险，需严格控制
├── HID人机交互设备（键盘、鼠标） → 低风险，通常允许
├── 网络设备（USB网卡、蓝牙适配器）→ 中风险，按需允许
├── 通讯设备（USB Modem、RNDIS）→ 中高风险
├── 打印机/扫描仪 → 低风险
└── 智能手机/PDAs → 中高风险（MTP/PTP协议）
```

### Windows组策略USB控制

```xml
<!-- 通过ADMX模板配置USB设备安装限制 -->
<registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions">
  <!-- 拒绝所有可移动设备 -->
  <registryValue name="DenyRemovableDevices" value="1" type="REG_DWORD"/>
  
  <!-- 允许管理员覆盖 -->
  <registryValue name="AllowAdminOverride" value="0" type="REG_DWORD"/>
  
  <!-- 允许已安装的设备ID -->
  <registryValue name="AllowDeviceIDs" value="1" type="REG_DWORD"/>
</registryKey>

<!-- 通过注册表启用USB写保护 -->
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies]
"WriteProtect"=dword:00000001
```

### 企业级USB管控方案对比

| 功能 | 组策略（GPO） | Microsoft DLP Device Control | Forcepoint DLP | Symantec DLP |
|------|-------------|------------------------------|---------------|-------------|
| 基于设备类型控制 | 有限 | 详细分类 | 详细分类 | 详细分类 |
| 基于用户/组控制 | 有限 | 支持 | 支持 | 支持 |
| 文件加密写入 | 不支持 | 支持（BitLocker To Go） | 支持 | 支持 |
| 审计日志 | 有限 | 详细 | 详细 | 详细 |
| 时间策略 | 不直接支持 | 通过条件访问 | 支持 | 支持 |
| 文件类型过滤 | 不支持 | 通过DLP策略 | 支持 | 支持 |

## 应用白名单

### AppLocker

AppLocker是Windows Pro/Enterprise版内置的应用白名单功能：

```xml
<!-- AppLocker XML策略示例（PS脚本规则） -->
<AppLockerPolicy Version="1">
  <!-- 可执行文件规则 -->
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" 
                  Name="Allow Program Files" Description="">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" 
                  Name="Allow Windows" Description="">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <PublisherRule Id="00000000-0000-0000-0000-000000000003" 
                   Name="Allow Microsoft Signed" Description="">
      <Conditions>
        <PublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" 
                           ProductName="*" BinaryName="*"/>
      </Conditions>
    </PublisherRule>
  </RuleCollection>
  
  <!-- 脚本规则 -->
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" 
                  Name="Allow Scripts" Description="">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\*.ps1"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  
  <!-- Windows Installer规则 -->
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" 
                  Name="Allow MSI" Description="">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

```powershell
# AppLocker管理和监控PowerShell命令
# 导出当前策略
Get-AppLockerPolicy -Local | Export-AppLockerPolicy -Path C:\AppLocker\policy.xml

# 测试策略效果
Test-AppLockerPolicy -Path C:\Windows\System32\calc.exe -User Everyone

# 查看AppLocker事件日志
Get-WinEvent -LogName Microsoft-Windows-AppLocker/EXE and DLL | 
  Where-Object {$_.Id -eq 8004} |  # 阻止事件ID
  Format-Table TimeCreated, Message -Wrap

# 生成仅审计模式策略
Set-AppLockerPolicy -Policy $policy -RuleType Audit
```

### AppLocker vs WDAC对比

| 特性 | AppLocker | WDAC（Windows Defender Application Control） |
|------|----------|---------------------------------------------|
| 架构级别 | 用户态 | 内核态 |
| 绕过风险 | 可通过注入绕过 | 更难绕过 |
| 配置复杂度 | 简单 | 复杂 |
| 管理方式 | GPO | GPO + Intune + PowerShell |
| 策略类型 | 白名单 + 黑名单 | 仅白名单 |
| 支持平台 | Windows Pro/Enterprise | Windows Enterprise/Server |
| 推荐使用 | 中小企业 | 高安全环境 |

```powershell
# WDAC策略生成示例
# 1. 生成默认策略
New-CIPolicy -FilePath C:\WDAC\BasePolicy.xml -Level FilePublisher -Fallback Hash

# 2. 转换为二进制并部署
ConvertFrom-CIPolicy -XmlFilePath C:\WDAC\BasePolicy.xml -BinaryFilePath C:\WDAC\BasePolicy.bin

# 3. 将策略复制到EFI分区（部署）
Copy-Item C:\WDAC\BasePolicy.bin C:\EFI\Microsoft\Boot\BasePolicy.p7b
```

## DLP内容感知策略

### 敏感数据类型

| 数据类型 | 正则表示例 | 示例匹配 |
|---------|-----------|---------|
| 信用卡号 | `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b` | 4111-1111-1111-1111 |
| 中国大陆身份证 | `\b[1-9]\d{5}(?:19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` | 110101199001011234 |
| 手机号 | `\b1[3-9]\d{9}\b` | 13800138000 |
| 银行卡号 | `\b(62\d{14,17})\b` | 6222021234567890 |
| API密钥 | `(?:AKIA[0-9A-Z]{16})\|(?:sk-[a-zA-Z0-9]{32,})` | AKIAIOSFODNN7EXAMPLE |

### Microsoft Endpoint DLP策略配置

```powershell
# Microsoft Purview DLP策略（PowerShell）
# 创建敏感信息类型
New-DlpSensitiveInformationType -Name "Custom-PII" `
  -Description "中国个人身份信息" `
  -Patterns @(
    [PSCustomObject]@{
      Element = "Regex"
      Regex = "\b1[3-9]\d{9}\b"  # 手机号
      ConfidenceLevel = "High"
    },
    [PSCustomObject]@{
      Element = "Regex" 
      Regex = "\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"
      ConfidenceLevel = "High"
    }
  )

# 创建DLP策略
New-DlpCompliancePolicy -Name "China-PII-Protection" `
  -Description "防护中国个人身份信息外泄" `
  -Priority 1 `
  -ExchangeLocation All `
  -SharePointLocation All `
  -OneDriveLocation All `
  -EndpointDeviceLocation All

# 创建DLP规则
New-DlpComplianceRule -Name "China-PII-Block-External" `
  -Policy "China-PII-Protection" `
  -SentTo "NotInOrganization" `
  -Condition @{
    SensitiveInformationContains = @(
      [PSCustomObject]@{
        Name = "Custom-PII"
        MinCount = 1
        MaxCount = -1
      }
    )
  } `
  -BlockAccess $true `
  -NotifyUser $true `
  -NotifyPolicyTip $true
```

## DLP分级策略

根据数据敏感度和传播渠道定义不同的防护策略：

| 数据分类 | 邮件外发 | USB拷贝 | 云上传 | 打印 | 截图 |
|---------|---------|---------|-------|------|------|
| 公开（Public） | 允许 | 允许 | 允许 | 允许 | 允许 |
| 内部（Internal） | 允许，审计 | 允许，审计 | 允许，审计 | 允许 | 允许 |
| 机密（Confidential） | 阻止，需审批 | 加密写入 | 阻止，需审批 | 审计 | 阻止 |
| 绝密（Restricted） | 阻止 | 阻止 | 阻止 | 阻止 | 阻止 |

## DLP与CAT（Content Aware）检测原理

```
数据检测流程：
1. 数据指纹匹配（精确匹配、模糊哈希、文档指纹）
   ├─ 精确匹配：已知敏感文档的完整MD5/SHA256匹配
   ├─ 模糊哈希：基于内容的相似度匹配（ssdeep）
   ├─ 文档指纹：提取段落/句子级指纹，容忍格式变化
   └─ 数据库指纹：结构化数据的部分字段匹配
    
2. 正则表达式匹配
   ├─ 信用卡号、身份证号、SSN等固定模式
   └─ 基于上下文的关键词+模式组合匹配（降低误报）

3. 机器学习分类
   ├─ 基于自然语言处理的内容分类
   └─ 基于关键词密度的主题分类
```

```python
# DLP检测引擎示例（简化）
import re
import hashlib

class DLPEngine:
    def __init__(self):
        self.patterns = {
            "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
            "china_id": r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            "china_phone": r"\b1[3-9]\d{9}\b",
            "api_key_aws": r"AKIA[0-9A-Z]{16}",
        }
        
        self.keyword_contexts = {
            "confidential": ["机密", "保密", "内部资料", "confidential", "secret"],
            "financial": ["银行", "账户", "转账", "银行账号", "银行卡"],
        }
    
    def scan_content(self, content, filename=""):
        """扫描内容中的敏感数据"""
        findings = []
        
        # 正则匹配
        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": name,
                    "count": len(matches),
                    "severity": "HIGH",
                    "matches": matches[:5]  # 只保留前5个匹配
                })
        
        # 上下文关键词检测
        for category, keywords in self.keyword_contexts.items():
            for kw in keywords:
                if kw in content:
                    findings.append({
                        "type": "keyword_context",
                        "category": category,
                        "keyword": kw,
                        "severity": "MEDIUM"
                    })
        
        # 文件哈希匹配
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in self.sensitive_document_hashes:
            findings.append({
                "type": "exact_hash_match",
                "hash": content_hash,
                "severity": "CRITICAL"
            })
        
        return findings
    
    def apply_policy(self, findings, destination="external_email"):
        """根据发现结果和传输渠道采取动作"""
        actions = []
        
        for finding in findings:
            if finding["severity"] == "CRITICAL":
                actions.append("BLOCK")
            elif finding["severity"] == "HIGH":
                if destination in ["usb", "external_email"]:
                    actions.append("BLOCK")
                else:
                    actions.append("ENCRYPT")
            elif finding["severity"] == "MEDIUM":
                actions.append("WARN")
        
        if "BLOCK" in actions:
            return "BLOCK"
        elif "ENCRYPT" in actions:
            return "ENCRYPT" 
        elif "WARN" in actions:
            return "WARN"
        else:
            return "ALLOW"
```

## DLP + CASB 集成

```
[终端DLP] ──敏感数据检测──► [CASB（云访问安全代理）]
    │                              │
    │ 策略1：检测到信用卡号         │ 策略A：阻止上传到个人云存储
    │ 策略2：检测到源代码          │ 策略B：对上传到企业云的文件
    │                              │        自动加密+标签
    │                              │
    ▼                              ▼
[统一策略控制台] ◄──────告警/事件─────
    │
    ├─ 邮件告警
    ├─ SIEM事件
    └─ 合规报告
```

## 总结

终端管控和DLP是防止数据泄露的最后一道防线。USB管控和应用白名单控制"通道"，DLP控制"内容"。在实际部署中，需要将USB控制、AppLocker/WDAC应用白名单、内容感知DLP三者结合，并集成CASB和SIEM平台，构建从端点到云的全链路数据保护体系。
