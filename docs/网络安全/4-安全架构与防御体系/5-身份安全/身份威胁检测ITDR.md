# 身份威胁检测ITDR

> 身份威胁检测与响应（Identity Threat Detection and Response, ITDR）是Gartner提出的新兴安全领域，专注于检测和应对针对身份系统的攻击。随着身份成为新的安全边界，ITDR正在成为身份安全体系中不可或缺的组成部分。

## ITDR在身份安全架构中的位置

```
传统身份安全：
[IGA] → [PAM] → [IDaaS] → 核心身份基础设施
  │        │        │
  └────────┴────────┘
  治理、管理、访问——但缺乏检测能力

ITDR补充后的身份安全：
[IGA] → [PAM] → [IDaaS] → 核心身份基础设施
  │        │        │              │
  └────────┴────────┘              │
                                  ▼
                             [ITDR检测层]
                              ├─ 异常检测
                              ├─ 攻击识别
                              └─ 自动响应
```

## 身份攻击类型

### 1. Token Theft（令牌窃取）

攻击者通过窃取会话Cookie、OAuth访问令牌或刷新令牌来冒充用户。

```
攻击流程：
1. 用户登录企业应用，获取会话令牌
2. 攻击者通过以下方式窃取令牌：
   ├─ XSS攻击窃取Cookie
   ├─ 恶意浏览器扩展读取浏览器存储
   ├─ 中间人攻击截获令牌
   └─ 设备上恶意软件窃取本地令牌
3. 攻击者使用窃取的令牌访问应用
4. 令牌验证通过，攻击者完全冒充用户

检测难点：令牌本身是有效的，行为分析是关键
```

### 2. MFA Fatigue（MFA疲劳攻击）

攻击者不断发送MFA推送通知，直到用户因疲劳而接受：

```
攻击过程：
时间   攻击者操作                              用户状态
T+0   尝试登录用户账号，触发MFA推送             收到推送通知，拒绝
T+1   再次推送                                 再次拒绝
T+2   第三次推送                               开始烦躁
T+3   第四次推送                               怀疑有问题
T+5   第五次推送                               已经疲劳
T+10  模拟午夜时间推送                          半睡状态中接受
```

**缓解措施**：

| 措施 | 说明 | 有效性 |
|------|------|--------|
| 数字匹配 | MFA推送要求输入屏幕上的数字验证码 | 高（用户需要确认具体数字） |
| 限制推送频率 | 单个用户在短时间内限制推送次数 | 中（5分钟内最多3次） |
| FIDO2/WebAuthn | 使用硬件安全密钥 | 最高（物理交互，无法远程推送） |
| 异常检测 | 检测暴力MFA推送模式并阻止 | 高 |

### 3. BEC（Business Email Compromise）

BEC是一种针对企业高管的定向社交工程攻击：

```yaml
bee_attack_patterns:
  - type: "CEO Fraud"
    description: "攻击者冒充CEO发邮件要求财务紧急转账"
    indicators:
      - "发件人域名与公司域名相似（如company.co vs company.com）"
      - "邮件语气紧迫，要求立即处理"
      - "要求绕过正常审批流程"
      - "发件时间在非工作时间"
  
  - type: "Account Compromise"
    description: "攻击者攻陷合法邮箱账号后发送欺诈邮件"
    indicators:
      - "异常的地理位置登录"
      - "新设备登录"
      - "邮件转发规则被添加（攻击者监控邮件内容）"
      - "大范围发送内部邮件"
  
  - type: "Vendor Email Compromise"
    description: "假冒供应商请求更改付款信息"
    indicators:
      - "供应商声称银行账户信息有变"
      - "声称原有账户"被冻结""
      - "邮件域名与供应商官方域名存在细微差异"
```

### 4. Consent Phishing（OAuth应用钓鱼）

攻击者创建恶意OAuth应用，诱导用户授权：

```
攻击流程：
1. 攻击者在云平台注册恶意应用（如"PDF Viewer Pro"）
2. 发送钓鱼邮件诱导用户授权
3. 用户点击授权链接，看到OAuth同意页面
4. 恶意应用请求高权限（如"Read all mail"、"Read contacts"）
5. 用户同意授权 → 攻击者获得OAuth令牌
6. 攻击者使用令牌访问用户邮箱、联系人等数据

可怕之处：OAuth授权后，攻击者不需要用户密码即可持续访问数据
```

**检测指标**：

```
可疑OAuth应用特征：
├─ 发布者名称模糊（如"John Smith"而非公司名）
├─ 请求权限超过应用功能所需（如PDF阅读器请求邮件读取）
├─ 应用最近创建（<30天）
├─ 没有隐私政策链接
├─ 没有经过组织验证
├─ 多位用户授权了同一可疑应用
```

### 5. Cloud-to-Cloud Lateral Movement

攻击者利用一个云服务的权限横向移动到另一个云服务：

```python
# 横向移动检测模型简化示例
class LateralMovementDetector:
    def __init__(self, identity_graph, log_analytics):
        self.graph = identity_graph  # 身份关系图
        self.logs = log_analytics      # 日志分析引擎
    
    def detect_lateral_movement(self, user_events):
        """
        检测异常的身份横向移动
        """
        alerts = []
        
        # 1. 检查用户在短时间内跨越多个云服务
        for user, events in self.group_by_user(user_events):
            services_accessed = set(e["service"] for e in events)
            time_window = max(e["timestamp"] for e in events) - min(e["timestamp"] for e in events)
            
            if len(services_accessed) >= 3 and time_window.seconds < 300:
                # 用户在5分钟内访问了3个以上不同的云服务
                alerts.append({
                    "type": "RAPID_CROSS_SERVICE_ACCESS",
                    "user": user,
                    "services": list(services_accessed),
                    "risk_score": 0.7
                })
        
        # 2. 检查用户是否访问了以前从未访问过的服务
        for user, events in self.group_by_user(user_events):
            for event in events:
                if event["service"] not in self.get_user_history(user):
                    alerts.append({
                        "type": "FIRST_TIME_SERVICE_ACCESS",
                        "user": user,
                        "service": event["service"],
                        "risk_score": 0.4 + (0.1 if event["ip"] not in self.get_user_ips(user) else 0)
                    })
        
        return alerts
```

## 检测技术

### Azure AD Identity Protection

Microsoft Entra ID Protection提供身份威胁检测的内置能力：

| 风险检测类型 | 描述 | 严重级别 |
|------------|------|---------|
| Leaked Credentials | 公开泄露的用户凭据 | 高 |
| Atypical Travel | 短时间内无法实现的地理位置切换 | 中 |
| Anonymous IP | 通过Tor/代理登录 | 中 |
| Malware Linked IP | 与已知恶意软件关联的IP | 中 |
| Unfamiliar Sign-in Properties | 不熟悉的登录特征 | 中 |
| Password Spray | 密码喷洒攻击 | 高 |
| Token Issuer Anomaly | 异常的令牌签发者 | 高 |

```json
{
  "riskDetection": {
    "riskEventType": "leakedCredentials",
    "riskLevel": "high",
    "riskState": "atRisk",
    "userDisplayName": "Zhang San",
    "userPrincipalName": "zhangsan@company.com",
    "detectedDateTime": "2024-05-26T10:15:30Z",
    "ipAddress": "203.0.113.50",
    "location": {
      "city": "Unknown",
      "countryOrRegion": "CN"
    }
  }
}
```

### Microsoft Defender for Identity

Microsoft Defender for Identity（前Azure ATP）用于检测本地AD的攻击行为：

```powershell
# Defender for Identity 告警查询（KQL）
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "SamAccountNameChanged"
| extend TargetAccount = tostring(AdditionalFields.TARGET_OBJECT_SAM)
| extend SourceAccount = tostring(AdditionalFields.SOURCE_ACCOUNT)
| join kind=inner (
    IdentityDirectoryEvents
    | where ActionType == "PasswordReset"
    | project TargetAccount = tostring(AdditionalFields.TARGET_OBJECT_SAM),
              ResetTime = Timestamp
) on TargetAccount
| project Timestamp, SourceAccount, TargetAccount, ResetTime
| where datetime_diff('minute', ResetTime, Timestamp) < 5
```

**Defender for Identity检测能力**：

| 检测类型 | 攻击技术 | MITRE ATT&CK ID |
|---------|---------|----------------|
| DCSync检测 | 通过DRS协议复制域凭据 | T1003.006 |
| HoneyToken | 对蜜令牌账号的访问告警 | - |
| Golden Ticket | Kerberos伪造票据检测 | T1558.001 |
| Kerberoasting | 服务账号Kerberos TGS请求异常 | T1558.003 |
| Overpass-the-Hash | 通过NTLM哈希请求Kerberos TGT | T1550.002 |
| Skeleton Key | 恶意LSASS补丁检测 | T1554 |
| Pass-the-Hash | 通过哈希认证横向移动 | T1550.002 |

### CrowdStrike Falcon Identity Threat Detection

```yaml
# CrowdStrike身份威胁检测能力
identity_threat_detection:
  lateral_movement:
    - "使用compromised凭据的RDP连接"
    - "异常的管理共享访问（ADMIN$、IPC$）"
    - "PsExec/WMI/WinRM远程执行"
    - "异常的服务创建"
  
  credential_access:
    - "LSASS内存转储"
    - "NTDS.dit文件访问"
    - "注册表SAM访问"
    - "Kerberos TGS请求异常"
  
  privilege_escalation:
    - "令牌窃取（Token Theft）"
    - "服务权限利用"
    - "计划任务创建"
    - "DLL劫持"
  
  persistence:
    - "新添加的域管理员"
    - "异常的Kerberos票据"
    - "SID历史注入"
    - "DCShadow攻击"
```

## 自动响应

### 条件访问策略响应

```json
{
  "conditional_access_response": {
    "detection": "leakedCredentials",
    "affected_user": "zhangsan@company.com",
    
    "auto_response": {
      "type": "REQUIRE_PASSWORD_CHANGE",
      "priority": "HIGH",
      "actions": [
        {
          "step": 1,
          "action": "FORCE_PASSWORD_RESET",
          "description": "强制用户重置密码",
          "execute_after_seconds": 0
        },
        {
          "step": 2,
          "action": "REVOKE_ALL_TOKENS",
          "description": "撤销所有活跃令牌和会话",
          "execute_after_seconds": 30
        },
        {
          "step": 3,
          "action": "ENFORCE_MFA",
          "description": "强制下一次登录需要MFA",
          "execute_after_seconds": 60
        },
        {
          "step": 4,
          "action": "NOTIFY_USER_AND_MANAGER",
          "description": "通知用户和经理",
          "execute_after_seconds": 120
        }
      ]
    }
  }
}
```

### Azure AD自动响应配置

```powershell
# Azure AD自动响应：检测到风险用户后自动修复
$authenticationContext = New-Object Microsoft.Open.MSGraph.Model.AuthenticationContext
$authenticationContext.AuthenticationContextClassReferences = @("c1")

# 配置自动补救策略
$policy = New-Object Microsoft.Open.MSGraph.Model.AccessPolicy
$policy.DisplayName = "Automated Response for Compromised Users"
$policy.Conditions.Users.IncludeUsers = @("All")
$policy.GrantControls.BuiltInControls = @("mfa", "passwordChange")
$policy.SessionControls.SignInFrequency.Value = 1
$policy.SessionControls.SignInFrequency.Type = "hours"

# 创建自动化
New-AzureADMSIdentityProtectionPolicy `
  -DisplayName "Compromised User Auto-Remediation" `
  -State "enabled" `
  -UserRiskLevel "high" `
  -GrantControl @{
    BuiltInControls = @("passwordChange")
  }
```

### Okta Workflows自动响应

```yaml
# Okta Workflows 自动响应流程图
triggers:
  - event: "USER_RISK_SCORE_CHANGED"
    condition: "risk_score > 0.8"
  
steps:
  - action: "OKTA_SUSPEND_USER"
    params:
      user_id: "${event.user.id}"
  
  - action: "SEND_EMAIL"
    params:
      to: "${event.user.manager.email}"
      subject: "[SECURITY ALERT] User compromised - ${event.user.profile.login}"
      body: |
        User ${event.user.profile.login} has been suspended due to 
        high-risk detection (score: ${event.risk_score}).
        
        Detection type: ${event.detection_type}
        Detection time: ${event.timestamp}
        
        Please verify with user and approve password reset.
  
  - action: "CREATE_TICKET"
    params:
      system: "JIRA"
      project: "SEC"
      summary: "Identity Compromise - ${event.user.profile.login}"
      priority: "Critical"
      assignee: "SOC_Team"
  
  - action: "WAIT"
    params:
      duration: "30 minutes"
  
  - action: "REVOKE_ALL_SESSIONS"
    params:
      user_id: "${event.user.id}"
  
  - action: "LOG_TO_SIEM"
    params:
      system: "Splunk"
      event_type: "identity_compromise_response"
      severity: "high"
```

## SOAR集成

ITDR与SOAR（安全编排自动化和响应）平台集成实现全自动响应：

```python
class ITDR_SOAR_Integration:
    def handle_identity_incident(self, detection):
        """处理身份安全事件的标准响应流程"""
        
        # Level 1 - 低风险：通知+观察
        if detection.severity == "LOW":
            self.notify_user(detection.user_id)
            self.log_to_siem(detection)
        
        # Level 2 - 中风险：增强验证+限制访问
        elif detection.severity == "MEDIUM":
            self.require_mfa(detection.user_id)
            self.restrict_access(detection.user_id, ["admin-portal", "payment-api"])
            self.notify_manager(detection.user_id, detection)
            self.create_ticket(detection, priority="HIGH")
        
        # Level 3 - 高风险：立即隔离
        elif detection.severity == "HIGH":
            self.suspend_user(detection.user_id)
            self.revoke_all_tokens(detection.user_id)
            self.revoke_all_sessions(detection.user_id)
            self.notify_soc(detection)
            self.create_ticket(detection, priority="CRITICAL")
            self.trigger_forensic_collection(detection.user_id)
            
            # 如果是特权账号，自动轮换密码
            if detection.user_type == "PRIVILEGED":
                self.pam_rotate_credentials(detection.user_id)
```

## 总结

ITDR填补了传统身份安全（IGA、PAM、IDaaS）在检测和响应层面的空白。身份攻击向量从Token盗窃、MFA疲劳到BEC和云间横向移动日益多样，需要专门的检测能力才能及时发现和响应。Azure AD Identity Protection、Microsoft Defender for Identity和CrowdStrike Falcon是当前主流的ITDR解决方案，结合条件访问策略和SOAR工作流，可以实现从检测到响应的全自动化闭环。
