# 特权账号管理PAM

> 特权账号管理（Privileged Access Management, PAM）专注于保护组织中最高风险的身份——管理员、根用户、服务账号等拥有特权访问权限的账号。PAM的核心能力包括凭据保险库、会话管理、JIT访问和自动密码轮换。

## PAM的核心能力

```
PAM功能全景：
┌─────────────────────────────────────────────────────────────┐
│                    Privileged Access Management               │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ 凭据管理      │ 会话管理     │ 权限提升      │ 审计与分析     │
├──────────────┼──────────────┼──────────────┼────────────────┤
│ ● 密码保险库  │ ● 会话录制   │ ● JIT访问    │ ● 特权会话审计  │
│ ● 自动轮换    │ ● 会话代理   │ ● 临时提权   │ ● 异常行为分析  │
│ ● 凭据检入/出 │ ● 命令拦截   │ ● 应用2FA    │ ● 特权账号发现  │
│ ● SSH密钥管理 │ ● 实时监控   │ ● 审批工作流 │ ● 合规报告      │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

## CyberArk企业PAM架构

CyberArk是市场领先的企业PAM解决方案，其组件架构如下：

```
                          [Web Access]
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│                     CyberArk PAM                          │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │
│  │    Vault    │  │    CPM     │  │        PSM         │ │
│  │  密码保险库  │  │ 策略管理    │  │  特权会话管理      │ │
│  │  AES-256加密│  │ 自动轮换    │  │  会话代理+录制     │ │
│  │  HSM集成    │  │ 密码策略   │  │  命令审计和控制    │ │
│  └────────────┘  └────────────┘  └────────────────────┘ │
│                                                          │
│  ┌────────────┐  ┌────────────┐                          │
│  │    AIM     │  │    PVWA    │                          │
│  │ 应用身份管理 │  │  Web管理   │                          │
│  │ 应用-应用   │  │  控制台    │                          │
│  │ 凭据管理    │  │  审批工作流 │                          │
│  └────────────┘  └────────────┘                          │
└──────────────────────────────────────────────────────────┘
```

### 组件详解

| 组件 | 全称 | 功能 |
|------|------|------|
| Vault | Password Vault | 核心组件，存储所有凭据，提供加密和访问控制 |
| CPM | Central Policy Manager | 自动执行密码轮换，执行密码策略 |
| PSM | Privileged Session Manager | 代理特权会话，监控、录制和审计 |
| AIM | Application Identity Manager | 面向应用的凭据管理，应用-应用认证 |
| PVWA | Password Vault Web Access | Web管理界面，用户自助服务 |

### CyberArk Vault安全架构

```yaml
cyberark_vault_security:
  encryption:
    at_rest: "AES-256"
    master_key: "需要双人解锁（Dual Control）"
    key_management: "HSM（硬件安全模块）"
  
  access_control:
    authentication:
      - "用户名+密码（至少14位）"
      - "可选：RADIUS/LDAP多因素认证"
    authorization:
      - "安全级别（Safe）级别的访问权限"
      - "基于用户/组的细粒度权限"
  
  disaster_recovery:
    - "主Vault和DR Vault自动复制"
    - "DR Vault支持异地部署"
    - "自动故障切换"
  
  auditing:
    - "所有Vault操作记录不可变日志"
    - "日志发送到SIEM系统"
    - "管理员操作监控和告警"
```

### CPM密码轮换配置

```yaml
# CyberArk CPM密码策略配置示例
password_policy:
  name: "Default Policy"
  
  complexity:
    min_length: 25
    max_length: 40
    require_upper: true
    require_lower: true
    require_digit: true
    require_special: true
    
  rotation:
    schedule: "30 DAYS"         # 管理员密码30天轮换
    service_account: "90 DAYS"  # 服务账号90天轮换
    ssh_key: "365 DAYS"         # SSH密钥每年轮换
    
  rules:
    - "新密码不得与历史10个密码重复"
    - "密码不得包含用户名或公司名"
    - "每次轮换后自动更新关联服务"
```

## JIT特权访问

Just-In-Time（JIT）访问是现代PAM中最重要的能力之一，取代了传统的永久特权。

### JIT vs 传统特权管理

| 维度 | 传统特权管理 | JIT特权访问 |
|------|-------------|------------|
| 权限时长 | 永久（除非被撤销） | 按需分配（受限时间段） |
| 授权方式 | 预分配角色 | 审批工作流 |
| 风险暴露 | 窗口无限 | 窗口受控 |
| 审计 | 难以追踪使用情况 | 全量审计 |
| 管理员数量 | 固定 | 随时间变化 |

```python
# JIT访问请求和授权流程
class JITAccessManager:
    def __init__(self, pam_system):
        self.pam = pam_system
    
    def request_privileged_access(self, user, target_system, reason, duration_minutes=60):
        """请求JIT特权访问"""
        request = {
            "user": user,
            "target": target_system,
            "reason": reason,
            "requested_duration": duration_minutes,
            "status": "pending",
            "timestamp": datetime.now()
        }
        
        # 1. 检查用户是否有权限请求
        if not self.authorize_request(user, target_system):
            request["status"] = "denied"
            request["reason_detail"] = "用户未授权请求此系统"
            return request
        
        # 2. 自动审批or需要人工审批
        if duration_minutes <= 30 and target_system in self.auto_approve_systems:
            request["status"] = "approved"
            request["approved_by"] = "SYSTEM"
        else:
            # 发送审批请求
            self.notify_approver(user, target_system, reason, duration_minutes)
            request["status"] = "pending_approval"
        
        self.pam.log_request(request)
        return request
    
    def grant_privileged_access(self, request_id):
        """授予JIT访问"""
        request = self.pam.get_request(request_id)
        
        # 1. 从Vault检出凭据
        credential = self.pam.checkout_credential(
            target_system=request["target"],
            user=request["user"],
            lease_duration=request["requested_duration"]
        )
        
        # 2. 创建临时权限
        if request["target"]["type"] == "windows":
            self.grant_local_admin(request["user"], request["target"]["hostname"])
        elif request["target"]["type"] == "linux":
            self.grant_sudo_access(request["user"], request["target"]["hostname"])
        elif request["target"]["type"] == "cloud":
            self.grant_iam_role(request["user"], request["target"]["arn"])
        
        # 3. 设置自动回收定时器
        self.schedule_revocation(request_id, request["requested_duration"])
        
        return credential
    
    def revoke_access(self, request_id):
        """回收特权访问"""
        request = self.pam.get_request(request_id)
        
        # 1. 回收权限
        self.remove_local_admin(request["user"], request["target"]["hostname"])
        self.remove_sudo_access(request["user"], request["target"]["hostname"])
        
        # 2. 强制凭据轮换
        self.pam.rotate_credential(target_system=request["target"])
        
        # 3. 日志记录
        self.pam.finalize_session(request_id, duration="actual_session_time")
```

## 特权会话管理

### PSM会话代理

CyberArk PSM通过代理方式管理特权会话：

```
[管理员] → [PSM代理] → [目标服务器（SSH/RDP）]
              │
              ├─ 会话录制（视频+文字）
              ├─ 命令拦截（黑名单/白名单）
              ├─ 文件传输控制
              └─ 实时监控（可随时切断）
```

### PSM命令拦截策略

```xml
<!-- CyberArk PSM命令拦截配置 -->
<PSMCommands>
  <!-- 危险命令黑名单 -->
  <BlackList>
    <Command>rm -rf /</Command>
    <Command>mkfs.*</Command>
    <Command>dd if=/dev/zero of=/dev/sda</Command>
    <Command>shutdown -h now</Command>
    <Command>reboot</Command>
    <Command>passwd root</Command>
    <Command>/etc/init.d/iptables stop</Command>
  </BlackList>
  
  <!-- 允许命令白名单（Linux sudo） -->
  <WhiteList>
    <Command>/usr/bin/systemctl status *</Command>
    <Command>/usr/bin/journalctl -u *</Command>
    <Command>/usr/bin/tail -f /var/log/*</Command>
    <Command>/usr/bin/grep * /var/log/*</Command>
  </WhiteList>
  
  <!-- 敏感命令需要额外审批 -->
  <DangerZone>
    <Command>/usr/bin/useradd *</Command>
    <Command>/usr/bin/usermod *</Command>
    <Command>/usr/bin/passwd *</Command>
    <Command pattern="*">chmod 777 *</Command>
  </DangerZone>
</PSMCommands>
```

## 密码轮换策略

| 账号类型 | 轮换频率 | 密码长度 | 复杂度 | 备注 |
|---------|---------|---------|--------|------|
| 本地管理员 | 30天 | 25-40位 | 高 | 轮换后自动更新所有服务 |
| 域管理员 | 30天 | 30-50位 | 高 | 需要域控复制完成 |
| 服务账号 | 90天 | 20-30位 | 中 | 需服务重启 |
| 应用程序账号 | 按需 | 随机 | 中 | 与应用生命周期绑定 |
| SSH密钥 | 365天 | 4096位(RSA) | N/A | 同时更新authorized_keys |
| 数据库管理员 | 30天 | 30-50位 | 高 | 需数据库用户更新 |
| 云服务账号 | 90天 | API Key格式 | 高 | 使用Cloud IAM角色代替 |

```python
# 密码自动轮换脚本（简化示例）
import secrets
import string
import paramiko

def rotate_linux_root_password(hostname, vault, new_password=None):
    """轮换Linux root密码"""
    # 1. 从Vault获取当前密码
    current_password = vault.get_credential(f"linux/{hostname}/root")
    
    # 2. 生成新密码
    if new_password is None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        new_password = ''.join(secrets.choice(alphabet) for _ in range(30))
    
    # 3. SSH连接并修改密码
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username="root", password=current_password)
    
    stdin, stdout, stderr = ssh.exec_command(f"echo 'root:{new_password}' | chpasswd")
    exit_code = stdout.channel.recv_exit_status()
    
    if exit_code == 0:
        # 4. 更新Vault中的密码
        vault.update_credential(f"linux/{hostname}/root", new_password)
        
        # 5. 触发密码使用后更新关联服务
        vault.trigger_service_update(hostname)
        
        return {"status": "success", "hostname": hostname}
    else:
        return {"status": "failed", "error": stderr.read().decode()}
```

## 服务账号管理

服务账号是PAM中容易被忽视但风险极高的领域：

### 服务账号管理最佳实践

| 实践 | 说明 | 实施 |
|------|------|------|
| 避免共享账号 | 每个服务使用独立账号 | PAM自动创建和管理服务账号 |
| 最小权限 | 服务账号只授予所需的最小权限 | 定期审计服务账号权限 |
| 自动轮换 | 定期轮换服务账号密码 | CPM策略配置90天轮换周期 |
| 行为监控 | 监控服务账号的异常行为 | 基线分析和异常告警 |
| 禁用交互登录 | 服务账号不应允许交互登录 | 通过GPO禁用本地登录权限 |
| 使用托管服务账号（gMSA） | Windows环境下使用gMSA | Active Directory配置gMSA |

```powershell
# Windows gMSA（Group Managed Service Account）配置
# 创建gMSA
New-ADServiceAccount -Name "SVC-PaymentAPI" `
  -DNSHostName "svc-paymentapi.corp.company.com" `
  -PrincipalsAllowedToRetrieveManagedPassword "Payment-Server-Group" `
  -KerberosEncryptionType AES256

# 在服务器上安装gMSA
Install-ADServiceAccount -Identity "SVC-PaymentAPI"

# 配置服务使用gMSA
Set-Service -Name "PaymentService" `
  -Credential (Get-Credential "CORP\SVC-PaymentAPI$")

# 测试gMSA
Test-ADServiceAccount -Identity "SVC-PaymentAPI"
```

## 总结

PAM是身份安全中风险最高、防护最关键的领域。通过凭据保险库（AES-256加密+HSM）、密码自动轮换、JIT访问和会话录制等能力，PAM大大降低了特权账号被滥用的风险。密码轮换频率和复杂度的阶梯式策略（管理员30天、服务账号90天）平衡了安全性和运维效率。在现代零信任架构中，PAM是实现"零长期特权"原则的关键基础设施。
