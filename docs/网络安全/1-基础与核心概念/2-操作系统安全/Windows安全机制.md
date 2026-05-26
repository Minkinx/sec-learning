# Windows安全机制

> Windows操作系统拥有复杂而完善的安全体系，涵盖身份认证、授权、审计等多个子系统。理解这些机制是进行Windows安全加固和攻防分析的前提。

## 核心安全组件

### SRM（Security Reference Monitor）
SRM是Windows执行体的一部分，负责：
- 强制检查所有对象访问请求
- 根据安全描述符（Security Descriptor）中的DACL判断访问权限
- 生成安全审计事件（若SACL中配置了审计）

SRM运行在内核模式下，用户态程序无法绕过其检查。任何对文件、注册表、进程等对象的访问，都必须经过SRM的授权验证。

### LSA（Local Security Authority）
LSA是Windows安全子系统核心组件：
- 管理本地安全策略（密码策略、审计策略、用户权限分配）
- 处理用户登录验证（本地登录或域登录）
- 生成安全访问令牌（Access Token）
- 与LSA策略数据库交互，存储安全策略配置

### SAM（Security Account Manager）
SAM是本地用户和组的凭据存储数据库：
- 存储用户密码的NTLM哈希值
- 位于 `%SystemRoot%\system32\config\SAM`
- 被系统进程锁定，无法直接复制（需使用卷影复制或注册表提取）
- 历史上是Pass-the-Hash攻击和凭据转储（如Mimikatz）的主要目标

## 认证协议比较

| 特性 | NTLM | Kerberos |
|------|------|----------|
| 类型 | 挑战-响应 | 票据（Ticket-based） |
| 架构 | 点对点 | 需KDC（DC） |
| 安全性 | 较弱，无相互认证 | 强，支持相互认证 |
| 协议 | NTLMv1已废弃，NTLMv2仍可用 | RFC 4120 |
| 信道 | 无 | 可选通道绑定 |
| 默认在域环境 | 否（备选） | 是 |

### NTLM认证流程
```
客户端 → 服务器：协商（请求认证）
服务器 → 客户端：挑战（随机16字节nonce）
客户端 → 服务器：响应（NTLMv2 = HMAC-MD5(挑战 + 用户密码哈希)）
服务器 → DC：验证响应
DC → 服务器：结果
```

### Kerberos认证流程
```
客户端 → AS：请求TGT（输入密码）
AS → 客户端：TGT（用KRBTGT哈希加密的票据）
客户端 → TGS：请求服务票据（携带TGT）
TGS → 客户端：服务票据（用服务账号密码哈希加密）
客户端 → 服务器：服务票据
服务器 → KDC：可选验证（PAC校验）
```

## Credential Guard

Windows 10/11和企业级Windows Server中引入的基于虚拟化的安全功能：
- 使用Hyper-V隔离LSASS进程，防止Mimikatz等工具提取凭据
- 凭据加密存储在VBS（Virtualization Based Security）环境中
- 即使以SYSTEM权限运行也无法读取受保护的凭据
- 依赖：必须启用Hyper-V、UEFI锁、Secure Boot、VT-d/AMD-Vi

启用方式：组策略 > 计算机配置 > 管理模板 > 系统 > Device Guard > 打开基于虚拟化的安全

## DAC与MIC

### DAC（Discretionary Access Control）
- 资源所有者可以自行决定谁可以访问资源
- 通过安全描述符中的DACL（Discretionary ACL）实现
- DACL由ACE（Access Control Entry）组成，每条ACE允许或拒绝特定用户/组的访问

### MIC（Mandatory Integrity Control）
- Windows Vista引入，基于完整性级别（Integrity Level）的强制访问控制
- 完整性级别：System > High（管理员）> Medium（普通用户）> Low（IE保护模式）> Untrusted
- 进程不能写入完整性级别更高的对象（无Write-Up权限）

## UAC（User Account Control）

UAC并非传统意义上的访问控制列表机制。管理员账户默认获得两个访问令牌：
- 完整管理员令牌（Administrator Approval Mode）
- 过滤管理员令牌（标准用户权限）

默认情况下，进程使用过滤令牌运行。需要管理员权限时，触发consent.exe弹窗，用户确认后使用完整令牌。

UAC工作流程：
```
用户登录（管理员组成员）
  ├─ 过滤令牌（标准用户权限）→ 运行explorer.exe
  └─ 完整令牌（管理员权限）→ 需要提升时使用
  
触发提升：
  - 执行标记为requireAdministrator的程序
  - 修改系统设置
  - UAC滑块级别决定提示行为
```

## 安全策略配置

### 密码策略
| 策略 | 推荐值 | 说明 |
|------|--------|------|
| 密码历史 | 24个 | 禁止重复使用最近24个密码 |
| 最长密码期限 | 60-90天 | 超出后强制更改 |
| 最短密码长度 | 12+字符 | NIST SP 800-63B建议 |
| 密码复杂性 | 启用 | 满足大写、小写、数字、特殊字符中3/4 |

### 账户锁定策略
| 策略 | 推荐值 |
|------|--------|
| 锁定阈值 | 5次无效登录 |
| 锁定时间 | 15-30分钟 |
| 重置计数器 | 15分钟 |

### 审计策略
Windows审计策略分为传统审计（Security Log）和高级审计策略：
- 登录事件：成功/失败均审计
- 对象访问：关键目录和注册表路径
- 特权使用：敏感特权调用审计
- 进程创建：命令行参数记录（4688事件）

审计日志位置：`%SystemRoot%\System32\winevt\Logs\Security.evtx`

## 相关攻击技术

- **Kerberoasting**：请求服务票据并离线破解服务账号密码
- **AS-REP Roasting**：对未启用Kerberos预认证的用户发起离线破解
- **DCSync**：通过MS-DRSR协议复制域控制器上的凭据数据
- **Silver Ticket**：伪造服务票据（使用服务账号NTLM哈希签名）
- **Golden Ticket**：伪造TGT票据（使用KRBTGT哈希签名）
- **Pass-the-Hash**：使用NTLM哈希直接认证，无需明文密码

## 参考

- Microsoft Docs: Windows Security Model
- MSDN: Security Reference Monitor
- MITRE ATT&CK: T1550.002 (Pass the Hash), T1558.003 (Kerberoasting)
