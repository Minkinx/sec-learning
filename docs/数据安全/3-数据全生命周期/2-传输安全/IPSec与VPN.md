# IPSec 与 VPN

## 概述

IPSec 和 VPN 技术为跨网络的数据传输提供机密性和完整性保护。在企业远程办公、多云互联和分支机构连接的场景中，选择正确的 VPN 协议和配置至关重要。

## IPSec 模式对比

### Transport Mode vs Tunnel Mode

| 特性 | Transport Mode | Tunnel Mode |
|------|---------------|-------------|
| 保护范围 | 仅 payload（IP header 明文） | 整个 IP packet |
| 典型场景 | 端到端通信（Host-to-Host） | 站点到站点（Gateway-to-Gateway） |
| 新 IP 头 | 不添加 | 添加新的外层 IP header |
| 安全性 | 较低（暴露源/目的地址） | 更高（隐藏内网拓扑） |

### IPSec 协议栈

```
Application Layer
       ↓
TCP/UDP Transport
       ↓
IP Layer
  ├── AH (Authentication Header): 完整性 + 认证, 不加密
  └── ESP (Encapsulating Security Payload): 加密 + 完整性 + 认证（推荐）
       ↓
IKE (Internet Key Exchange): SA 协商 + 密钥管理
```

## IKEv1 vs IKEv2 对比

| 特性 | IKEv1 (RFC 2409) | IKEv2 (RFC 7296) |
|------|------------------|------------------|
| 交换过程 | 阶段 1 (主模式/野蛮模式) + 阶段 2 (快速模式) | 单一 IKE_SA 交换 |
| 消息数量 | 主模式 6 条 + 快速模式 3 条 | IKE_SA_INIT 2 条 + IKE_AUTH 2 条 |
| NAT 穿透 | 需额外 NAT-T 支持 | 原生支持 |
| MOBIKE | 不支持 | 原生支持（移动场景） |
| 重连速度 | 慢（需重新协商 SA） | 快（SA 恢复机制） |
| 建议 | 仅兼容存量设备 | 新部署应优先选择 |

## VPN 协议选型

| 协议 | 加密 | 速度 | 安全性 | 配置复杂度 | 适用场景 |
|------|------|------|--------|-----------|----------|
| WireGuard | ChaCha20-Poly1305 | 极快 | 高（现代密码学） | 低 | 远程访问、站点互联 |
| OpenVPN | AES-GCM/ChaCha20 | 中 | 高（配置灵活） | 中 | 通用场景 |
| IPSec/IKEv2 | AES-GCM | 中 | 高 | 高 | 站点到站点 |
| L2TP/IPSec | AES-CBC | 慢 | 中 | 中 | 兼容性需求 |
| SSTP | AES-CBC | 中 | 中 | 低 | Windows 生态 |
| PPTP | MPPE | 快 | **不安全（已破解）** | 低 | **禁止使用** |

## Site-to-Site vs Remote Access

### 站点到站点 (Site-to-Site)

```
[DC 1] ─── IPSec Tunnel ─── [DC 2]
   │                            │
[Subnet A]                  [Subnet B]
```

- 连接两个或多个网络的网关
- 通常使用 IPSec Tunnel Mode
- 支持 BGP/OSPF 动态路由
- 需配置路由策略和 failover

### 远程访问 (Remote Access)

```
[Employee Laptop] ─── VPN Tunnel ─── [VPN Concentrator] ─── [Corporate Network]
```

- 用户设备连接到企业网络
- 支持多平台客户端
- 需集成 MFA 认证

## Split Tunneling 策略

| 模式 | 说明 | 安全风险 | 适用场景 |
|------|------|----------|----------|
| Full Tunnel | 全部流量经 VPN | 低（所有流量受控） | 高安全要求 |
| Split Tunnel | 仅内网流量经 VPN | 中（可能泄露 IP） | 带宽优化 |
| Reverse Split | 仅特定流量直连 | 中 | 特定合规要求 |

**推荐实践**：默认使用 full tunnel，通过 DNS 策略实现 split tunnel 例外。

## VPN Auditing

VPN 系统需要持续审计以下方面：

1. **连接审计**：记录每次连接的时间、用户、源 IP、持续时长
2. **配置审计**：定期审查加密算法、认证方式、协议版本
3. **访问审计**：记录通过 VPN 访问的内网资源
4. **异常检测**：检测异常连接模式（多地同时登录、异常时间）
5. **合规审计**：验证是否符合企业内部安全策略

## 参考标准

- NIST SP 800-77 (IPSec Security)
- NIST SP 800-113 (SSL VPN Guidance)
- RFC 7296 (IKEv2), RFC 8446 (WireGuard Protocol)
- IETF WireGuard Protocol (RFC 8446)
