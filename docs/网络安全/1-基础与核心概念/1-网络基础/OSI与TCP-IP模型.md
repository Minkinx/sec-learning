# OSI与TCP-IP模型

> 理解网络分层模型是网络安全的基础。OSI七层模型和TCP/IP四层模型是两种核心网络架构参考模型。

## OSI七层模型

| 层 | 名称 | 功能 | 典型协议/设备 | 安全关注点 |
|----|------|------|-------------|-----------|
| 7 | 应用层 | 用户接口与应用服务 | HTTP、FTP、SMTP、DNS | Web漏洞、DNS劫持 |
| 6 | 表示层 | 数据格式转换与加密 | SSL/TLS、JPEG、ASCII | 加密协议实现缺陷 |
| 5 | 会话层 | 会话建立与管理 | NetBIOS、RPC | 会话劫持 |
| 4 | 传输层 | 端到端可靠传输 | TCP、UDP | SYN Flood、端口扫描 |
| 3 | 网络层 | 路由与寻址 | IP、ICMP、ARP | IP欺骗、ARP欺骗 |
| 2 | 数据链路层 | 帧传输与MAC寻址 | Ethernet、PPP、VLAN | MAC欺骗、VLAN跳跃 |
| 1 | 物理层 | 物理信号传输 | 网线、光纤、Hub | 物理窃听、线路截获 |

## TCP/IP四层模型

- **应用层**：对应OSI的5-7层，包含HTTP、DNS、SSH等
- **传输层**：TCP（面向连接可靠传输）、UDP（无连接快速传输）
- **网络层**：IP协议负责路由寻址，ICMP用于诊断
- **网络接口层**：对应OSI的1-2层，处理物理帧

## 安全映射关系

- 每层都有对应的安全威胁和防护手段
- 分层防御（Defense in Depth）正是利用这种层次结构，在每层部署安全控制
- 理解分层模型有助于定位攻击面和分析攻击路径

## 参考

- RFC 1122: Requirements for Internet Hosts
- ISO/IEC 7498-1: OSI Reference Model
