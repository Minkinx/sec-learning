# BGP与路由安全

> BGP（边界网关协议）是互联网的核心路由协议，负责在自治系统（AS）之间交换路由信息。然而，BGP的设计基于AS间的信任模型，缺乏内建的安全验证机制，导致路由劫持和路由泄露事件频发。

## BGP基础

### BGP工作机制

BGP是一种路径向量协议（Path Vector Protocol），主要运行在互联网的AS（自治系统）之间：

```
AS 65001 ──── AS 65002 ──── AS 65003
     │            │            │
  网络A         网络B         网络C

路由通告示例：
AS 65003 通告 203.0.113.0/24
  ↓
AS 65002 收到后添加自己的AS号 → 转发路由：203.0.113.0/24 via AS 65003
  ↓
AS 65001 收到后添加自己的AS号 → 路由：203.0.113.0/24 via AS 65002, AS 65003
```

**路径选择要素**：
1. 最高本地优先级（Local Preference）
2. 最短AS路径长度
3. 最低MED（多出口区分符）
4. eBGP优于iBGP（路径类型）
5. 最低IGP度量到下一跳
6. 最低路由器ID

### BGP的安全缺陷

BGP的核心问题：**没有机制验证路由通告的合法性**。

| 缺陷 | 说明 | 影响 |
|------|------|------|
| 无源验证 | 无法确认通告者是否是前缀的真正所有者 | 任意AS可声明任意IP前缀 |
| 无路径验证 | 无法确认AS_PATH是否真实 | 可伪造/篡改路径 |
| 无完整性保护 | TCP连接可被伪造BGP消息篡改 | 路由毒化、会话重置 |

## BGP攻击/事件

### 路由劫持（Route Hijacking）

攻击者通告不属于自己的IP前缀，吸引流量经过自己的网络。

| 事件 | 年份 | 详情 | 影响 |
|------|------|------|------|
| **YouTube劫持** | 2008 | 巴基斯坦电信错误通告YouTube的IP前缀（/22 → /24更具体），全球BGP优选更具体路由导致YouTube中断约2小时 | 全球YouTube流量经巴基斯坦路由 |
| **MyEtherWallet劫持** | 2018 | 攻击者通过BGP劫持DNS解析路由到AWS Route53，安装Let's Encrypt证书 | 约17万美元加密货币被盗 |
| **亚马逊DNS劫持** | 2018 | 攻击者劫持亚马逊DNS服务器的IP前缀，重定向myetherwallet.com流量 | 估计约17万美金被盗 |
| **Facebook中断** | 2021 | BGP路由撤回导致所有DNS和公共可达服务中断约6小时（非恶意，系配置错误） | 全球性中断，损失约$100M营收 |
| **CRYSTALROUTER** | 2017-2024 | APT组织针对全球骨干网络的路由基础设施攻击 | DNS重定向、流量监听 |

### 路由泄露（Route Leak）

合法的路由被错误地传播到不应接收的网络：

```
场景：一个多宿主的AS将eBGP学习的路由通过另一个eBGP邻居传播出去
  
正常路径：
  上游A ← 客户AS → 上游B
  客户从上游A和上游B安装默认路由

泄露情况：
  客户将自己的默认路由（从上游A学习到）传递给上游B
  → 上游B认为通过客户AS可到达上游A的客户
  → 造成路由路径次优化甚至环路

影响：流量经过更长的路径，性能下降；可引发中间人攻击
```

### BGP流量拦截（Traffic Interception）

```
攻击者合法或非法获得IP前缀所有权后：
1. 通告该前缀（或更具体子网）
2. 周边AS优选更具体或更短路径的路由
3. 流量被重定向至攻击者的网络
4. 攻击者可：监听流量、修改内容、注入恶意代码
5. 流量可以转发回原始目的地（不造成服务中断，难以发现）
```

## RPKI（资源公钥基础设施）

RPKI通过密码学方式将IP前缀与合法的AS号关联起来，防止路由劫持。

### 核心概念

| 组件 | 作用 | 说明 |
|------|------|------|
| **ROA**（Route Origin Authorization） | 授权声明 | 特定的AS（Origin AS）有权通告特定的IP前缀 |
| **RIR**（区域互联网注册机构） | 证书签发 | ARIN/RIPE/APNIC/LACNIC/AfriNIC签发资源证书 |
| **RPKI Validator** | 验证服务 | 下载并验证RPKI数据，输出有效/无效/未知状态 |

### ROA配置示例
```
AS65001 拥有 203.0.113.0/24 前缀
ROA声明：
  前缀：203.0.113.0/24
  来源AS：AS65001
  最大前缀长度：/24

当另一个AS AS65002 通告 203.0.113.0/24 时：
  - RPKI验证：来源AS = AS65002 ≠ ROA中声明的AS65001
  - 结果：INVALID → 路由器应拒绝该路由
```

### RPKI部署状态（截至2024年）
- 全球约50%的路由表条目有ROA覆盖
- 约40%的运营商配置了RPKI验证
- APNIC（亚太）、RIPE NCC（欧洲）部署率较高
- 实际过滤INVALID路由的比例较低（许多运营商仅做监控不强制过滤）

## BGP安全最佳实践

### 1. 前缀过滤（Prefix Filtering）

```bash
# Cisco路由器 eBGP入站过滤示例
ip prefix-list ALLOWED-PREFIXES seq 5 permit 203.0.113.0/24
ip prefix-list ALLOWED-PREFIXES seq 10 permit 198.51.100.0/24

route-map FROM-CUSTOMER permit 10
  match ip address prefix-list ALLOWED-PREFIXES
  set local-preference 120

neighbor 10.0.0.1 route-map FROM-CUSTOMER in
# 阻止未经授权的前缀进入路由表
```

- 每个eBGP对等方应定义允许的前缀列表
- 客户只应通告自己的前缀
- 上游应验证客户的前缀所有权

### 2. TTL安全（GTSM）

Generalized TTL Security Mechanism（RFC 5082）：
```
原理：eBGP对等方通常直连（TTL=1）
如果BGP报文来自非直连的IP（TTL > 1），一定是伪造的

配置：
neighbor 10.0.0.1 ttl-security hops 1
# 路由器丢弃TTL≠255的BGP报文（将期望TTL设为255）

防御：攻击者必须位于直连链路上才能发送伪造BGP报文
```

### 3. BGP MD5认证

```bash
# 对BGP TCP连接进行MD5签名认证
neighbor 10.0.0.1 password 0 MySecurePassword
```

- 防止TCP RST攻击和伪造BGP会话
- **局限**：MD5已知较弱（可被暴力破解）；密钥管理困难
- 建议使用更新的TCP-AO（TCP Authentication Option，RFC 5925）替代

### 4. 最大前缀限制

```bash
# 限制从对等方接收的路由数量
neighbor 10.0.0.1 maximum-prefix 1000 restart 60
# 超过1000条后断开连接，60分钟后重试

# 警惕场景：前缀数量异常增加可能是劫持信号
```

### 5. 路由监控与检测

| 工具/服务 | 功能 |
|-----------|------|
| **BGPmon** | 实时BGP更新监控，告警路由变更 |
| **Cloudflare Radar** | AS级路由可视化和异常检测 |
| **RIPE RIS** | Route Views和RIPE的路由信息收集 |
| **BGPlay** | 路由变化可视化回放 |
| **ARTEMIS** | 开源BGP劫持检测系统 |
| **Prefix Broker** | 前缀可达性监控 |

## MANRS（Mutually Agreed Norms for Routing Security）

MANRS是一个行业驱动的路由安全协作框架：

| MANRS行动 | 说明 |
|-----------|------|
| **过滤（Filtering）** | 防止路由劫持——运营商应过滤不正确的前缀通告 |
| **反欺骗（Anti-Spoofing）** | 防止源地址欺骗——实施BCP 38（入站过滤） |
| **协调（Coordination）** | 促进全球路由安全协作——维护联系人信息 |
| **全球验证（Global Validation）** | 实施RPKI——促进路由数据的密码学验证 |

**BCP 38（RFC 2827）**：网络入口过滤，阻止源地址不在预期范围内的数据包。

## 参考

- RFC 4271: BGP-4 Specification
- RFC 7454: BGP Operations and Security
- RFC 8205: BGPsec Protocol
- RFC 6811: BGP Prefix Origin Validation
- MANRS: Mutually Agreed Norms for Routing Security
- Cloudflare: BGP Hijack Detection
- Team Cymru: Bogon Reference
- NIST SP 800-189: BGP Security Best Practices
