# DNS安全

> DNS是互联网的基础设施协议，但其设计之初并未充分考虑安全性。DNS欺骗、缓存投毒、DDoS放大等攻击屡见不鲜。DNSSEC、DoH/DoT等安全扩展正在逐步改善DNS安全生态。

## DNS基本概念

### DNS解析流程
```
用户输入 example.com → 浏览器
  ↓ 1. 递归查询
本地DNS缓存/递归解析器
  ↓ 2. 根域名服务器 → 返回 .com 的NS记录
  ↓ 3. TLD服务器 → 返回 example.com 的NS记录
  ↓ 4. 权威名称服务器 → 返回 A/AAAA 记录
  ↓ 5. 缓存结果并返回IP
浏览器 → IP:93.184.216.34 → 发起HTTP连接
```

## DNS攻击面

### 1. 缓存投毒（Cache Poisoning）

| 攻击类型 | 年代 | 原理 | 影响 |
|----------|------|------|------|
| Kaminsky攻击 | 2008 | 预测TXID + 大量伪造响应投毒 | 可投毒任意域名（需约2^16次尝试） |
| 生日攻击投毒 | 现代 | 同时触发多个查询，提高碰撞概率 | TXID随机化不足时有效 |
| SAD DNS | 2020 | 利用侧信道泄露端口号 | 绕过源端口随机化 |

**Kaminsky攻击的经典机制**：
```
1. 攻击者向递归解析器发送大量针对 nonexist.example.com 的查询
2. 攻击者同时发送大量伪造的DNS响应（猜测TXID）
3. 如果某伪造响应猜对TXID且先于真实响应到达：
   - 解析器接受该响应并缓存
   - 伪造的NS记录指向攻击者控制的权威服务器
4. 攻击者控制的权威服务器返回example.com的虚假IP地址
5. 所有指向example.com的流量都被重定向至攻击者服务器
```

**缓解措施**：
- 启用DNSSEC（验证响应签名，防止伪造）
- 源端口随机化（提高TXID猜测难度）
- 查询ID随机化
- 使用0x20编码（域名大小写随机化增加猜测复杂度）

### 2. DNS劫持（DNS Hijacking）

| 类型 | 范围 | 典型案例 |
|------|------|---------|
| 路由器劫持 | 局域网 | 家用路由器被恶意固件修改DNS设置 |
| 运营商劫持 | ISP层面 | 在HTTP响应中插入广告/弹窗 |
| 公共Wi-Fi劫持 | 热点 | 恶意网关重定向DNS请求 |
| 注册商劫持 | 域名级别 | 攻击者通过社会工程转移域名控制权 |

### 3. DNS DDoS放大攻击

利用DNS响应大于请求的特点进行流量放大：

```
DNS放大攻击放大系数（EDNS0支持DNSSEC时）：

攻击者（伪造受害者IP）──► 开放DNS解析器
  请求：type=ANY, size≈60字节        │
                                    ▼
                                 响应：≈4000字节（DNSSEC记录）
                                    │
                    ┌───────────────┘
                    ▼
                受害者（被伪造的IP）
                流量放大比：≈ 66倍

实际案例：
2018年GitHub遭受1.35 Tbps DDoS攻击
→ 使用Memcached放大（DNS类似，Memcached放大比可达50,000倍）
→ 实际DNS放大攻击常在数百Gbps级别
```

**防护措施**：
- 禁止递归解析器接受来自非授权源的查询（ACL白名单）
- 响应速率限制（Response Rate Limiting, RRL）
- 关闭开放解析器（Open Resolver Project：超过100万个开放解析器在线）

### 4. DNS隧道（DNS Tunneling）

利用DNS协议封装非DNS流量，用于绕过网络限制或建立隐蔽C2通道：

| 工具 | 语言 | 特性 |
|------|------|------|
| dnscat2 | Ruby + C | 命令控制通道，加密通信 |
| iodine | C | 高性能IP over DNS隧道 |
| DNSTT (dnstt) | Go | 使用TLS加密的DNS隧道 |
| Cobalt Strike | Java | 商业C2框架，支持DNS Beacon |

**检测方法**：
- 高频率异常的DNS查询
- TXT/ANY类型查询占比异常高
- 域名包含编码数据的Base64特征
- 域名长度超过正常（> 典型域名长度30字符）
- TXT记录响应数据熵值高（类似加密数据）

## DNSSEC（DNS Security Extensions）

DNSSEC通过数字签名确保DNS响应的完整性和真实性。

### DNSSEC核心资源记录

| 记录类型 | 作用 | 说明 |
|----------|------|------|
| DNSKEY | 公钥记录 | 包含区域签名密钥（ZSK）和密钥签名密钥（KSK） |
| RRSIG | 签名记录 | 为每个RRset提供数字签名 |
| DS | 委托签名者 | 父区域对子区域KSK的哈希，构建信任链 |
| NSEC/NSEC3 | 不存在证明 | 提供域名不存在的可验证证明（防止Zone Walking） |
| CDNSKEY/CDS | 自动化KSK轮换 | 子区域向父区域通告新的密钥 |

### DNSSEC信任链
```
Root Zone (root DNSKEY)
    ↓     验证 DS 记录签名（RRSIG）
.com TLD (DS → DNSKEY)
    ↓     验证 DS 记录签名（RRSIG）
example.com (DS → DNSKEY)
    ↓     验证 RRSIG
example.com A 记录
    ↓     验证
用户获得可验证的合法IP地址
```

### DNSSEC挑战
- **部署率低**：全球部署率约~30%（截至2024年），主要原因：
  - 配置复杂（密钥管理、轮换、签名算法更新）
  - 性能开销（签名验证增加解析延迟）
  - 缺乏商业驱动（用户不感知DNSSEC与普通DNS的区别）
- **复杂性**：密钥轮换、签名维护、DS记录同步需要自动化工具
- **放大攻击**：DNSSEC记录增大DNS响应（放大攻击系数更高）

## DNS安全增强协议

### DNS over HTTPS（DoH）
- RFC 8484（2018年）
- DNS查询通过HTTPS（TCP 443）传输
- 加密、伪装为普通HTTPS流量
- 缺点：绕过企业内容过滤策略
- 常用服务：Cloudflare 1.1.1.1, Google 8.8.8.8

### DNS over TLS（DoT）
- RFC 7858（2016年）
- DNS查询通过TLS（TCP 853）传输
- 使用专用端口，可被识别和过滤
- 配置示例：
```
# stubby.yml（Linux DNS隐私守护进程）
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
upstream_recursive_servers:
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
```

### 其他保护措施

| 措施 | 说明 | 实现级别 |
|------|------|---------|
| DNS Rate Limiting | 限制单源查询频率 | 递归解析器 |
| Response Policy Zone (RPZ) | 恶意域名阻止列表 | 递归解析器 |
| DNS 防火墙 | 过滤恶意域名查询 | 边界设备 |
| 0x20编码 | 随机化域名大小写提高TXID猜测难度 | 递归解析器 |
| 限制ANY查询 | 减少放大攻击向量 | 权威服务器 |

## 参考

- RFC 1034/1035: DNS Specification
- RFC 4033-4035: DNSSEC Protocol
- RFC 7858: DNS over TLS
- RFC 8484: DNS over HTTPS
- Kaminsky, D. (2008): "Black Ops 2008: It's The End Of The Cache As We Know It"
- MITRE ATT&CK: T1573 (DNS Tunneling), T1568 (DNS Hijacking)
- APNIC: DNSSEC Deployment Statistics
