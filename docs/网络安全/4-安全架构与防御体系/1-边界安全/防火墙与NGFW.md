# 防火墙与NGFW

> 防火墙是网络安全的第一道防线。从早期的包过滤防火墙到新一代防火墙（NGFW），其功能不断演进，应用识别、用户识别、SSL解密等功能已成为企业边界安全的标准配置。

## 防火墙基础分类

### Stateless vs Stateful

| 特性 | Stateless（无状态） | Stateful（有状态） |
|------|-------------------|-------------------|
| 检测粒度 | 仅检测数据包头部（源IP、目的IP、端口、协议） | 跟踪连接状态，识别会话上下文 |
| 性能 | 更快，无需维护连接表 | 消耗更多内存和CPU维护状态表 |
| 安全能力 | 无法判断返回流量是否合法 | 自动允许合法会话的返回流量 |
| 应用层识别 | 不支持 | 支持有限的应用层检测 |
| 适用场景 | 路由器ACL、高速骨干网 | 企业边界、数据中心出口 |

Stateless防火墙的规则示例：允许特定源IP访问特定目标端口，但不关心该流量是否属于已建立的合法连接。Stateful防火墙则维护一个连接跟踪表，记录每个会话的源/目的IP、端口、序列号等信息，只有属于已建立连接的返回流量才会被允许通过。

### iptables/nftables 规则示例

```bash
# 设置默认策略为DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 允许已建立连接的返回流量
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 允许SSH（端口22）入站
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 允许HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 允许本地回环
iptables -A INPUT -i lo -j ACCEPT

# 拒绝所有其他流量并记录日志
iptables -A INPUT -j LOG --log-prefix "DROP: " --log-level 4
iptables -A INPUT -j DROP
```

nftables（iptables的下一代替代）示例：

```bash
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    tcp dport {22,80,443} accept
    ip saddr 10.0.0.0/8 accept
    log prefix "DROP: "
    counter drop
  }
}
```

## NGFW 关键能力

### Deep Packet Inspection（DPI）

DPI不仅检查数据包头部，还深入分析应用层负载内容。NGFW通过DPI能够识别和阻断隐藏在HTTP/HTTPS隧道中的恶意流量，即使其端口不是标准端口。

### Application-ID

应用识别技术通过多种指纹特征（签名、行为分析、SSL证书信息、HELLO消息特征）识别应用，不依赖端口号。例如Skype为了穿越防火墙，可能使用80端口，但NGFW可以通过检测Skype协议握手特征来识别：

| 应用 | 可能使用的端口 | NGFW识别方式 |
|------|--------------|-------------|
| Skype | 80, 443, 随机端口 | 检测Skype协议的特定握手和加密特征 |
| BitTorrent | 随机端口 | 检测BitTorrent协议特征和DHT流量 |
| Teams/Zoom | 443, 3478-3481 | SNI分析 + 媒体流特征检测 |
| SSH隧道 | 任何端口 | 协议指纹识别（SSH banner + KEX特征） |

### User-ID

将网络流量映射到具体用户身份，通常通过以下方式集成：

- LDAP/AD：同步用户和组织结构信息
- 终端代理：在终端设备上安装Agent，关联用户登录信息
- Captive Portal：未认证用户通过Web页面登录
- Exchange/ISA Server：监听Exchange服务器的MAPI流量获取用户名

```python
# Palo Alto NGFW User-ID API示例
import requests

headers = {
    'Content-Type': 'application/xml',
}

# 通过XML API注册用户IP映射
xml_payload = '''
<uid-message>
  <type>update</type>
  <payload>
    <login>
      <entry name="zhangsan" ip="10.0.1.50" timeout="0"/>
    </login>
  </payload>
</uid-message>
'''
resp = requests.post(
    'https://firewall.example.com/api/?type=user-id&key=YOUR_API_KEY',
    data=xml_payload, headers=headers
)
```

### SSL Decryption

NGFW通过中间人（MITM）代理方式解密SSL/TLS流量，以便进行内容检测：

1. NGFW拦截客户端发起的SSL ClientHello
2. NGFW作为中间人与服务器建立SSL连接
3. NGFW用自签名证书（或企业CA签发的证书）与客户端建立另一个SSL连接
4. 解密后的明文流量经安全策略检查后重新加密发送

```nginx
# Nginx作为反向代理进行SSL终结的配置示意
server {
    listen 443 ssl;
    server_name app.internal.com;

    ssl_certificate /etc/nginx/certs/internal-ca.crt;
    ssl_certificate_key /etc/nginx/certs/internal-ca.key;

    # 后端应用使用自签名证书，内部转发
    location / {
        proxy_pass https://10.0.1.10:8443;
        proxy_ssl_verify off;
    }
}
```

## 防火墙策略设计原则

| 原则 | 说明 | 示例 |
|------|------|------|
| 最小权限（Least Privilege） | 仅开放必要的端口和协议 | 只允许特定源访问特定目标，而非整个子网 |
| 默认拒绝（Default Deny） | 未明确允许的流量一律拒绝 | 规则末尾添加隐式拒绝规则 |
| 规则顺序优化 | 防火墙按顺序匹配，通用规则置后 | 先放行常用业务流量，后放行管理流量 |
| 避免Any/Any | 尽量避免全开放规则 | 明确指定源、目标、端口、时间 |
| 定期清理 | 删除冗余和Shadow规则 | 每季度使用工具分析规则集 |

### 规则冲突类型

- **Shadow规则**：一条规则被后续规则完全覆盖，永远无法命中
- **冗余规则**：多条规则允许相同流量，造成管理混乱
- **缺口规则**：规则之间存在间隙，意料之外的流量可能通过

```bash
# 使用 fwanalyzer 进行规则集分析（开源工具）
fwanalyzer -i iptables-save.txt -o report.html -c config.yaml
```

## 防火墙高可用架构

### Active/Active vs Active/Passive

| 模式 | 描述 | 优缺点 |
|------|------|--------|
| Active/Active | 两台防火墙同时处理流量，共享会话状态 | 利用率高，但需处理非对称路由问题 |
| Active/Passive | 主设备处理流量，备设备待命 | 配置简单，故障切换明确，但备机资源闲置 |

### 非对称路由问题

在Active/Active模式下，入站流量可能经过Firewall-A，而出站流量经过Firewall-B。如果两台防火墙之间没有同步会话状态，出站流量会被Firewall-B丢弃。解决方案包括：

1. **会话同步（Session Sync）**：防火墙间通过专用链路同步状态表
2. **PBR（策略路由）**：确保往返流量经过同一防火墙
3. **Clustering**：虚拟化多台防火墙为单一逻辑实体

## 下一代防火墙的演进方向

### 云防火墙（Cloud Firewall）

| 云平台 | 原生防火墙产品 | 特点 |
|--------|---------------|------|
| AWS | Security Group + Network ACL | SG为实例级状态防火墙，NACL为子网级无状态防火墙 |
| Azure | NSG + Azure Firewall | NSG为分布式状态防火墙，Azure Firewall为托管NGFW服务 |
| GCP | VPC Firewall Rules + Cloud Armor | VPC防火墙为分布式状态规则，Cloud Armor提供WAF/DDoS能力 |

### FWaaS（防火墙即服务）

- **Zscaler Internet Access（ZIA）**：云原生安全Web网关，用户流量经过Zscaler云，无需回传数据中心
- **Palo Alto Prisma Access**：基于云的NGFW，SASE架构
- **Check Point CloudGuard**：统一管理云环境与本地防火墙策略

## 总结

防火墙技术从简单的包过滤到NGFW再到云防火墙（FWaaS），始终是网络安全架构的核心组件。合理设计防火墙策略、选择合适的高可用架构、充分利用NGFW的应用识别和SSL解密能力，是构建纵深防御体系的基础。
