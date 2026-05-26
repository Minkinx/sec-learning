# DDoS防护

> 分布式拒绝服务攻击（DDoS）通过大量僵尸主机向目标发送海量流量，耗尽目标带宽或系统资源。根据攻击层次不同，DDoS可分为L3/L4流量型攻击和L7应用层攻击。

## DDoS攻击分类

### Layer 3/4 流量型攻击

**SYN Flood**

攻击原理：向目标发送大量伪造源IP的SYN包，目标服务器为每个SYN包分配TCB（传输控制块）并回复SYN-ACK，等待ACK超时。大量半开连接耗尽服务器连接表。

```
攻击者 -> 伪造源IP -> 目标: SYN
目标 -> 伪造源IP（不存在）: SYN-ACK（无法收到ACK）
目标系统资源: 半开连接队列（backlog queue）被填满
正常用户 -> 目标: SYN（被拒绝，无法建立连接）
```

**UDP Amplification（UDP放大攻击）**

利用UDP无连接验证的特性，结合放大因子大的协议：

| 协议 | 请求大小 | 响应大小 | 放大因子 | 说明 |
|------|---------|---------|---------|------|
| NTP | 约50字节 | 约5400字节 | 50-100x | monlist命令返回最近NTP客户端列表 |
| DNS | 约60字节 | 约4000字节 | 50-70x | ANY类型的DNS递归查询 |
| SSDP | 约30字节 | 约7500字节 | 10-250x | UPnP设备请求 |
| Memcached | 约15字节 | 约1MB | 5-7万x | 未授权访问的Memcached服务器 |
| CLDAP | 约40字节 | 约7000字节 | 10-175x | Connection-less LDAP |

```bash
# 检查当前系统是否参与UDP放大攻击
# 查看NTP服务是否暴露
netstat -an | grep ":123 "
# 关闭NTP monlist（NTP版本4.2.7p26以上默认关闭）
restrict default kod nomodify notrap nopeer noquery
```

**ICMP Flood**

通过发送大量ICMP Echo请求（Ping），消耗目标带宽和处理能力。

**ICMP Smurf Attack**

向广播地址发送源IP伪造成目标的ICMP Echo请求，网络内所有主机同时回复目标，产生放大效果。

### Layer 7 应用层攻击

**HTTP Flood**

| 类型 | 描述 | 检测难度 |
|------|------|---------|
| GET Flood | 大量GET请求，模拟正常页面访问 | 低（高并发+识别请求URL规律） |
| POST Flood | 大量POST请求，消耗应用处理能力 | 中（需要识别参数随机性） |
| Slow GET | 慢速发送HTTP请求头，保持TCP连接 | 高（请求看起来正常，只是速度慢） |
| Cache Bypass | 请求随机URL或加随机参数绕过CDN缓存 | 中（命中静态资源缓存可缓解） |

**Slowloris**

攻击原理：以极慢的速度发送HTTP请求头部，每个请求头部行之间间隔很长时间，让Web服务器维持大量半开HTTP连接，耗尽连接池。

```
GET / HTTP/1.1\r\n
Host: target.com\r\n
User-Agent: Mozilla/5.0\r\n
（等待5秒）
Accept: text/html\r\n
（等待5秒）
...
（永不发送最后的\r\n\r\n）
```

**RUDY（R-U-Dead-Yet?）**

Slowloris的变种，缓慢发送POST请求的Body部分：

```
POST /login HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 1000000\r\n
\r\n
username=admin&password=test（后续数据以极慢速度发送）
```

**WordPress Pingback反射攻击**

利用WordPress的XML-RPC pingback功能，将攻击流量反射到目标：

```
POST /xmlrpc.php HTTP/1.1
Host: wordpress-site.com
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value>http://攻击目标/xxx</value></param>
    <param><value>http://wordpress-site.com/合法文章</value></param>
  </params>
</methodCall>
```

## DDoS缓解技术

### Anycast分布

Anycast路由将相同IP地址通告到全球多个数据中心，根据BGP路由协议将用户导向最近的数据中心，天然分散攻击流量：

```
[DDoS攻击流量]
  |              |              |
 [Tokyo DC]   [London DC]    [NY DC]
（每个DC承担三分之一的攻击流量，通过BGP路由散）
```

**应用Anycast的产品**：

- **Cloudflare**：全球200+数据中心，Anycast网络自动分散流量
- **Akamai**：大型边缘网络，Prolexic DDoS防护服务
- **AWS Shield**：全球Anycast基础设施

### 流量清洗（Traffic Scrubbing）

Scrubbing Center是专门的DDoS清洗设施：

1. 正常流量通过BGP路由（或DNS）引流到Scrubbing Center
2. 分析流量特征，区分攻击流量和正常流量
3. 清洗后的干净流量通过隧道转发回源站

```python
# 示例：基于NetFlow的DDoS检测和BGP触发引流
def check_ddos_threshold(flow_data):
    """
    flow_data: dict of {src_ip: packet_count}
    如果单个IP的流量超过阈值，触发BGP RTBH（Remotely Triggered Black Hole）
    """
    threshold = 1000000  # 每秒1M包
    for src_ip, count in flow_data.items():
        if count > threshold:
            # 触发BGP blackhole
            bgp_blackhole(f"192.0.2.1", src_ip)
            alert(f"DDoS mitigation triggered for source: {src_ip}")

def alert(message):
    print(f"[ALERT] {message}")
    # 发送到SIEM或SOC
```

### 速率限制（Rate Limiting）

**Nginx速率限制配置**：

```nginx
# 定义限速区域
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# 应用限速
server {
    location /api/ {
        # 每个IP每秒最多5个请求，突发允许10个
        limit_req zone=login_limit burst=10 nodelay;
        
        # 最大并发连接数
        limit_conn addr 10;
        
        # 延迟响应（慢速攻击缓解）
        limit_rate 1024k;
        
        proxy_pass http://backend;
    }
}
```

**iptables连接限制**：

```bash
# 限制每个IP的并发SYN连接数
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j DROP

# SYN Flood保护
iptables -A INPUT -p tcp --syn -m limit --limit 200/s --limit-burst 500 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

### TCP SYN Cookie

SYN Cookie是操作系统内核级的SYN Flood缓解机制，在半开连接队列满时自动启用：

```bash
# Linux启用SYN Cookie（默认开启）
sysctl -w net.ipv4.tcp_syncookies=1

# 调整SYN-ACK重试次数
sysctl -w net.ipv4.tcp_synack_retries=2

# 调整半开连接队列大小
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

### Sinkholing（黑洞路由）

将攻击流量引导至不存在的目标地址（Null0），使其在网络中丢弃：

```bash
# Cisco路由器配置黑洞路由
ip route 192.0.2.10 255.255.255.255 Null0
ip route 10.0.0.0 255.0.0.0 Null0

# RTBH（Remotely Triggered Black Hole）：
# 触发条件达到时，自动注入到BGP
route-map RTBH permit 10
  match ip address DDoS_TRIGGER
  set ip next-hop 192.0.2.1  # 指向Null0
```

**DNS Sinkhole**：在DNS层面将已知恶意域名的解析指向黑洞IP，阻止客户端与C2通信。

## 流量分析与检测

### NetFlow/IPFIX/sFlow

```bash
# 使用nfacctd（pmacct项目）收集NetFlow数据
# 配置示例（/etc/pmacct/pmacctd.conf）：
daemonize: true
pidfile: /var/run/pmacctd.pid
interface: eth0
aggregate: src_host, dst_host, proto, src_port, dst_port
plugins: print, mysql

# 使用flowtop实时查看流量（ntop工具）
flowtop
```

### 基线检测与异常告警

```python
# 简化的DDoS异常检测逻辑
import statistics
from collections import defaultdict

traffic_baseline = {
    'avg_packets_per_sec': 5000,
    'std_packets_per_sec': 1000,
    'avg_connections_per_sec': 200,
}

def detect_anomaly(current_packets_per_sec, current_connections_per_sec):
    """基于3-sigma法则检测异常"""
    pkt_threshold = traffic_baseline['avg_packets_per_sec'] + 3 * traffic_baseline['std_packets_per_sec']
    
    alerts = []
    if current_packets_per_sec > pkt_threshold:
        alerts.append(f"流量异常：当前包速率 {current_packets_per_sec}/s，阈值 {pkt_threshold}/s")
    
    conn_ratio = current_connections_per_sec / traffic_baseline['avg_connections_per_sec']
    if conn_ratio > 10:
        alerts.append(f"新建连接数异常：当前 {current_connections_per_sec}/s，基线 {traffic_baseline['avg_connections_per_sec']}/s")
    
    return alerts
```

## 云环境DDoS防护

| 云平台 | 免费防护 | 付费增强 | 功能 |
|--------|---------|---------|------|
| AWS Shield | Standard（自动包含） | Advanced（3000美元/月） | 自动L3/L4缓解，Advanced提供DDoS响应团队 |
| Azure DDoS | Basic（自动包含） | Standard（按资源计费） | 自动基线调整，L7缓解，审计日志 |
| GCP Cloud Armor | 基本L3/L4防护 | Managed Protection Plus | WAF+DDoS，自定义规则，速率限制 |

## 总结

DDoS防护需要多层协作：网络层依靠Anycast分布式架构进行流量分散，Scrubbing Center进行流量清洗；应用层依靠速率限制、WAF和反向代理进行精细控制；检测层通过NetFlow/sFlow进行流量基线分析和大数据异常检测。没有任何单一技术可以完全防御DDoS，纵深防御和云结合是当前最佳实践。
