# WAF与IDS-IPS

> Web应用防火墙（WAF）、入侵检测系统（IDS）和入侵防御系统（IPS）是应用层和网络层安全检测与防护的核心组件。本章详细介绍其工作原理、部署模式和绕过技术。

## WAF 部署模式

| 部署模式 | 工作原理 | 优缺点 |
|---------|---------|--------|
| 反向代理 | WAF作为反向代理位于用户和后端服务器之间，用户直接访问WAF | 隐藏后端服务器真实IP，支持SSL卸载，但需修改DNS |
| 透明桥接 | WAF以透明模式串联在网络中，不修改网络拓扑 | 无需修改网络配置，但对性能要求较高 |
| 云WAF | DNS解析指向云WAF，流量经过云清洗 | 部署快速，全球分布式节点，抗DDoS |
| 旁路（镜像） | 通过端口镜像/SPAN获取流量副本进行分析 | 仅检测不阻断，适用于合规监控 |

### ModSecurity + OWASP Core Rule Set（CRS）

ModSecurity是最流行的开源WAF引擎，配合OWASP CRS规则集提供Web应用防护能力。

**OWASP CRS规则分类**：

| 规则类别 | 编号范围 | 描述 | 示例 |
|---------|---------|------|------|
| 协议强制 | 920xxx | HTTP协议合规性检查 | 检测HTTP方法白名单、请求头格式 |
| 文件包含 | 930xxx | 本地/远程文件包含防护 | `../`、`file://` 等路径遍历 |
| XSS | 941xxx | 跨站脚本攻击检测 | `<script>`、`onerror=` 事件 |
| SQL注入 | 942xxx | SQL注入攻击检测 | `' OR 1=1--`、`UNION SELECT` |
| 远程执行 | 944xxx | 远程代码执行防护 | `cmd.exe`、`/bin/bash` |
| RFI | 951xxx | 远程文件包含防护 | `include(http://evil.com)` |

**CRS Paranoia Levels（偏执级别）**：

| 级别 | 说明 | 误报率 |
|------|------|--------|
| PL1 | 默认级别，较低的误报率，覆盖常见攻击 | 低 |
| PL2 | 增加更严格的规则，减少误报 | 中 |
| PL3 | 大幅增加检测规则，对协议检查非常严格 | 高 |
| PL4 | 最高级别，几乎不信任任何输入 | 极高 |

```apache
# ModSecurity启用OWASP CRS配置示例
<IfModule mod_security2.c>
    # 启用ModSecurity引擎
    SecRuleEngine On
    
    # 请求体限制
    SecRequestBodyLimit 10485760
    SecRequestBodyNoFilesLimit 1048576
    
    # 加载CRS规则
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/rules/*.conf
    
    # 设置偏执级别为PL2
    SecAction \
        "id:900000,\
         phase:1,\
         nolog,\
         pass,\
         t:none,\
         setvar:tx.block_paranoia_level=2"
    
    # 开启异常评分模式
    SecAction \
        "id:900001,\
         phase:1,\
         nolog,\
         pass,\
         t:none,\
         setvar:tx.anomaly_score_blocking=on"
</IfModule>
```

## WAF绕过技术

### HTTP参数污染（HPP）

通过在请求中重复发送同名参数，绕过WAF的单参数检查逻辑：

```
# 正常请求
?id=1 UNION SELECT * FROM users

# HPP绕过
?id=1&id=2' UNION SELECT * FROM users--+
# WAF检测第二个参数为安全值，但后端可能拼接所有参数或取最后一个参数值
```

### 编码绕过

```python
# 双重URL编码示例
# 原始Payload: ' OR '1'='1
# 单编码:  %27%20OR%20%271%27%3D%271
# 双编码绕过: %25%32%37%25%32%30%25%34%46%25%35%32...（多层编码）

# Unicode绕过
# '/' 的Unicode变体:
# - %c0%af (过长的UTF-8编码)
# - %e0%80%af (超长UTF-8编码)
# 旧版WAF可能无法正确解码，而后端服务器（如IIS）却接受这些变体
```

### Chunked Transfer Encoding Smuggling

利用分块传输编码绕过来检测请求体的WAF：

```
POST /login HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 45  # 混淆WAF的Content-Length检查

0

POST /admin HTTP/1.1
Host: target.com
```

### HTTP/0.9降级

```
# HTTP/0.9不支持请求头，只有请求行
GET /../../etc/passwd
# 一些WAF对HTTP/0.9的支持不完善，不解析路径
```

### 请求大小限制绕过

通过制造超出WAF缓冲区大小的请求，使WAF截断检查而实际Payload在后半部分：

```
# 发送一个非常大的请求体（超过WAF的Request Body Limit）
# WAF检查前N字节后放行，但后端完整接收整个请求
GET /search?q=A<填充大量无用数据>UNION SELECT * FROM users
```

## IDS vs IPS

| 特性 | IDS（入侵检测系统） | IPS（入侵防御系统） |
|------|-------------------|-------------------|
| 部署方式 | 旁路（镜像端口），被动监听 | 串联（Inline），在线阻断 |
| 动作 | 告警、日志记录 | 实时阻断、重置连接、限速 |
| 延迟 | 零延迟（不影响网络） | 增加少量延迟（毫秒级） |
| 风险 | 无断网风险 | 误报可能导致正常业务中断 |
| 典型产品 | Snort（仅检测模式）、Suricata | Palo Alto IPS、Cisco Firepower |

### IPS部署架构

```
[互联网] --- [IPS呈Inline模式] --- [核心交换机] --- [内部网络]
                          |
                    [管理控制台]
```

**NIPS（Network-based IPS）**：部署在网络关键节点之间，例如：

- 数据中心出口（南北向流量检测）
- 核心交换机之间（东西向流量检测）
- VLAN间的流量通道

**HIPS（Host-based IPS）**：部署在终端上：

- 系统调用拦截（根据策略允许/阻止系统调用）
- 文件系统保护（防止未授权的文件修改）
- 注册表保护（Windows系统关键注册表项）

## 检测逃逸技术

### IP分片

将恶意Payload分散到多个IP分片中，使IPS无法重组完整Payload：

```python
# Scapy发送分片数据包示例
from scapy.all import *
ip = IP(src="10.0.0.1", dst="10.0.0.2")
# 将Payload分成两个分片
frag1 = ip / b"A" * 8  # 第一个分片包含无害数据
frag2 = IP(src="10.0.0.1", dst="10.0.0.2", frag=1, flags="MF") / b"UNION SELECT * FROM users"
```

### TTL操纵

通过精心设置TTL值，使IPS看到的分片与目标主机重组的分片不同：

```
分片1: TTL=64, Offset=0, Payload="<scri"
分片2: TTL=1, Offset=12, Payload="pt>alert(1)</script>"
# 分片2在到达目标前TTL耗尽（由于TTL=1），但分片1到达目标
# IPS看到完整的<script>标签，而目标主机只收到不完整的片段
```

### SSL/TLS Evasion

攻击者利用SSL加密隧道传输恶意流量，绕过传统的IPS检测：

```
[攻击者] ===SSL加密=== [IPS（无法解密）] ===SSL加密=== [目标服务器]
```

解决方案：IPS需要SSL解密能力（与NGFW类似），在串联位置进行SSL卸载和重新加密。

## Snort/Suricata规则示例

```snort
# SQL注入检测规则
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SQL Injection - UNION SELECT Detected";
    flow:to_server,established;
    content:"UNION"; nocase;
    content:"SELECT"; within:20; nocase;
    pcre:"/UNION\s+ALL?\s+SELECT/smi";
    classtype:web-application-attack;
    sid:1000001; rev:1;
)

# XSS检测规则
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"Cross-Site Scripting - script tag";
    flow:to_server,established;
    content:"<script"; nocase;
    pcre:"/<\s*script[^>]*>/smi";
    classtype:web-application-attack;
    sid:1000002; rev:1;
)
```

## 总结

WAF保护Web应用层，IDS/IPS保护网络层和传输层。实践中应该将三者协同部署：IPS串接在网络入口进行实时阻断，WAF在应用层精细化防护Web服务，IDS旁路部署提供全面的威胁监控。再结合威胁情报源（如AlienVault OTX、MISP），形成完整的检测与防护体系。
