# 入侵检测IDS-IPS

## 概述

入侵检测系统（IDS）和入侵防御系统（IPS）是网络安全纵深防御的关键组件。IDS 监测网络流量并告警，但不会阻断流量；IPS 则位于网络路径中，能够实时阻断检测到的攻击。

## IDS vs IPS 对比

| 特性 | IDS | IPS |
|------|-----|-----|
| 部署模式 | 旁路 (Passive/Tap) | 串联 (Inline) |
| 流量影响 | 无影响 | 可能增加延迟 |
| 阻断能力 | 无 | 支持主动阻断 |
| 单点故障风险 | 低 | 存在 |
| 加密流量处理 | 挑战大 | 通过 SSL 解密能力 |
| 误报影响 | 告警干扰 | 可能阻断正常业务 |
| 典型场景 | 合规审计、威胁监测 | 边界防御、零日防护 |

## 检测方法

### 签名检测 vs 异常检测

| 维度 | 签名检测 | 异常检测 |
|------|---------|---------|
| 原理 | 规则匹配已知攻击模式 | 统计基线偏离检测 |
| 误报率 | 低 | 中-高 |
| 漏报率 | 对未知攻击高 | 对未知攻击低 |
| 维护成本 | 需要持续更新签名库 | 需要建立基线 |
| 部署复杂度 | 低 | 高 |
| 检测能力 | 已知攻击 | 已知+未知攻击 |

### 混合检测架构

现代 NIDS/NIPS 通常采用多层检测引擎组合：

```
网络流量
  ├─→ Layer 1: 快速签名匹配 (Snort/Suricata 规则)
  │      匹配则 → 进行 Layer 2 深度检查
  │      不匹配 → 继续监控
  │
  ├─→ Layer 2: 协议解码与状态分析
  │      HTTP/DNS/SMB 协议解析
  │      TCP 流重组
  │      SSL/TLS 证书检查
  │
  ├─→ Layer 3: 文件提取与沙箱检测
  │      提取网络传输的文件
  │      YARA 规则扫描
  │      发送到沙箱执行
  │
  └─→ Layer 4: 行为分析与 ML 模型
      网络流量基线偏离检测
      ML 模型评分
      关联分析
```

## Snort / Suricata 规则详解

Snort 和 Suricata 使用类似的规则语法，是业界最广泛使用的开源 NIDS。

### 规则结构

```
action    proto    src_ip    src_port    direction    dst_ip    dst_port     (规则头部)
alert     tcp      $HOME_NET any        ->          $EXTERNAL_NET 80        (规则头部)
  msg:"MALWARE-CN - Evil Domain Detected";                                 (规则选项:消息)
  content:"evil.com"; flow:to_server,established;                         (规则选项:匹配内容)
  classtype:trojan-activity;                                              (规则选项:分类)
  sid:1000001; rev:1;                                                     (规则选项:SID和版本)
```

### 规则选项参考

| 选项 | 用途 | 示例 |
|------|------|------|
| content | 匹配特定字节/字符串 | content:"|00 01 00|" |
| offset/depth | 限制 content 匹配范围 | content:"GET"; offset:0; depth:3 |
| flow | 流方向匹配 | flow:to_server,established |
| pcre | 正则匹配 | pcre:"/[a-z]{10,}\.exe/i" |
| byte_test | 二进制数值检查 | byte_test:4,>,1000,0,relative |
| threshold | 告警频率限制 | threshold:type limit, count 5, seconds 60 |
| reference | 外部引用 | reference:url, attack.mitre.org/techniques/T1059/ |
| sid | 规则唯一标识 | sid:1000001 |
| rev | 规则版本号 | rev:3 |

### 检测规则示例

```snort
# 检测 PowerShell 下载执行 (IEX cradle)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
  msg:"POWERSHELL - PowerShell Download Cradle Detected";
  content:"powershell"; nocase; distance:0;
  content:"IEX"; nocase; within:100;
  content:"Net.WebClient|2e|DownloadString|28 29|"; nocase; within:500;
  pcre:"/(?:IEX|Invoke-Expression)\s*(?:\()?\s*\(New-Object\s+Net\.WebClient\)\.DownloadString/i";
  classtype:trojan-activity;
  sid:1000002; rev:2;
  reference:url,attack.mitre.org/techniques/T1059/001;
)

# 检测永恒之蓝 (EternalBlue) 攻击
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
  msg:"MALWARE - EternalBlue SMB Exploit Attempt";
  flow:to_server,established;
  content:"|00 00 00 31 ff|SMB|2e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|";
  distance:0; within:64;
  sid:1000003; rev:3;
  classtype:attempted-admin;
  reference:cve,2017-0144;
)
```

## Zeek (Bro) 网络分析框架

不同于 Snort/Suricata 的规则匹配，Zeek 是一个网络分析框架，生成结构化日志用于后续分析。

### 核心日志

| 日志文件 | 内容 | 重要字段 |
|---------|------|---------|
| conn.log | 所有网络连接记录 | proto, service, duration, orig_bytes, resp_bytes |
| http.log | HTTP 请求 | method, host, uri, user_agent, status_code |
| dns.log | DNS 查询 | query, qtype, answers, rcode |
| ssl.log | SSL/TLS 握手 | server_name, certificate, version, cipher |
| ftp.log | FTP 会话 | user, password, command, reply_code |
| smtp.log | SMTP 邮件 | from, to, subject, is_webmail |
| files.log | 文件提取 | filename, mime_type, md5, sha1, sha256 |
| notice.log | 检测到的异常事件 | note, msg, src, dst |

### Zeek 脚本示例

```zeek
# 检测 DNS 隧道 — 异常长的 DNS 查询
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > 100) {
        NOTICE([
            $note=DNS::Domain_High_Entropy,
            $msg=fmt("Suspicious long DNS query (len=%d): %s", |query|, query),
            $conn=c,
            $identifier=cat(c$id$orig_h, query)
        ]);
    }
}

# 检测 SSL 证书异常
event ssl_established(c: connection)
{
    if (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {
        local cert = c$ssl$cert_chain[0];
        
        # 检测近期签发的证书 (24小时内)
        if (cert$not_valid_before > network_time() - 86400) {
            NOTICE([
                $note=SSL::Certificate_Recently_Issued,
                $msg=fmt("Recently issued cert: %s -> %s",
                        cert$subject, cert$subject),
                $conn=c
            ]);
        }
        
        # 检测自签名证书流向内部网络
        if (cert$issuer == cert$subject &&
            Site::is_local_addr(c$id$resp_h)) {
            NOTICE([
                $note=SSL::Self_Signed_Cert,
                $conn=c
            ]);
        }
    }
}
```

## IPS 绕过技术

红队常用的 IDS/IPS 绕过方法：

| 绕过技术 | 原理 | 示例 |
|---------|------|------|
| 分片覆盖 (Fragmentation) | 将攻击 payload 分散到多个 IP 分片中 | fragroute |
| 字符编码 | 使用不同编码绕过字符串匹配 | base64, UTF-16, gzip 压缩 |
| TLS/SSL 加密 | 利用加密流量隐藏 payload | HTTPS C2, 邮件加密附件 |
| HTTP 请求分片 | 将 HTTP 请求拆分为多个 TCP 包 | Slow HTTP POST, chunked encoding |
| 多态/变形代码 | 每次执行都改变代码形态 | Metamorphic payloads |
| 协议混淆 | 使用非标准协议交互 | ICMP/DNS 隧道 |
| 大小写混淆 | 利用规则对大小写敏感特性 | "powershell" → "PowersHell" |

## 部署位置建议

```
Internet ──→ 防火墙 ──→ IPS(串联) ──→ 核心交换机 ──→ IDS(旁路/SPAN)
                         │                    │
                         │                [内部分段]
                     DMZ 区               ┌──────┐
                     ┌──────┐            │ EDR  │
                     │ Web  │            └──────┘
                     │ Mail │
                     └──────┘
```

| 部署位置 | 推荐方式 | 说明 |
|---------|---------|------|
| 互联网边界 | IPS 串联 | 阻断已知攻击，减少进入内网的风险 |
| DMZ 区域 | IPS 串联 | 保护对外服务，检测 Web 攻击 |
| 内网核心 | IDS 旁路 | 检测横向移动，不影响网络性能 |
| 服务器区前 | IPS 串联 | 保护关键资产（数据库、域控） |
| 云 VPC 入口 | 云 WAF + NIDS | AWS Network Firewall, Azure Firewall |
