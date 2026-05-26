# HIDS-Osquery-Wazuh

> 主机入侵检测系统（HIDS）通过监控主机内部的活动来检测威胁。Osquery提供基于SQL的端点可观察性，Wazuh则是一个开源的安全监控平台。本文将详细介绍两者的功能、配置和集成方案。

## Osquery：SQL驱动的端点遥测

Osquery将操作系统抽象为一个关系型数据库，使用SQL查询操作系统状态。

### 核心概念

```
Osquery 架构：
┌─────────────────────────────────────────────┐
│              Osquery Daemon (osqueryd)         │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Scheduler │ │ Logger    │ │  Distributed   │  │
│  │ 定时采集   │ │ 日志输出   │ │  查询接口      │  │
│  └─────────┘ └──────────┘ └──────────────┘  │
│  ┌────────────────────────────────────────┐   │
│  │           Virtual Tables                │   │
│  │  processes │ network_interfaces │ file  │   │
│  │  users     │ sockets            │ registry │
│  │  ...       │                    │         │   │
│  └────────────────────────────────────────┘   │
│              ↑ 表数据由内核/系统API填充          │
└─────────────────────────────────────────────┘
```

### 常用Osquery表

| 表名 | 用途 | 跨平台 |
|------|------|--------|
| processes | 当前运行的进程列表 | Windows/Linux/macOS |
| network_interfaces | 网络接口信息（IP/MAC） | Windows/Linux/macOS |
| socket_events | Socket事件（需启用进程事件监控） | Linux |
| file_events | 文件修改事件 | Linux/macOS |
| dns_resolvers | DNS配置 | 所有平台 |
| registry | Windows注册表（键和值） | Windows |
| services | Windows服务列表 | Windows |
| user_events | 用户登录/注销事件 | Linux/macOS |
| kernel_extensions | 已加载的内核扩展 | macOS |
| etc_hosts | hosts文件内容 | 所有平台 |
| suid_bins | SUID二进制文件列表 | Linux |
| scheduled_tasks | 计划任务 | Windows/Linux |
| docker_containers | Docker容器信息 | Linux |

```sql
-- 查询示例1：查找隐藏进程（不在磁盘上的进程）
SELECT name, path, pid, parent
FROM processes
WHERE on_disk = 0;

-- 查询示例2：查找近期SSH登录失败的尝试
SELECT * FROM last
WHERE type = 7  -- LOGIN_PROCESS
  AND username != ''
  AND pid != 0
ORDER BY time DESC LIMIT 20;

-- 查询示例3：查找SUID二进制文件
SELECT path, username, groupname, permissions
FROM suid_bins
WHERE path NOT LIKE '/usr/bin/%'
  AND path NOT LIKE '/bin/%';

-- 查询示例4：查找开放的端口和关联进程
SELECT p.port, p.protocol, p.address, p.pid,
       pr.name AS process_name, pr.path AS process_path
FROM listening_ports p
JOIN processes pr ON p.pid = pr.pid
WHERE p.port < 1024;

-- 查询示例5：查找所有计划任务
SELECT * FROM scheduled_tasks;
```

### Osquery配置示例

```json
{
  "options": {
    "schedule_splay_percent": 10,
    "pidfile": "/var/osquery/osquery.pid",
    "database_path": "/var/osquery/osquery.db",
    "verbose": false,
    "disable_events": false,
    "disable_audit": false,
    "audit_allow_config": true,
    "audit_persist": true
  },
  "schedule": {
    "process_audit": {
      "query": "SELECT pid, name, path, cmdline, parent FROM processes",
      "interval": 60,
      "removed": true
    },
    "network_connections": {
      "query": "SELECT pid, fd, family, protocol, local_address, remote_address, state FROM process_open_sockets WHERE family = 2",
      "interval": 300,
      "removed": false
    },
    "file_integrity": {
      "query": "SELECT * FROM file_events",
      "interval": 600
    },
    "suid_monitor": {
      "query": "SELECT * FROM suid_bins",
      "interval": 3600
    }
  },
  "file_paths": {
    "etc": [
      "/etc/%%",
      "/etc/ssh/%%"
    ],
    "home": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
    "www": [
      "/var/www/%%"
    ]
  },
  "packs": [
    "osquery-monitoring",
    "incident-response",
    "hardware-monitoring"
  ]
}
```

## Wazuh：开源HIDS/SIEM平台

Wazuh由三个主要组件组成：

```
┌──────────────┐    ┌──────────────┐    ┌───────────────┐
│  Wazuh Agent  │───►│ Wazuh Manager│───►│ Wazuh Indexer  │
│  (端点采集)    │    │ (中央管理)    │    │ (数据存储/搜索) │
│              │    │              │    │               │
│  文件监控      │    │  规则引擎     │    │  可视化仪表盘   │
│  漏洞检测      │    │  告警聚合     │    │  告警分析      │
│  配置审计      │    │  主动响应     │    │  （Elasticsearch）│
│  命令执行      │    │  FIM处理     │    │               │
└──────────────┘    └──────────────┘    └───────────────┘
```

### Wazuh Agent安装

```bash
# Linux Agent安装
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-agent

# 配置Agent连接到Manager
echo "WAZUH_MANAGER='192.168.1.100'" > /etc/wazuh-agent/agent.conf
systemctl start wazuh-agent

# Windows Agent安装
# 通过MSI安装包安装，安装时指定Manager地址
# wazuh-agent-4.7.0-1.msi WAZUH_MANAGER="192.168.1.100" WAZUH_REGISTRATION_PASSWORD="reg_password"
```

### Wazuh Manager配置

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <!-- 全局配置 -->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>

  <!-- 文件完整性监控（FIM） -->
  <syscheck>
    <frequency>7200</frequency>
    <directories check_all="yes">/etc,/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/root/.ssh,/home</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/tmp</directories>
    <ignore>/etc/mtab</ignore>
    <!-- Windows路径 -->
    <directories check_all="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\inetpub\wwwroot</directories>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  </syscheck>

  <!-- 入侵检测规则 -->
  <rules>
    <include>rules_config.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <!-- 漏洞检测配置 -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
    </provider>
  </vulnerability-detector>

  <!-- 主动响应 -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5715</rules_id>  <!-- SSH暴力破解规则ID -->
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

### Wazuh自定义规则

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="syslog,attacks,">
  <!-- SSH暴力破解规则增强 -->
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>Failed password for invalid user</match>
    <description>SSH暴力破解检测：无效用户登录失败</description>
    <group>authentication_failure,</group>
  </rule>

  <!-- 检测sudo权限提升 -->
  <rule id="100002" level="12">
    <if_sid>5402</if_sid>
    <match>SSH:TTY=/dev/</match>
    <description>用户通过SSH执行了特权命令：$(log)</description>
    <group>privilege_escalation,</group>
  </rule>

  <!-- 检测可疑的Cron配置变更 -->
  <rule id="100003" level="10">
    <if_sid>590</if_sid>
    <match>/var/spool/cron</match>
    <description>Cron配置变更，可能为持久化操作</description>
    <group>persistence,</group>
  </rule>
</group>
```

### Wazuh告警示例

```json
{
  "timestamp": "2024-05-26T10:30:45+0800",
  "rule": {
    "level": 10,
    "description": "SSH暴力破解检测：无效用户登录失败",
    "id": "100001",
    "mitre": {
      "id": ["T1110"],
      "technique": ["Brute Force"]
    }
  },
  "agent": {
    "id": "012",
    "name": "web-server-01",
    "ip": "10.0.1.15"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "data": {
    "srcip": "203.0.113.50",
    "dstip": "10.0.1.15",
    "srcport": 54321,
    "dstport": 22,
    "protocol": "TCP"
  },
  "location": "sshd",
  "full_log": "May 26 10:30:45 web-server-01 sshd[12345]: Failed password for invalid user admin from 203.0.113.50 port 54321 ssh2"
}
```

## Osquery + Wazuh集成

Wazuh可以接收Osquery采集的数据，实现更全面的监控。

### 方法1：Osquery通过syslog向Wazuh发送数据

```bash
# osquery配置：启用syslog日志输出
osqueryctl config-check

# 配置osquery日志输出到syslog
# /etc/osquery/osquery.flags
--logger_plugin=filesystem,syslog
--syslog_event_type=true
--verbose=false

# 配置Wazuh Agent读取syslog中的Osquery事件
# /var/ossec/etc/ossec.conf 添加:
<localfile>
  <location>/var/log/osquery/osqueryd.results.log</location>
  <log_format>json</log_format>
</localfile>
```

### 方法2：Osquery分布式查询 + Wazuh Active Response

```python
# Osquery分布式查询工具（Fleet管理）
import requests
import json

fleet_url = "https://fleet.company.com:8080"
api_token = "your_fleet_token"

def run_osquery_query(query, target_hosts):
    """在目标主机上运行Osquery分布式查询"""
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "query": query,
        "targets": {"hosts": target_hosts}
    }
    
    response = requests.post(
        f"{fleet_url}/api/v1/fleet/queries/run",
        headers=headers,
        json=payload
    )
    
    results = response.json()
    for result in results["results"]:
        host = result["host"]["hostname"]
        if result["error"] is None:
            print(f"主机 {host} 查询结果:")
            for row in result["rows"]:
                print(f"  {row}")
        else:
            print(f"主机 {host} 查询失败: {result['error']}")
```

### 文件完整性监控对比

| 功能 | Osquery (FIM) | Wazuh (Syscheck) |
|------|--------------|-----------------|
| 监控机制 | fanotify/inotify | inotify + 定时扫描 |
| 实时监控 | 支持（inotify） | 支持（realtime=yes） |
| 完整性检查 | SHA256哈希 | SHA1/SHA256/MD5 |
| 排除模式 | 基于路径和通配符 | 路径 + 正则 + 文件名 |
| 性能 | 配置更简单 | 更成熟的扫描引擎 |
| 告警生成 | 需外部日志处理 | 内置规则引擎 |

## 安全监控实用查询

### 应急响应查询

```sql
-- 查找最近的登录事件
SELECT username, address, terminal, time
FROM user_events
WHERE type = 'login'
ORDER BY time DESC LIMIT 50;

-- 查找新安装的应用/包
SELECT name, version, source
FROM deb_packages
ORDER BY install_time DESC LIMIT 30;

-- 查找建立的网络连接
SELECT pid, process.name, remote_address, remote_port, state
FROM process_open_sockets
JOIN processes USING (pid)
WHERE remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0')
  AND family = 2  -- AF_INET
  AND state IN ('ESTABLISHED', 'LISTEN');

-- 查找特权用户（UID=0的账户）
SELECT * FROM users WHERE uid = 0;

-- 查找Kubernetes集群中的异常容器
SELECT dc.name, dc.image, dc.status, dc.command
FROM docker_containers dc
WHERE dc.status = 'running'
  AND dc.image NOT IN (
    -- 白名单镜像列表
    SELECT docker_image FROM allowed_container_images
  );
```

## 总结

Osquery和Wazuh是开源端点安全的黄金组合。Osquery提供基于SQL的灵活查询能力，适合快速检视系统状态和应急响应；Wazuh提供持续监控、规则引擎和告警管理的能力。两者结合可以构建出与商业EDR产品相媲美的开源端点检测体系。
