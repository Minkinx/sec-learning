# SIEM-SOC建设

## 概述

安全运营中心（SOC）是企业网络安全防御的中枢神经，而 SIEM（安全信息和事件管理）是 SOC 的核心技术平台。一个成熟的 SOC 能够实现威胁的实时检测、调查和响应。

## SOC 组织架构与人员分级

现代 SOC 通常采用三线或四线架构模型：

| 级别 | 名称 | 核心职责 | 技能要求 | 占比 |
|------|------|---------|---------|------|
| Tier 1 | 监控与告警研判 | 告警初步筛选，确定是否为真实告警 | 基础安全知识，理解常见攻击类型 | 40% |
| Tier 2 | 事件调查 | 深入调查确认的告警，确定影响范围 | 掌握取证分析、日志分析、网络分析 | 35% |
| Tier 3 | 威胁狩猎与高级分析 | 主动搜索威胁，规则调优，恶意软件分析 | 逆向工程、威胁情报、红队思维 | 20% |
| Tier 4 | 架构与自动化 | SOAR、自动化编排、检测架构设计 | 开发、DevSecOps、大数据 | 5% |

## SIEM 架构流水线

```
数据源 ──→ 日志采集器 ──→ 解析/标准化 ──→ 索引/存储 ──→ 关联分析 ──→ 告警/仪表盘
    ↑              ↑            ↑             ↑               ↑
    │              │            │             │               │
 端点日志       Syslog       Logstash      Elasticsearch    Kibana
 网络设备       Fluentd      CEF/LEEF       Splunk          Splunk ES
 云服务的        WinEvent    JSON              ──→       SIEM Console
 应用日志        Beats        K-V 提取                         ↓
                                                         SOAR Playbook
```

## ELK Stack (Elasticsearch, Logstash, Kibana)

### 组件功能

| 组件 | 功能 | 部署角色 |
|------|------|---------|
| Elasticsearch | 分布式搜索引擎，日志存储和检索 | 数据存储层 |
| Logstash | 日志采集、解析和转换 | 数据处理层 |
| Kibana | 可视化、仪表盘、告警管理 | 展示层 |
| Beats (Filebeat/Winlogbeat) | 轻量级日志采集代理 | 采集层 |

### Logstash 解析示例

```ruby
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
  }
}

filter {
  if [event_id] == 4624 {
    mutate {
      add_tag => ["windows_logon_success"]
    }
    if [logon_type] == "10" or [logon_type] == 10 {
      mutate {
        add_tag => ["remote_logon"]
      }
    }
    if [account_name] != $KNOWN_ACCOUNTS {
      elasticsearch {
        hosts => ["localhost:9200"]
        query => "
          source: $HOSTNAME AND
          event_id: 4624 AND
          account_name: $account_name AND
          _exists_: source_ip
        "
        fields => {"source_ip" => "prev_logon_ip"}
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "windows-security-%{+YYYY.MM.dd}"
  }
}
```

## Splunk

Splunk 是企业级 SIEM 市场领导者，核心能力包括：

### SPL 搜索语言

```
# 检测密码喷洒攻击 - 同一个IP多个用户登录失败
index=windows EventCode=4625
| bucket span=5m _time
| stats dc(UserName) as unique_users,
         count as total_attempts
         by Source_Network_Address, _time
| where unique_users >= 10 AND total_attempts >= 30
| sort - total_attempts

# 检测 PowerShell 编码命令执行
index=windows EventCode=4104 ScriptBlockText="*EncodedCommand*" OR ScriptBlockText="*-enc*"
| stats count by UserName, ComputerName, ScriptBlockText

# 检测异常网络连接（数据渗出）
index=network sourcetype=fortinet
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 50000000
| join src_ip [search index=windows EventCode=4624 | stats latest(Account_Name) as user by ip_address]
```

### 数据模型 (CIM)

Splunk Common Information Model (CIM) 提供了标准化的安全事件数据模型：

| 数据模型 | 描述 | 关键字段 |
|---------|------|---------|
| Authentication | 认证事件 | user, src_ip, dest, action, app |
| Endpoint | 端点进程 | process, parent_process, command, user |
| Network Traffic | 网络流量 | src_ip, dest_ip, dest_port, bytes, protocol |
| Web | HTTP 流量 | url, method, user_agent, status |
| Malware | 恶意软件检测 | signature, file_name, file_hash, action |

## 检测用例开发

完整的检测用例开发流程：

1. **需求阶段**: 识别需要检测的攻击行为（如 brute force, DCSync, Pass-the-Hash）
2. **数据源映射**: 确定提供检测数据的数据源（Sysmon, Windows Event Log, DNS logs）
3. **规则编写**: 编写检测逻辑
4. **调优测试**: 基线测试，调整阈值以避免误报
5. **部署生产**: 生产环境部署，伴随观察期
6. **持续优化**: 根据误报/漏报持续调优

### 检测用例示例：密码喷洒

```spl
# 检测逻辑: 单一 IP -> 多个不同用户 -> 短时间内多次登录失败 -> 一次成功
# 关联 EID 4625 (登录失败) 和 EID 4624 (登录成功)

index=windows EventCode IN (4625, 4624)
| stats values(EventCode) as events,
        dc(EventCode) as event_types,
        values(UserName) as users_attempted,
        dc(UserName) as unique_users
        by Source_Network_Address, _time
| search event_types=2 AND events="4624" AND events="4625"
| where unique_users > 5
```

### 通用检测规则示例

| 规则名称 | 检测逻辑 | 严重级别 | 数据源 |
|---------|---------|---------|--------|
| DCSync 检测 | 来源为非域控的 DS-Replication-Get-Changes 请求 | 严重 | Windows Event Log 4662 |
| Pass-the-Hash | NTLM 认证中 source IP 与 account 历史行为不一致 | 高危 | Windows Event Log 4624 |
| Kerberoasting | TGS-REP 中加密类型为 RC4 的请求异常增多 | 高危 | Windows Event Log 4769 |
| WMI 横向移动 | WinRM/WMI 事件创建了计划任务或服务 | 中危 | Sysmon EID 1, EID 7 |

## SOAR 集成

SOAR（安全编排自动化与响应）平台将 SOC 流程自动化：

| SOAR 平台 | 类型 | 特点 |
|----------|------|------|
| Splunk Phantom | 商业 | 深度 Splunk 集成，Playbook 可视化 |
| Shuffle | 开源 | 轻量级，Webhook 驱动 |
| Swimlane | 商业 | 低代码平台，案例管理强大 |
| Palo Alto XSOAR | 商业 | 丰富的集成市场 |
| Wazuh | 开源 | SIEM+SOAR 一体，基于 OSSEC |

### 典型 SOAR Playbook：钓鱼告警处理

```
用户报告钓鱼邮件
  └─→ 自动提取邮件 IOCs（发件人、链接、附件哈希）
      ├─→ 查询威胁情报平台 (VirusTotal/AbuseIPDB)
      ├─→ 检查企业内部是否有其他人收到相同邮件
      ├─→ 邮件全局删除（如果确认为钓鱼）
      └─→ 创建工单 → 通知安全团队 → 回复用户
```

## SOC 成熟度模型

| 级别 | 名称 | 特征 | 关键指标 |
|------|------|------|---------|
| Level 1 | 初始级 (Ad-hoc) | 非正式流程，依赖个人能力 | MTTA > 4h, MTTR > 24h |
| Level 2 | 标准化级 | 有明确流程和基础 SIEM | MTTA 1-4h, MTTR 8-24h |
| Level 3 | 主动狩猎级 | 威胁狩猎、威胁情报驱动 | MTTA < 1h, MTTR < 4h |
| Level 4 | 预测级 | AI/ML 驱动、自动化闭环 | MTTA < 15min, MTTR < 1h |

注：MTTA=平均确认时间，MTTR=平均响应时间。

## 常见挑战与建议

1. **告警疲劳 (Alert Fatigue)**: 每天数千告警 → 减少规则噪音，使用告警分组和优先级排序
2. **人员流失**: SOC 人员工作压力大 → 自动化重复工作，提供培训路径和职业发展
3. **数据溯源复杂性**: 需要跨系统关联 → 建立统一的日志分类和标签体系
4. **预算限制**: SIEM 数据存储成本高 → 分层存储策略（热/温/冷），优化日志量
