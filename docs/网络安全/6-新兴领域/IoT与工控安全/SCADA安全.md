# SCADA安全

## SCADA架构概述

SCADA（Supervisory Control and Data Acquisition，监控和数据采集系统）是大型工业控制系统的核心架构。它由多个组件协同工作，实现分布式设备的远程监控和控制。

### 核心组件

| 组件 | 全称 | 功能描述 |
|------|------|---------|
| MTU | Master Terminal Unit | 主站终端单元，中心控制服务器 |
| RTU | Remote Terminal Unit | 远程终端单元，现场数据采集 |
| IED | Intelligent Electronic Device | 智能电子设备，智能传感器/继电器 |
| HMI | Human Machine Interface | 人机界面，可视化操作面板 |
| Historian | 历史数据库 | 存储过程数据和报警记录 |
| PLC | Programmable Logic Controller | 可编程逻辑控制器，现场控制 |

### 典型架构

```
[企业网]            [控制中心]           [现场设备]
  ERP  ── 防火墙 ──  MTU/HMI  ── RTU ── 传感器/执行器
  MES                 Historian     PLC   IED
  Web/Email           工程站
```

## Purdue模型

Purdue企业参考架构（PERA）是ICS网络分层的行业标准模型：

| 层级 | 名称 | 功能 | 典型组件 |
|------|------|------|---------|
| Level 5 | 企业网络 | 企业级应用和互联网 | Email, Web, 企业ERP |
| Level 4 | 场地业务规划 | 生产和物流管理 | ERP, MES, 资产管理 |
| Level 3.5 | DMZ | IT/OT安全隔离 | 工业防火墙, 数据二极管 |
| Level 3 | 运营管理 | 生产监控和调度 | 历史数据库, AD域控, 调度系统 |
| Level 2 | 区域监控 | 本地化监督控制 | HMI, 工程工作站, 报警系统 |
| Level 1 | 基本控制 | 自动化的设备控制 | PLC, RTU, 分散控制系统 |
| Level 0 | 过程设备 | 物理传感和执行 | 传感器, 执行器, 变频器, 电机 |

### 关键隔离原则

1. **Level 3-4之间必须部署DMZ**：不允许OT到IT或IT到OT的直接连接
2. **单向数据流**：从Level 0-2到Level 3以上使用数据二极管（Data Diode）
3. **禁止直连互联网**：Level 0-3的任何组件不应直接访问互联网
4. **远程访问管控**：通过跳板机（Bastion/Jump Host）进行所有远程维护

### DMZ配置示例

```
┌─────────────────────────────────────────────────┐
│                    企业IT网络                      │
│  Level 4-5: ERP, Email, AD, Web                  │
└──────────────────────┬──────────────────────────┘
                       │
              ┌────────┴────────┐
              │   Level 3.5 DMZ  │
              │  · 反向代理      │
              │  · 堡垒机        │
              │  · 文件镜像      │
              │  · 日志转发器    │
              └────────┬────────┘
                       │
┌──────────────────────┴──────────────────────────┐
│                     OT控制网络                     │
│  Level 0-3: PLC, RTU, HMI, Historian, SCADA     │
└─────────────────────────────────────────────────┘
```

## ICS杀伤链

与传统IT杀伤链相比，ICS杀伤链增加了对物理破坏的强调：

### ICS杀伤链各阶段

| 阶段 | 描述 | 示例 |
|------|------|------|
| 1. 侦察 | 收集目标ICS信息 | 扫描OT网络、分析控制协议 |
| 2. 武器化 | 制作针对ICS的载荷 | 为特定PLC型号定制恶意固件 |
| 3. 投递 | 将载荷送达目标系统 | 钓鱼邮件、USB摆渡、供应链 |
| 4. 利用 | 利用漏洞获得初始访问 | Web漏洞、默认密码、远程代码执行 |
| 5. 安装 | 建立持久化控制 | 在工程站安装后门、修改PLC程序 |
| 6. 指挥控制 | 建立C2通道 | 通过DMZ的允许端口建立隧道 |
| 7. **达成目标** | **执行物理破坏操作** | **关闭断路器、损坏设备、造成安全事故** |

ICS杀伤链与传统IT杀伤链的最大区别在于**阶段7的物理后果**。IT攻击的目标通常是数据窃取或勒索，而ICS攻击的目标可能是造成设备损坏、生产停滞甚至人身伤亡。

### 案例：乌克兰电网攻击（2015）

```
侦察阶段: 攻击者收集乌克兰电力公司员工信息
投递阶段: 发送包含BlackEnergy恶意软件的钓鱼邮件
利用阶段: 获得办公网络访问权限，窃取VPN凭据
安装阶段: 利用VPN凭据进入OT网络，在HMI工程站安装KillDisk
C2阶段: 通过已经建立的VPN隧道远程控制
达成目标:
  · 远程打开7个110kV变电站的断路器
  · 用KillDisk擦除HMI和MTU系统
  · 对UPS进行DoS攻击（电话拒绝服务阻止通知）
  · 影响约23万用户，停电数小时
```

## ICS-CERT/CISA ICS安全公告

CISA ICS（原ICS-CERT）定期发布ICS漏洞公告，涵盖各类工控产品的安全问题：

```yaml
ICS Advisory: ICSA-24-xxx
Title: Siemens SIMATIC S7-1200 CPU Web Server
Vulnerability: Stack-based Buffer Overflow
CVE: CVE-2024-XXXXX
CVSS v3.1: 9.8 (Critical)
Impact: Remote Code Execution via crafted HTTP request
Affected:
  - SIMATIC S7-1200 V4.x prior to 4.6
  - SIMATIC S7-1200 V5.x prior to 5.2
Mitigation:
  - Update to firmware version 4.6 or later
  - Disable Web Server when not in use
  - Restrict network access to authorized devices only
```

常见ICS漏洞类型：

| 漏洞类型 | 比例 | 典型影响 |
|---------|------|---------|
| 缓冲区溢出 | 35% | 远程代码执行、PLC崩溃 |
| 认证缺失/不当 | 25% | 未授权控制、配置篡改 |
| 拒绝服务 | 15% | 控制器挂起、看门狗复位 |
| 信息泄露 | 10% | 凭据泄露、项目文件被盗 |
| 权限管理 | 8% | 提权、功能越级 |
| 其他 | 7% | 硬编码密码、明文通信 |

## OT网络隔离实战

### 数据二极管

数据二极管（Data Diode，也称单向网关）是一种硬件级的安全设备，只允许数据单向传输：

```
┌──────┐     光信号单向      ┌──────┐
│  OT  │ ──────────────────→ │  IT  │
│ 网络  │   (物理层单向)     │ 网络  │
└──────┘                    └──────┘
```

数据二极管原理：使用光纤收发器，只有发送端连接光源，接收端无光源，物理上保证无法反向通信。运营商级数据二极管可实现万兆速率传输。

### 被动监控

OT网络中监控应使用被动方式（端口镜像/网络TAP），**禁止主动扫描**：

```bash
# ❌ 危险：主动扫描可能导致PLC崩溃
nmap -sV -O 192.168.0.0/24  # PLC可能对非标准扫描包响应异常

# ✓ 安全：被动流量分析
tcpdump -i eth0 -w ot_traffic.pcap port 502 or port 20000

# 使用Zeek/Bro分析ICS协议
zeek -r ot_traffic.pcap ics/Modbus ics/DNP3

# 分析工控协议统计
zeek-cut ts uid proto service duration conn_state < conn.log
```

### 告警规则示例

```yaml
# ICS特定告警规则 (基于Zeek)
# 1. Modbus线圈写操作检测
event modbus_write_coil(rec: Modbus::WriteCoilRecord) {
    if (rec$coil_value == T) {
        NOTICE([
            $note=Modbus::Coil_Write,
            $msg=fmt("Modbus coil %d written to TRUE by %s",
                     rec$coil_address, rec$id$orig_h),
            $conn=rec$id
        ]);
    }
}

# 2. 非工作时间控制操作告警
event modbus_write_register(rec: Modbus::WriteRegisterRecord) {
    local current_hour = strptime("%Y-%m-%d %H:%M:%S",
                                  strftime("%Y-%m-%d %H:%M:%S",
                                  network_time()))$hour;
    if (current_hour < 8 || current_hour > 18) {
        NOTICE([
            $note=Modbus::Off_Hours_Operation,
            $msg="Modbus write operation outside business hours"
        ]);
    }
}
```

## 总结

SCADA安全是ICS/OT安全的核心，其挑战在于OT环境对可用性的极端要求。采用Purdue模型进行网络分层、部署工业防火墙和数据二极管实现单向隔离、使用被动监控避免主动扫描对PLC的影响，是SCADA安全的基础实践。同时，追踪CISA ICS安全公告并及时评估影响是保持安全态势持续有效的关键。
