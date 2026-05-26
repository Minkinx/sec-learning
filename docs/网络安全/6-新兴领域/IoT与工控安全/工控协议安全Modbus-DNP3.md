# 工控协议安全：Modbus与DNP3

## 概述

工业控制系统（ICS）协议与IT协议有本质区别。ICS协议强调确定性（deterministic）、实时性（real-time）和可靠性。传统ICS协议在设计时未考虑安全因素，缺乏认证、加密和完整性校验，这使得它们在现代互联环境中面临严重威胁。

| 特性 | ICS协议 | IT协议 |
|------|---------|--------|
| 优先级 | 可用性 > 完整性 > 机密性 | 机密性 > 完整性 > 可用性 |
| 实时性 | 毫秒级要求 | 容忍延迟 |
| 通信模式 | 周期性轮询 | 请求-响应 |
| 数据包大小 | 小（几十字节） | 可大（MTU 1500） |
| 生命周期 | 15-20年 | 3-5年 |

## Modbus协议

### 协议基础

Modbus由Modicon（现Schneider Electric）于1979年发布，是工控领域最广泛使用的协议。Modbus有两种主要变体：

**Modbus RTU**：串行通信（RS-232/RS-485），二进制编码，CRC校验。

**Modbus TCP**：以太网通信，端口502，去掉了CRC（由TCP保证），增加MBAP头。

Modbus TCP帧结构：

```
Transaction ID (2 bytes)  Protocol ID (2 bytes)  Length (2 bytes)
Unit ID (1 byte)          Function Code (1 byte) Data (variable)
```

### 功能码

Modbus功能码定义了读写操作的类型：

| 功能码 | 操作 | 用途 |
|--------|------|------|
| 01 (0x01) | Read Coils | 读取离散输出 |
| 02 (0x02) | Read Discrete Inputs | 读取离散输入 |
| 03 (0x03) | Read Holding Registers | 读取保持寄存器 |
| 04 (0x04) | Read Input Registers | 读取输入寄存器 |
| 05 (0x05) | Write Single Coil | 写入单个线圈 |
| 06 (0x06) | Write Single Register | 写入单个寄存器 |
| 15 (0x0F) | Write Multiple Coils | 批量写线圈 |
| 16 (0x10) | Write Multiple Registers | 批量写寄存器 |

使用Python与Modbus设备交互：

```python
from pymodbus.client import ModbusTcpClient

# 连接到PLC
client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# 读取保持寄存器（从地址0开始读10个寄存器）
response = client.read_holding_registers(0, 10, unit=1)
if not response.isError():
    print(f"寄存器值: {response.registers}")

# 写入单个线圈
client.write_coil(0, True, unit=1)

# 批量写入寄存器
client.write_registers(0, [100, 200, 300], unit=1)

client.close()
```

### Modbus安全缺陷

Modbus面临的核心安全问题是**完全没有认证和加密机制**：

1. **无认证**：任何能访问502端口的攻击者都可以发送任意功能码
2. **无加密**：所有数据包以明文传输
3. **无会话管理**：每个包独立，无身份关联
4. **功能码滥用**：03读取全部寄存器，06写任意寄存器

攻击场景示例：

```python
# 攻击者脚本：禁用所有输出线圈
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# 批量写线圈：将地址0-100全部设为False
client.write_coils(0, [False] * 100, unit=1)
client.close()
```

## DNP3协议

### 协议特点

DNP3（Distributed Network Protocol）由GE Harris在1993年开发，主要应用于电力行业。相比Modbus，DNP3功能更加丰富：

1. **事件驱动**：支持时间戳事件上报，而非仅轮询
2. **数据优先级**：分类（Class 0/1/2/3）实现分级传输
3. **非请求响应**：设备主动上报事件
4. **分片传输**：大消息分片传输和重组
5. **应用层确认**：可靠传输保证

DNP3帧结构：

```
Sync (2 bytes: 0x0564)  Length (1 byte)  Link Control (1 byte)
Dest Address (2 bytes)  Src Address (2 bytes)  CRC (2 bytes)
...(传输层)  应用层请求/响应   CRC...
```

### DNP3认证

DNP3 Secure Authentication v5（SAv5）提供了挑战-响应认证机制：

| 功能码 | 描述 |
|--------|------|
| 0x0F | 认证请求 |
| 0x10 | 认证响应 |
| 0x25 | 会话密钥状态请求 |
| 0x26 | 会话密钥状态响应 |

认证流程：

```
主站 → 从站: 功能码 + 数据 + MAC
从站 → 主站: 挑战随机数 + 序列号
主站 → 从站: 基于共享密钥计算的MAC响应
从站 → 主站: 认证成功/失败状态码
```

### DNP3攻击面

尽管DNP3提供了认证机制，但其攻击面仍然广泛：

1. **功能码滥用**：控制操作（Select/Operate）、直接操作、冷重启
2. **对象变体操纵**：改变数据类型解释方式
3. **分片攻击**：应用层分片重组缓冲区溢出
4. **未启用认证**：许多部署未启用SAv5

攻击向量示例：

```
# 恶意的DNP3分片消息
分片1: [应用层头] 功能码=0x05(冷重启)
分片2: [应用层头] 对象组=0x0C (控制对象)
分片3: [应用层头] ...
# 重组后形成恶意的完整控制指令
```

### 使用Boofuzz进行协议Fuzzing

```python
from boofuzz import *

def modbus_fuzz():
    session = Session(
        target=Target(Connection("tcp://192.168.1.100:502"))
    )

    # Modbus TCP MBAP头
    s_initialize("ModbusTCP")
    s_word(0x0001, name="TransactionID")   # 事务ID
    s_word(0x0000, name="ProtocolID")      # 协议ID
    s_word(0x0006, name="Length")          # 长度（可变）
    s_byte(0x01, name="UnitID")            # 单元ID
    s_byte(0x03, name="FunctionCode")      # 功能码
    s_string(b'\x00\x00', name="Data")     # 数据负载

    session.connect(s_get("ModbusTCP"))
    session.fuzz()

if __name__ == "__main__":
    modbus_fuzz()
```

Fuzzing目标：通过发送畸形包触发处理函数中的边界条件错误、空指针解引用、整数溢出和缓冲区溢出。

## 工控协议安全防护

### 网络隔离

基于Purdue模型的工控网络层级隔离是基础防护：

```
Level 3: 运营管理层
     | (工业防火墙/Tofino)
Level 2: 区域监控层
     | (工业防火墙)
Level 1: 基本控制层 (PLC/RTU)
```

### 安全措施

1. **工业防火墙**：Tofino、Hirschmann等支持Modbus/DNP3深度包检测的专用防火墙
2. **网络分割**：基于VLAN/物理隔离的ICS网络分区
3. **应用层认证**：启用DNP3 SAv5、OPC UA认证
4. **协议异常检测**：识别异常功能码组合、异常寄存器范围
5. **SoE审计日志**：事件顺序记录，存证合规

### 深度包检测规则示例（Suricata）

```yaml
# Modbus异常检测规则
alert tcp any any -> any 502 (
    msg:"Modbus - 异常功能码（写操作）";
    content:"|00 00 00 00 00 06 01|";  # MBAP头
    content:"|10|";                      # 功能码0x10 批量写
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:attempted-recon;
    sid:1000001;
)

alert tcp any any -> any 502 (
    msg:"Modbus - 异常寄存器地址范围";
    content:"|00 00 00 00 00 06 01|";
    content:"|06|";                      # 写单个寄存器
    byte_test:2, >, 1000, 8;            # 寄存器地址 > 1000
    classtype:bad-unknown;
    sid:1000002;
)

# DNP3异常检测
alert tcp any any -> any 20000 (
    msg:"DNP3 - 未经认证的控制操作";
    content:"|05 64|";                   # DNP3 sync
    content:"|0C|";                      # 应用层控制功能码
    flags:!ACK;
    classtype:attempted-admin;
    sid:1000003;
)
```

## 总结

Modbus和DNP3作为工控领域最核心的通信协议，在设计之初缺乏安全考量。Modbus完全无认证加密，DNP3虽提供认证选项但实际部署率低。工控协议安全防护需要采取纵深防御策略：物理隔离、工业层防火墙、协议异常检测和持续的ICS安全监控相结合。
