# 蓝牙安全BlueBorne-BLE

## 概述

蓝牙技术分为经典蓝牙（BT Classic）和低功耗蓝牙（Bluetooth Low Energy, BLE），广泛应用于物联网设备、可穿戴设备、医疗设备和智能家居。蓝牙安全漏洞包括协议栈RCE（BlueBorne）、PIN破解、BLE嗅探和中间人攻击。由于蓝牙设备常作为无头设备运行（无屏幕和输入），安全问题往往被忽视。

## 蓝牙协议栈概览

### Classic Bluetooth协议栈

```text
Application Layer
    ↑
RFCOMM (串口仿真)
    ↑
L2CAP (逻辑链路控制和适配)
    ↑
HCI (主机控制器接口)
    ↑
Link Manager (链路管理)
    ↑
Baseband/Link Controller (基带/链路控制)
    ↑
Bluetooth Radio (射频)
```

### BLE协议栈

```text
Application (GATT Profiles)
    ↑
GATT (Generic Attribute Profile)
    ↑
ATT (Attribute Protocol)
    ↑
SM (Security Manager)
    ↑
L2CAP
    ↑
HCI
    ↑
Link Layer
    ↑
BLE Radio
```

## BlueBorne攻击（CVE-2017-0781等）

BlueBorne是2017年披露的一系列蓝牙协议栈漏洞，影响数十亿设备：

### 核心漏洞

```text
# Android (CVE-2017-0781, CVE-2017-0782)
- 蓝牙网络封装协议（BNEP）远程代码执行
- 个人区域网（PAN）服务内存损坏
- Android 4.4至8.0受影响

# iOS (CVE-2017-14315)
- Apple Wireless Direct Link (AWDL) RCE
- iOS 9.3.5及更早版本受影响

# Linux (CVE-2017-1000251)
- BlueZ协议栈堆栈缓冲区溢出
- 所有Linux内核版本（3.3-rc1至4.13.1）

# Windows (CVE-2017-8628)
- Windows Bluetooth驱动远程代码执行
- Windows 7至Windows 10 (Fall Creators Update之前)
```

### 攻击特点

```text
# BlueBorne攻击链
1. 发现阶段：主动扫描附近活跃的蓝牙设备（无需配对）
2. 信息收集：获取设备名称、MAC、服务列表
3. 漏洞利用：发送特制的蓝牙数据包触发协议栈漏洞
4. 传播：利用受感染设备作为跳板感染更多设备

# 攻击优势
- 无需用户交互
- 不需要设备已配对
- 不需要蓝牙可见模式
- 在空中传播（类似蠕虫）
- 绕过传统网络安全控制
```

## BLE攻击技术

### BLE嗅探

```bash
# 使用BlueZ工具扫描BLE设备
hcitool lescan

# 更好的扫描
bluetoothctl
bluetoothctl > scan on
bluetoothctl > devices

# 使用Wireshark配合Ubertooth进行BLE嗅探
# 需要Ubertooth One硬件
ubertooth-btle -f -c capture.pcap

# 使用btlejack进行BLE劫持
btlejack -s  # 扫描BLE连接
btlejack -c connection_handle -f  # 跟随连接

# 使用nRF Sniffer（Nordic官方工具）
# 配合nRF52840 DK或nRF Dongle
```

### BLE GATT服务枚举

```bash
# 枚举BLE设备的服务和特征

# 使用gatttool
gatttool -b XX:XX:XX:XX:XX:XX -I
connect
primary  # 列出所有服务
characteristics  # 列出所有特征

# 使用bluetoothctl
bluetoothctl > menu gatt
bluetoothctl > select-attribute XX:XX:XX:XX:XX:XX
bluetoothctl > list-attributes
bluetoothctl > read XX:XX:XX:XX:XX:XX

# 自动化枚举脚本
python3 -c "
import pexpect
import sys

def enumerate_ble(addr):
    child = pexpect.spawn('gatttool -b %s -I' % addr)
    child.sendline('connect')
    child.expect('Connection successful')
    child.sendline('primary')
    print(child.read().decode())
    child.sendline('characteristics')
    print(child.read().decode())

enumerate_ble('XX:XX:XX:XX:XX:XX')
"
```

### BLE中间人攻击

```bash
# 使用btlejuice进行BLE MITM
btlejuice -u  # 启动Web UI
# 浏览器访问 http://localhost:8080
# 选择BLE设备进行拦截

# 使用gattacker
# 创建Rogue BLE设备
node apps/ble-central.js --target XX:XX:XX:XX:XX:XX

# BLE Key Negotiation攻击
# 1. 拦截配对过程
# 2. 强制使用Just Works模式（无安全连接）
# 3. 窃取密钥
```

### BLE安全连接分析

```text
# BLE配对模式（安全级别递增）
1. Just Works - 无安全保护（密钥总为0）
2. Passkey Entry - 6位数字PIN
3. Out of Band (OOB) - NFC交换密钥
4. LE Secure Connections - ECDH密钥交换

# BLE安全漏洞
- Just Works模式不提供MITM保护
- Passkey Entry仅6位数字（100万种组合）
- 密钥分发可能被拦截
- LTK（长期密钥）可能被提取
```

## BT Classic攻击

### PIN破解

```bash
# 蓝牙PIN暴力破解（仅限旧版2.0及以下）
# 在某些实现中PIN固定为0000或1234

# 使用Bluediving破解PIN
bluediving -b XX:XX:XX:XX:XX:XX -p brute

# 使用BTCrack
btcrack -b XX:XX:XX:XX:XX:XX -W wordlist.txt
```

### BlueBug攻击（CVE-2004-0829）

```bash
# 利用OBEX Push服务的认证绕过漏洞
# 无需授权即可访问AT命令、电话簿、短信

# 使用obexftp访问设备
obexftp -b XX:XX:XX:XX:XX:XX -l

# 使用BlueMaho进行BlueBug攻击
bluemaho -b XX:XX:XX:XX:XX:XX -m bug
```

### Bluesnarfing攻击

```bash
# 通过OBEX协议窃取设备信息
# 利用OBEX Push服务的未授权访问

# 使用bluesnarfer
bluesnarfer -b XX:XX:XX:XX:XX:XX -v

# 窃取电话簿
obexftp -b XX:XX:XX:XX:XX:XX -c telecom -g pb.vcf
```

## 蓝牙攻击工具

| 工具 | 用途 | 特点 |
|------|------|------|
| BlueZ | Linux官方蓝牙协议栈 | 基础工具集（hcitool, bluetoothctl） |
| Ubertooth | 蓝牙嗅探硬件 | 开源BT/BLE嗅探器 |
| btlejack | BLE劫持工具 | 连接劫持、密钥嗅探 |
| btlejuice | BLE中间人 | Web UI，实时拦截 |
| BlueBorne PoC | BlueBorne攻击 | RCE和DoS利用 |
| InternalBlue | BlueZ调试 | Python蓝牙调试框架 |
| GATTacker | BLE欺骗 | BLE设备克隆和重放 |
| Crackle | BLE破解 | Just Works/Passkey密钥恢复 |

## 防御措施

### 设备级防御

```text
# 1. 及时更新固件
- 保持蓝牙协议栈为最新版本
- 厂商安全补丁及时应用
- 特别是Android设备的每月安全更新

# 2. 关闭未使用的蓝牙
- 不使用时禁用蓝牙功能
- iOS控制中心开关可禁用（非完全关闭需在设置中关闭）
- 禁用蓝牙共享和可见性

# 3. 使用强配对
- 使用Passkey Entry而非Just Works
- 使用LE Secure Connections（BLE 4.2+）
- 验证配对码一致性
- 删除不再使用的配对记录

# 4. 最小化服务
- 仅启用必要的蓝牙Profile
- 禁用OBEX、DUN、PAN等高风险服务
- 使用安全模式3（加密+认证）
```

### 协议级防御

```text
# BLE 4.0/4.1的问题
- Just Works模式易受MITM攻击
- 密钥分发固定（LTK在连接建立时协商）
- 无前向保密

# BLE 4.2+的改进
- LE Secure Connections (ECDH密钥交换)
- LE Privacy 1.2 (可解析随机地址)
- 密钥长度从56位增加到128位

# BLE 5.x的增强
- 更强的加密算法
- 改进的配对协议
- 数据长度扩展（更安全的连接）
```

### 企业防御

```text
# 蓝牙安全策略
1. 禁止非托管蓝牙设备接入
2. 使用蓝牙安全管理方案
3. 定期审计蓝牙设备
4. 部署蓝牙入侵检测
5. 员工安全意识培训

# 检测BlueBorne
- 监控异常蓝牙通信量
- 检测未授权的蓝牙扫描
- 使用BlueBorne检测工具
```

## 参考资源

- [BlueBorne](https://www.armis.com/blueborne/)
- [BlueZ](http://www.bluez.org/)
- [InternalBlue](https://github.com/seemoo-lab/internalblue)
- [btlejack](https://github.com/virtualabs/btlejack)
- [btlejuice](https://github.com/DigitalSecurity/btlejuice)
- [OWASP Bluetooth Security](https://owasp.org/www-project-mobile-security-testing-guide/)
