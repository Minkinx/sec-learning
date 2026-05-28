# APP合规工具与检测方法

> APP合规检测需要结合静态分析、动态抓包、权限监控、隐私内容审计等多种技术手段。以下梳理常用工具及其使用场景。

## 静态分析工具

静态分析用于检测APP代码和配置中的合规风险，无需运行APP即可发现隐私政策缺失、权限声明不匹配、SDK引用等问题。

### 1. APP权限声明提取

Android APP的权限声明位于 `AndroidManifest.xml` 文件中。通过提取和分析权限声明，可以发现权限滥用问题。

```bash
# 使用 aapt 提取权限声明
aapt dump permissions app.apk

# 输出示例
uses-permission: android.permission.ACCESS_FINE_LOCATION
uses-permission: android.permission.CAMERA
uses-permission: android.permission.READ_CONTACTS
uses-permission: android.permission.RECORD_AUDIO
```

**合规检测要点**：提取的权限声明需与隐私政策中的说明逐项比对，识别**未声明的权限使用**和**非必要权限**。

### 2. APK反编译分析

使用 jadx 或 Apktool 反编译APK，检查隐私政策实现和SDK集成情况。

```bash
# 使用 jadx 反编译（推荐，支持GUI和命令行）
jadx -d output_dir app.apk

# 使用 Apktool 反编译（获取 smali 代码和资源）
apktool d app.apk -o output_dir

# 搜索隐私政策相关字符串
grep -r "privacy" output_dir/res/
grep -r "permission" output_dir/smali/ --include="*.smali"
```

**检测内容**：
- 隐私政策是否内嵌在APP中（assets目录）
- 首次启动弹窗逻辑（检查 MainActivity / SplashActivity）
- SDK初始化代码（搜索第三方SDK类名）
- 权限请求时机（检查运行时权限请求代码）

### 3. iOS IPA分析

```bash
# 解压IPA
unzip app.ipa -d output_dir

# 检查 Info.plist 中的权限声明
plutil -p output_dir/Payload/App.app/Info.plist | grep -E "NS(Location|Photo|Camera|Contacts|Microphone|Bluetooth)"

# 检查 Mach-O 二进制中的隐私相关字符串
strings output_dir/Payload/App.app/App | grep -iE "privacy|permission|consent"
```

iOS的 `Info.plist` 中定义的 `NS*UsageDescription` 必须与APP实际使用的权限一致，且需提供**中文用途说明**。

### 工具对比

| 工具 | 平台 | 功能 | 适用阶段 | 难易度 |
|------|------|------|---------|--------|
| jadx-gui | Android | 反编译+源码浏览 | 代码审查 | 低 |
| Apktool | Android | 反编译+回编译 | 资源分析 | 中 |
| aapt2 | Android | 资源/权限提取 | 权限快检 | 低 |
| class-dump | iOS | Objective-C头文件提取 | 接口分析 | 中 |
| Hopper | iOS | 二进制反汇编 | 深层分析 | 高 |

## 动态行为监控

动态监控通过运行APP并实时记录其行为，检测运行时的权限调用、数据外传和SDK活动。

### 1. 网络抓包分析

使用抓包工具监控APP的网络通信，检测数据外传行为。

**使用 mitmproxy 进行HTTPS抓包**：

```bash
# 1. 启动 mitmproxy
mitmproxy -p 8888

# 2. 设置代理（Android模拟器）
adb shell settings put global http_proxy 127.0.0.1:8888

# 3. 安装mitmproxy CA证书
# 将 ~/.mitmproxy/mitmproxy-ca-cert.pem 推送到设备
adb push mitmproxy-ca-cert.pem /sdcard/
# 在设备设置中安装CA证书（Android 7+需要root或Magisk模块）

# 4. 过滤特定域名
# mitmproxy 中按 f 输入过滤表达式
# ~d api.example.com
# ~d .*analytics.*
```

**检测内容**：

| 检测项 | 方法 | 合规风险 |
|--------|------|---------|
| 数据外传域名 | 分析所有HTTP/HTTPS请求域名 | 数据传输至未披露的第三方 |
| 请求body内容 | 检查POST请求的JSON/XML内容 | 超出范围的个人数据上传 |
| 加密传输 | 检查是否使用HTTPS（TLS 1.2+） | 明文传输敏感数据 |
| Cookie/Token | 检查鉴权信息的存储和传输安全 | Token泄露风险 |

### 2. 权限调用实时监控

**Android运行时权限检测**：

```bash
# 方法一：使用 adb 实时查看权限状态
adb shell dumpsys package <package_name>

# 检查运行时权限
adb shell dumpsys package <package_name> | grep -A 100 "runtime permissions"

# 输出示例
  requested permissions:
    android.permission.ACCESS_FINE_LOCATION
    android.permission.CAMERA
    android.permission.READ_CONTACTS
  install permissions:
    android.permission.ACCESS_NETWORK_STATE
    ...
  runtime permissions:
    android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[USER_SET]
    android.permission.CAMERA: granted=true, flags=[USER_SET]
```

**方法二：使用 logcat 监控权限调用**（Android 11+）：

```bash
# 捕获权限相关的日志
adb logcat -v time | grep -E "Permission|permission|Denied|Granted"

# 关注敏感权限调用
adb logcat -v time | grep -E "ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO"
```

### 3. APP行为抓取工具

| 工具 | 功能 | 支持平台 | 适用场景 |
|------|------|---------|---------|
| **Frida** | 动态插桩，Hook API调用 | Android/iOS | 反向追踪数据流、绕过检测 |
| **Xposed** | 框架级Hook | Android | 模块化隐私检测 |
| **Objection** | 运行时探索 | Android/iOS | 快速检测SSL Pinning、路径等 |
| **Drozer** | 安全评估框架 | Android | 四大组件安全、内容泄露检测 |
| **MobSF** | 自动化安全扫描 | Android/iOS | 综合合规扫描报告 |

**Frida Hook 示例** — 监控位置信息读取：

```javascript
// hook_location.js
if (Java.available) {
    Java.perform(function() {
        var LocationManager = Java.use('android.location.LocationManager');
        
        LocationManager.getLastKnownLocation.implementation = function(provider) {
            console.log('[HOOK] getLastKnownLocation called: ' + provider);
            // 记录调用栈
            console.log(Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()
            ));
            return this.getLastKnownLocation(provider);
        };
        
        LocationManager.requestLocationUpdates.overload(
            'java.lang.String', 'long', 'float', 'android.location.LocationListener'
        ).implementation = function(provider, minTime, minDistance, listener) {
            console.log('[HOOK] requestLocationUpdates: ' + provider);
            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
        };
    });
}
```

运行：
```bash
frida -U -f com.example.app -l hook_location.js --no-pause
```

## 自动化合规检测工具链

### 1. MobSF（Mobile Security Framework）

MobSF是一款覆盖静态分析+动态分析的移动端安全测试框架，适合作为合规检测的**第一道关卡**。

```bash
# 启动 MobSF
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# 命令行上传APK进行分析
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload
# 获取报告
curl -F "hash=<hash>" http://localhost:8000/api/v1/report_json
```

**MobSF合规检测项目**：

| 检测项 | 说明 | 严重程度 |
|--------|------|---------|
| 权限声明分析 | 对比声明的权限与APP类型是否匹配 | 高 |
| 不安全数据传输 | 检测HTTP明文传输、SSL Pinning缺失 | 高 |
| WebView配置 | JavaScript启用、文件访问允许 | 中 |
| 数据存储 | SharedPreferences明文存储、SQLite无加密 | 高 |
| 第三方SDK列表 | 自动识别集成的SDK及版本 | 中 |

### 2. APP专项治理自评估工具

APP专项治理工作组（由信安标委牵头）发布了官方的**APP个人信息保护合规自评估工具**，可用于：

- 隐私政策条款完整性检查
- 权限声明与功能一致性校验
- 数据收集行为合规评估
- 第三方SDK管理合规检查

评估维度覆盖：

| 评估维度 | 权重 | 检查项数 | 最低达标要求 |
|---------|------|---------|-------------|
| 隐私政策 | 20% | 12项 | 10项 |
| 告知同意 | 25% | 15项 | 12项 |
| 权限管理 | 20% | 10项 | 8项 |
| 数据安全 | 20% | 10项 | 8项 |
| 用户权利 | 15% | 8项 | 6项 |

### 3. 合规检测流水线（CI/CD集成）

将合规检测嵌入开发流水线，实现自动化持续监控。

```yaml
# .gitlab-ci.yml 示例
app-security-check:
  stage: test
  script:
    # 1. 静态权限检查
    - aapt dump permissions app/build/outputs/apk/release/app-release.apk > permissions.txt
    
    # 2. MobSF扫描
    - curl -F "file=@app-release.apk" http://mobsf:8000/api/v1/upload
    - curl -F "hash=$hash" http://mobsf:8000/api/v1/report_json > mobsf_report.json
    
    # 3. SDK合规检查
    - python scripts/check_sdk_compliance.py app-release.apk
    
    # 4. 隐私政策版本检查
    - python scripts/check_privacy_policy.py app/src/main/assets/privacy.html
    
    # 5. 生成合规报告
    - python scripts/generate_compliance_report.py
  artifacts:
    paths:
      - compliance_report.pdf
```

## 专项检测脚本

### 隐私政策完整性检查

```python
#!/usr/bin/env python3
"""隐私政策合规检查脚本"""
import re
import sys

def check_privacy_policy(html_content):
    checks = {
        '收集信息类型': r'收集.*信息|信息类型|数据类型',
        '收集目的': r'目的|用途|用于',
        '第三方共享': r'第三方|共享|提供.*第三方',
        '用户权利': r'删除|更正|注销|撤回',
        '联系方式': r'联系方式|邮箱|电话|地址',
        '存储期限': r'存储.*期限|保留.*时间|保存.*期限',
        '儿童保护': r'儿童|未成年人|14.*岁',
        '跨境传输': r'跨境|境外|海外|国外',
        'Cookie使用': r'Cookie|缓存.*技术',
        '政策更新': r'更新|变更|修改.*通知',
    }
    
    missing = []
    for name, pattern in checks.items():
        if not re.search(pattern, html_content, re.IGNORECASE):
            missing.append(name)
    
    return missing

# 使用
with open('privacy.html', 'r', encoding='utf-8') as f:
    content = f.read()
    
missing = check_privacy_policy(content)
if missing:
    print(f"缺少以下条款: {', '.join(missing)}")
else:
    print("基本条款完整")
```

### 权限最小化检查

```python
#!/usr/bin/env python3
"""检查APP权限是否违反最小必要原则"""

# 按APP类型定义必要权限白名单
NECESSARY_PERMISSIONS = {
    '地图导航': ['ACCESS_FINE_LOCATION', 'ACCESS_NETWORK_STATE', 'INTERNET'],
    '网络约车': ['ACCESS_FINE_LOCATION', 'ACCESS_NETWORK_STATE', 'INTERNET', 'READ_PHONE_STATE'],
    '即时通信': ['INTERNET', 'ACCESS_NETWORK_STATE', 'CAMERA', 'RECORD_AUDIO'],
    '网络购物': ['INTERNET', 'ACCESS_NETWORK_STATE'],
    '短视频': ['INTERNET', 'ACCESS_NETWORK_STATE', 'CAMERA', 'RECORD_AUDIO', 
               'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
}

SENSITIVE_PERMISSIONS = [
    'READ_CONTACTS', 'WRITE_CONTACTS',
    'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
    'CAMERA', 'RECORD_AUDIO',
    'READ_CALENDAR', 'WRITE_CALENDAR',
    'READ_CALL_LOG', 'WRITE_CALL_LOG',
    'BODY_SENSORS',
    'READ_SMS', 'SEND_SMS',
    'READ_EXTERNAL_STORAGE',
]

def check_permission_minimality(permissions, app_type):
    """检查权限最小化"""
    needed = set(NECESSARY_PERMISSIONS.get(app_type, set()))
    declared = set(permissions)
    
    # 识别非必要敏感权限
    non_essential_sensitive = declared.intersection(SENSITIVE_PERMISSIONS) - needed
    
    return non_essential_sensitive

# 使用示例
permissions = ['INTERNET', 'ACCESS_FINE_LOCATION', 'READ_CONTACTS', 'CAMERA']
app_type = '网络购物'
extra = check_permission_minimality(permissions, app_type)
print(f"非必要敏感权限: {extra}")  # {'READ_CONTACTS', 'CAMERA'}
```

## 检测报告范本

一个完整的APP合规检测报告应包含以下章节：

| 章节 | 内容 | 示例发现 |
|------|------|---------|
| APP基本信息 | 包名、版本、类型、大小 | com.example.app v3.2.1 |
| 权限分析 | 声明的权限列表、非必要权限 | 发现2项非必要权限 |
| 隐私政策 | 完整性、合规性评估 | 缺少儿童保护条款 |
| 数据采集 | 网络抓包分析结果 | 发现3个未披露的数据接收方 |
| SDK清单 | 集成的第三方SDK及版本 | 集成7个SDK，其中2个版本过期 |
| 动态行为 | 权限调用日志、后台活动 | 相机权限在非使用场景被调用 |
| 安全评估 | 加密、存储、传输安全 | HTTPS未启用证书校验 |
| 整改建议 | 优先级排列的整改项 | 高优先级：删除READ_CONTACTS权限 |

## 常用工具速查表

| 工具 | 安装方式 | 核心命令 | 合规用途 |
|------|---------|---------|---------|
| jadx | `brew install jadx` | `jadx-gui app.apk` | APK反编译查看代码 |
| aapt2 | Android SDK内置 | `aapt2 dump permissions` | 权限声明提取 |
| apktool | `brew install apktool` | `apktool d app.apk` | 资源文件提取 |
| mobsf | Docker | `docker run mobsf` | 自动化合规扫描 |
| frida | `pip install frida-tools` | `frida -U -f package` | 动态Hook行为监控 |
| mitmproxy | `brew install mitmproxy` | `mitmproxy -p 8888` | HTTPS流量分析 |
| adb | Android SDK内置 | `adb logcat -v time` | 实时日志监控 |
| objection | `pip install objection` | `objection -g package explore` | 运行时安全评估 |
