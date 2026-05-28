# SDK个人信息保护

## SDK数据收集风险概述

第三方SDK在APP中广泛使用（统计、广告、登录、支付、推送等），但SDK的数据收集行为常常超出APP开发者的控制范围，成为个人信息保护的灰色地带。2024年工信部通报的APP违规案例中，超过60%涉及第三方SDK的数据收集问题。

### 常见SDK合规风险

| 风险类型 | 具体表现 | 典型案例 |
|---------|---------|---------|
| 超范围收集 | SDK收集与自身功能无关的信息（设备信息、应用列表等） | 某广告SDK收集已安装应用列表用于竞品分析 |
| 未告知收集 | APP未在隐私政策中披露SDK采集行为 | 某推送SDK收集设备标识未在隐私政策中说明 |
| 私自共享数据 | SDK未经允许将数据传输至境外服务器 | 分析SDK默认将数据回传至海外总部服务器 |
| 持续后台采集 | 退出APP后SDK仍在采集数据 | 某广告SDK通过心跳机制常驻后台持续上报位置 |
| 权限不合理 | SDK要求非必需的敏感权限 | 某推送SDK要求读取通讯录权限 |
| SDK版本过旧 | 使用含有已知漏洞的SDK版本 | 某APP使用3年前的旧版SDK，存在Log4j漏洞 |
| SDK自更新 | SDK绕过应用商店自行更新代码逻辑 | 某热更新SDK可动态加载第三方代码 |

## SDK分类合规矩阵

不同类型的SDK在数据处理范围和合规要求上有显著差异：

| SDK类型 | 典型代表 | 常见收集数据 | 必要数据 | 非必要数据风险 | 合规等级 |
|---------|---------|-------------|---------|--------------|---------|
| 统计类 | 友盟+、Firebase、GrowingIO | 设备信息、事件埋点、会话时长 | 设备标识、页面访问事件 | 精确位置、通讯录 | 中风险 |
| 推送类 | 极光、个推、信鸽、Firebase Cloud Messaging | 设备标识、应用列表、网络状态 | 设备Token、推送通道标识 | 通讯录、精确位置、相册 | 高风险 |
| 广告类 | Google AdMob、穿山甲、腾讯广告、快手联盟 | 设备指纹、广告点击行为、位置、应用列表 | 广告ID、设备类型 | 精确位置、IMEI、通讯录 | 极高风险 |
| 支付类 | 微信支付、支付宝、银联 | 订单信息、设备指纹 | 订单号、金额 | 通讯录、相册、短信 | 低风险 |
| 社交登录类 | 微信OpenSDK、QQ互联、微博SDK、Google Sign-In | 用户标识、Token、社交关系 | 用户OpenID、AccessToken | 通讯录、位置、相册 | 低风险 |
| 安全类 | 极验、阿里云安全、腾讯安全 | 设备指纹、环境信息 | 设备环境参数 | 应用列表、通讯录 | 低风险 |
| 客服类 | 网易七鱼、美洽、智齿 | 用户聊天内容、设备信息 | 用户ID、消息内容 | 精确位置、通讯录、相册 | 中风险 |
| 地图类 | 高德、百度、腾讯地图 | 位置信息、搜索记录 | 当前位置、目的地 | 通讯录、短信 | 中风险 |

### 各类型SDK合规检查要点

**统计类SDK**：
- 应支持去标识化数据收集，避免收集精确位置
- 埋点数据应限制在功能分析必需范围内
- 用户可选择退出分析跟踪（Opt-out机制）

**推送类SDK**（监管重点）：
- 不得收集通讯录、短信等无关数据
- 2023年专项治理中，推送SDK是违规高发类型
- 应明确区分推送通道数据与营销数据

**广告类SDK**（最高风险）：
- 需获取用户对广告追踪的单独同意
- 不得使用不可重置的设备标识（IMEI）替代广告ID
- 必须遵守用户设置的"限制广告追踪"

**支付类SDK**：
- 数据收集范围最小化（仅支付订单信息）
- 支付数据不应与其他SDK共享
- 涉及金融敏感信息需加密传输

## SDKD数据收集行为分析技术

### 静态分析SDK源码中的API调用

```bash
# 1. 使用jadx反编译APK查看所有SDK类（macOS/Linux）
jadx -d output_dir app.apk
grep -r "TelephonyManager\|getDeviceId\|getImei" output_dir/ --include="*.java" | grep -v "R\$" 

# 2. 使用dex2jar+JD-GUI分析
d2j-dex2jar app.apk -o app.jar
# 在JD-GUI中浏览各SDK的敏感API调用

# 3. 使用第三方工具自动化分析SDK行为
# 使用MobSF (Mobile Security Framework)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# 上传APK/IPA后，在SDK分析模块查看结果
```

**静态分析重点检查的API调用**：

| 检测API | 指示的SDK行为 | 合规风险级别 |
|---------|-------------|-------------|
| TelephonyManager.getDeviceId() | 获取IMEI | 高（不可匿名化） |
| NetworkInterface.getHardwareAddress() | 获取MAC地址 | 高（不可重置） |
| WifiManager.getScanResults() | 扫描WiFi列表 | 中（可用于定位） |
| LocationManager.requestLocationUpdates() | 持续获取位置 | 高（需审查合理性） |
| PackageManager.getInstalledApplications() | 读取已安装应用列表 | 高（隐私敏感） |
| CameraManager.open() | 打开相机 | 中（需有真实场景） |
| AudioRecord.startRecording() | 录制音频 | 高（需单独同意） |
| ClipboardManager.getPrimaryClip() | 读取剪贴板内容 | 高（iOS 14+/Android 12+已限制） |

### 动态抓包监控SDK网络通信

```bash
# 1. 使用mitmproxy设置HTTPS代理（需安装CA证书）
mitmproxy -p 8888 --mode transparent

# 2. 配合adb设置系统代理
adb shell settings put global http_proxy 127.0.0.1:8888

# 3. 使用SSL Pinning绕过（仅用于合规审查测试）
# 方法A：使用Frida Hook绕过证书校验
frida -U -l ssl-pinning-bypass.js com.example.app

# 方法B：使用Objection（可自动绕过常见SSL Pinning）
objection -g com.example.app explore
objection> android sslpinning disable
```

**SDK通信分析关注点**：

| 分析维度 | 检测方法 | 发现问题的意义 |
|---------|---------|-------------|
| 目标域名 | 抓包查看SDK通讯的目标服务器域名 | 是否传输至境外服务器、是否默第三域名 |
| 传输内容 | 解码请求体/响应体中数据字段 | 是否传输了未声明的个人信息 |
| 传输频率 | 统计SDK发送心跳/数据上报的频率 | 是否存在非功能所需的频繁数据上报 |
| 传输时机 | 监控SDK在APP前后台状态下的传输行为 | 退出APP后是否有持续数据传输 |
| 加密方式 | 检查通讯是否使用HTTPS/TLS | 敏感信息是否明文传输 |

```bash
# 4. 使用PCAP统计SDK通信特征
tcpdump -i en0 host sdk.example.com -w sdk_traffic.pcap
tshark -r sdk_traffic.pcap -T fields -e ip.src -e ip.dst -e http.host | sort | uniq -c | sort -nr
```

### 使用Frida Hook SDK类的详细方法

```javascript
// Frida脚本：Hook Android SDK类，监控敏感数据访问
Java.perform(function() {
    // Hook TelephonyManager.getDeviceId
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
        var result = this.getDeviceId();
        // 获取调用栈，确定哪个SDK调用了该方法
        var stacktrace = Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()
        );
        send({
            'type': 'sensitive_api',
            'api': 'TelephonyManager.getDeviceId()',
            'value': result,
            'stack': stacktrace
        });
        console.log('[SDK Monitor] getDeviceId called by: ' + stacktrace.split('\n')[2]);
        return result;
    };

    // Hook 网络请求—监控SDK的数据传出
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        var url = request.url().toString();
        // 过滤SDK相关的请求
        if (url.indexOf('sdk') > -1 || url.indexOf('analytics') > -1 || url.indexOf('track') > -1) {
            send({
                'type': 'network_request',
                'url': url,
                'headers': request.headers().toString()
            });
            console.log('[SDK Network] ' + url);
        }
        return this.newCall(request);
    };

    // Hook SharedPreferences写入（监控SDK本地缓存数据）
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    SharedPreferences.edit.implementation = function() {
        var edit = this.edit();
        var original_putString = edit.putString;
        edit.putString = function(key, value) {
            if (key.indexOf('device') > -1 || key.indexOf('id') > -1 || key.indexOf('token') > -1) {
                send({
                    'type': 'local_storage',
                    'key': key,
                    'value': value,
                    'stack': Java.use('android.util.Log').getStackTraceString(
                        Java.use('java.lang.Exception').$new()
                    )
                });
            }
            return original_putString.call(this, key, value);
        };
        return edit;
    };
});
```

```bash
# 运行Frida Hook脚本
frida -U -l sdk_monitor.js com.example.app
```

### MobSF中SDK检测结果解读

| MobSF检测项 | 检测内容 | 解读方法 |
|------------|---------|---------|
| Trackers Detected | 检测集成的第三方追踪器SDK | 每个追踪器对应一个独立的数据接收方，需在隐私政策中披露 |
| Dangerous Permissions | SDK使用的危险权限 | 对比APP功能判断SDK权限是否"越界" |
| Network Analysis | SDK所有通信域名和协议 | 识别未在隐私政策中声明的数据传输目标 |
| Malware Check | SDK是否存在已知恶意行为 | 高风险（APK被植入恶意SDK的常见手段） |
| Code Analysis | SDK代码中的敏感API调用 | 如SDK在非UI线程访问Camera/Location则高度可疑 |

## 最新监管动态：工信部SDK专项整治

### 2022-2024年SDK专项通报

| 通报批次 | 时间 | 通报SDK数量 | 主要问题 |
|---------|------|------------|---------|
| 2022年第1批 | 2022年2月 | 14款SDK | 违规收集个人信息、超范围收集 |
| 2022年第2批 | 2022年8月 | 10款SDK | SDK违规处理用户个人信息 |
| 2023年第1批 | 2023年3月 | 12款SDK | SDK强制索权、违规收集、未同步隐私政策更新 |
| 2023年第2批 | 2023年8月 | 16款SDK | SDK后台自启动、数据回传至境外、使用不可重置标识 |
| 2024年第1批 | 2024年3月 | 20款SDK | SDK收集设备参数违规、隐私政策不符、超范围索权 |

### 被通报的典型SDK违规案例

| SDK名称 | 通报批次 | 违规行为 | 处罚措施 |
|---------|---------|---------|---------|
| 某推送SDK | 2022年2月 | 未经用户同意收集IMEI、IMSI、应用列表 | 通报整改，下架相关APP |
| 某广告SDK | 2022年8月 | 强制索取位置权限、读写存储权限 | 通报整改，SDK停止更新 |
| 某统计SDK | 2023年3月 | SDK收集信息超出隐私政策声明范围 | 限期整改，APP需更新隐私政策 |
| 某短信SDK | 2023年8月 | SDK在后台读取通话记录和通讯录 | 下架处理，追究相关责任 |
| 某推送合流SDK | 2024年3月 | 将数据回传至境外服务器，未告知用户 | 责令停止数据出境，限期整改 |

### SDK专项整治趋势

| 时间 | 监管重点 | 执法力度 |
|------|---------|---------|
| 2021年前 | SDK基本无单独监管 | 仅关注APP本身 |
| 2021-2022 | SDK开始被纳入监管视线 | 约谈+通报 |
| 2022-2023 | SDK违规列为单独处罚项 | 通报+下架+罚款 |
| 2023-2024 | SDK全链条合规（数据收集→传输→存储→删除） | 多部门联合执法+常态化检查 |

## SDK 版本管理

### 自动化版本更新与合规检查

```yaml
# .github/dependabot.yml — 自动检测SDK版本更新
version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "Asia/Shanghai"
    open-pull-requests-limit: 10
    labels:
      - "dependency"
      - "sdk-update"
    # 为SDK更新添加合规审查标签
    reviewers:
      - "team-security"
      - "team-legal"
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

```json
// renovate.json — Renovate配置示例
{
  "extends": ["config:base"],
  "packageRules": [
    {
      "updateTypes": ["major", "minor"],
      "labels": ["sdk-update", "needs-review"],
      "reviewers": ["team:security"],
      "prBodyNotes": [
        "此更新涉及SDK版本变更，请务必审查：",
        "1. 隐私政策是否需要同步更新",
        "2. SDK的权限声明是否有变化",
        "3. SDK收集的数据类型是否增加"
      ]
    },
    {
      "matchUpdateTypes": ["patch"],
      "labels": ["sdk-update", "auto-merge"],
      "automerge": true
    }
  ]
}
```

### SDK版本升级合规检查清单

| 检查项 | 检查方法 | 必须更新隐私政策？ |
|--------|---------|-----------------|
| 新增权限声明 | 比较新旧版本的AndroidManifest差异 | 是 |
| 新增数据收集字段 | 检查SDK changelog和隐私政策变更 | 是 |
| 新增数据传输目标 | DNS抓包分析新版本通信域名 | 是 |
| 数据处理方式变化 | 审查SDK新版本的数据聚合/去标识化方式 | 根据变化程度 |
| 安全修复 | 检查CVE公告和修复内容 | 否（推荐提及） |
| API调用行为变更 | 运行新版本SDK进行动态监控 | 如果涉及数据收集变化则是 |
| 子处理者变化 | 检查SDK隐私政策中的子处理者列表 | 是 |
| 数据跨境变化 | 确认新版本的数据存储位置 | 是 |

## SDK 隐私政策自动比对

```bash
# 使用git diff监控SDK隐私政策变更
# 步骤1：定期下载SDK隐私政策并提交到版本库
curl -s https://example-sdk.com/privacy > sdk_privacy/sdk_name_$(date +%Y%m%d).md
git add sdk_privacy/
git commit -m "chore: update SDK privacy policy snapshot $(date +%Y%m%d)"

# 步骤2：与上次版本比较
git diff HEAD~1 -- sdk_privacy/sdk_name_*.md

# 步骤3：自动化差异检测脚本
diff --git a/sdk_privacy/sdk_name_20240601.md b/sdk_privacy/sdk_name_20240615.md
index abc123..def456 100644
--- a/sdk_privacy/sdk_name_20240601.md
+++ b/sdk_privacy/sdk_name_20240615.md
@@ -5,6 +5,8 @@
 +新增收集：应用安装列表、WiFi扫描结果
 +新增共享：与关联公司XX共享设备信息用于广告归因
```

### SDK隐私政策变更自动告警

```python
#!/usr/bin/env python3
"""SDK隐私政策变更监控脚本"""
import hashlib
import requests
import smtplib
from datetime import datetime

SDKS = {
    "sdk_a": "https://sdk-a.com/privacy",
    "sdk_b": "https://sdk-b.com/privacy-policy.html",
}

def check_sdk_privacy_changes():
    for sdk_name, url in SDKS.items():
        response = requests.get(url, timeout=10)
        current_hash = hashlib.sha256(response.text.encode()).hexdigest()
        
        # 读取上次保存的哈希值
        try:
            with open(f".sdk_privacy_hash/{sdk_name}.hash", "r") as f:
                last_hash = f.read().strip()
        except FileNotFoundError:
            last_hash = ""
        
        if current_hash != last_hash:
            print(f"[ALERT] {sdk_name} 隐私政策已变更!")
            # 保存新哈希
            with open(f".sdk_privacy_hash/{sdk_name}.hash", "w") as f:
                f.write(current_hash)
            # 触发告警流程
            notify_team(sdk_name, url)
        else:
            print(f"[OK] {sdk_name} 隐私政策无变更")

def notify_team(sdk_name, url):
    """发送通知给合规团队"""
    # 实现发送邮件/钉钉/飞书/企业微信通知
    pass

if __name__ == "__main__":
    check_sdk_privacy_changes()
```

## SDK 最小化集成

### 如何裁剪SDK中不必要的权限和功能模块

```xml
<!-- AndroidManifest.xml — 使用tools:node移除SDK声明的非必要权限 -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- 使用tools:node="remove"移除SDK声明的非必要权限 -->
    <uses-permission
        android:name="android.permission.ACCESS_FINE_LOCATION"
        tools:node="remove" />
    <uses-permission
        android:name="android.permission.READ_CONTACTS"
        tools:node="remove" />
    <uses-permission
        android:name="android.permission.READ_EXTERNAL_STORAGE"
        tools:node="remove" />
</manifest>
```

**SDK裁剪策略**：

| 裁剪方式 | 实现方法 | 风险等级 |
|---------|---------|---------|
| 权限移除清单 | 在AndroidManifest中使用tools:node移除SDK声明的不必要权限 | 低——但需验证移除后SDK功能是否正常 |
| 功能模块禁用 | 调用SDK初始化方法时传入配置参数禁用非必要模块 | 低——需参考SDK文档 |
| ProGuard混淆排除 | 仅保留使用到的SDK类，移除未使用的类和方法 | 中——可能导致编译错误 |
| 动态加载替代 | 仅在需要时初始化SDK，非必需场景不解码SDK代码 | 低——但需测性能影响 |
| 部分集成 | 仅引入SDK的AAR中必要的模块，裁剪非必需资源 | 中——需持续维护 |

```kotlin
// Kotlin示例：SDK初始化时仅启用必要模块
class SDKIntegrationManager(private val context: Context) {
    
    fun initMinimalAnalyticsSDK() {
        AnalyticsSDK.init(
            context,
            AnalyticsConfig().apply {
                // 禁用非必要功能模块
                enableCrashReport = true        // 必需 — 错误分析
                enableAutoTrack = false          // 禁用自动页面追踪
                enableDeviceInfoCollection = false // 禁用设备信息收集（合规最优）
                enableLocationCollection = false   // 禁用位置收集
                enableUserIdentifier = true       // 仅允许业务账号关联
                // 设置数据上报策略
                uploadStrategy = UploadStrategy.WIFI_ONLY // 仅WiFi上传
                dataRetentionDays = 30            // 数据保留30天自动清理
            }
        )
    }
}
```

## SDK 合规评分卡

### SDK评估打分表（满分100分）

| 评估维度 | 权重 | 评分标准（满分） | 说明 |
|---------|------|----------------|------|
| **一、数据收集** | 30分 | | |
| 数据最小化 | 15分 | 仅收集功能必需数据（15分）；有少量非必需数据（8分）；明显超范围（0分） | 核对SDK文档与实际收集行为 |
| 权限合理性 | 10分 | 权限列表与功能匹配（10分）；有1-2项不合理权限（5分）；多项不合理权限（0分） | 对比AndroidManifest.xml |
| 数据去标识化 | 5分 | 所有数据均已去标识化（5分）；部分未去标识（2分）；直接收集原始标识（0分） | 检查数据传输内容 |
| **二、知情同意** | 20分 | | |
| 隐私政策透明度 | 10分 | 明确说明收集类型/目的/共享（10分）；说明不清（5分）；未披露（0分） | 审查SDK独立隐私政策 |
| 用户控制权 | 10分 | 提供Opt-out接口（10分）；限部分退出（5分）；无法退出（0分） | 测试SDK的数据收集开关 |
| **三、安全保障** | 25分 | | |
| 传输加密 | 10分 | 全链路HTTPS + 证书固定（10分）；仅HTTPS（6分）；混合明文传输（0分） | 抓包验证 |
| 数据加密存储 | 5分 | 数据加密存储（5分）；明文存储（0分） | 本地存储分析 |
| 安全认证 | 5分 | 有ISO 27701/SOC2 Type II认证（5分）；有自评估报告（2分）；无认证（0分） | 索取认证报告 |
| 漏洞响应 | 5分 | 有CVE监控和快速修复机制（5分）；有响应但速度慢（2分）；无机制（0分） | 查询历史漏洞响应时间 |
| **四、合规管理** | 25分 | | |
| 数据地图 | 10分 | 提供完整数据流向图（10分）；部分提供（5分）；未提供（0分） | 审查SDK文档 |
| 审计支持 | 8分 | 支持客户审计（8分）；提供审计报告（4分）；不支持（0分） | 确认合同条款 |
| 合同条款 | 7分 | DPA条款完整覆盖PIPL要求（7分）；部分覆盖（3分）；标准条款需补充（0分） | 审查SDK服务协议 |
| **加分项** | +10分 | 提供本地化部署方案（+5分）；支持数据保留期限设置（+3分）；提供SDK合规培训材料（+2分） | |

**评分等级**：
- A级（90-100分）：优质合规SDK，推荐首选集成
- B级（70-89分）：基本合规，需补充合同条款和用途说明
- C级（50-69分）：合规风险较高，建议限期替换
- D级（<50分）：不合规SDK，应立即停止集成

## SDK数据处理协议（DPA）核心条款

| 条款 | 内容要求 | 法律依据 |
|------|---------|---------|
| 处理目的 | 明确SDK功能所需的特定数据处理目的 | PIPL第21条 |
| 数据范围 | 逐项列出SDK可收集和处理的个人信息字段 | PIPL第6条（最小必要） |
| 处理限制 | 禁止SDK将数据用于自身商业目的（如广告、用户画像） | PIPL第21条 |
| 安全措施 | SDK须采取的技术和组织安全措施标准清单 | PIPL第51条 |
| 子处理者管理 | SDK更换子处理者需提前通知并获得APP开发者同意 | PIPL第21条 |
| 安全事件通报 | 安全事件发生后24小时内通报APP开发者 | 《数据安全法》第29条 |
| 审计权 | APP开发者有权审计SDK的数据处理活动 | PIPL第21条 |
| 数据删除 | 合同终止后SDK须在30日内删除所有数据 | PIPL第47条 |
| 赔偿责任 | 因SDK违规导致的损失由SDK提供商承担连带责任 | PIPL第69条 |
| 跨境传输 | 涉及数据出境的，需明确传输方式和合规依据 | PIPL第38条 |

## SDK合规清单总表

| 合规动作 | 执行频率 | 责任方 | 交付物 |
|---------|---------|-------|-------|
| SDK选型评估 | 每次集成新SDK时 | 安全团队+法务 | SDK合规评分卡 |
| 隐私政策审查 | 每次集成新SDK时 | 法务团队 | SDK隐私政策差异分析报告 |
| DPA签署 | 每次集成新SDK时 | 采购/法务 | 已签署的DPA |
| 权限声明审查 | 每次SDK版本更新 | 开发团队 | SDK权限变更对比表 |
| 数据抓包验证 | 初始集成+每次大版本更新 | 安全测试团队 | SDK网络通信分析报告 |
| 隐私政策同步更新 | SDK数据处理变更时 | 法务团队 | 更新后的APP隐私政策 |
| SDK行为审计 | 每季度 | 安全团队 | SDK合规审计报告 |
| SDK版本更新 | 每月 | 开发团队 | SDK版本清单+更新记录 |
| SDK风险评估复审 | 每年 | 安全团队+法务 | SDK风险评估报告 |
