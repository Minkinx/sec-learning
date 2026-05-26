# Android逆向

## 概述

Android逆向工程是移动安全分析的核心技术，广泛应用于恶意软件分析、漏洞挖掘、应用安全评估和隐私合规检测。逆向分析包括静态分析（代码审查、资源分析）和动态分析（运行时监控、Hook拦截）两大方向。

## APK文件结构

APK（Android Package Kit）是一个ZIP压缩包，包含以下核心文件：

```text
app.apk
├── AndroidManifest.xml      # 应用清单（二进制XML）
├── classes.dex              # DEX字节码（Dalvik Executable）
├── classes2.dex             # 多DEX（应用过大时拆分）
├── resources.arsc           # 编译后的资源文件
├── res/                     # 原始资源文件
│   ├── layout/              # UI布局文件
│   ├── drawable/            # 图片资源
│   └── values/              # 字符串/颜色等常量
├── lib/                     # 原生库
│   ├── armeabi-v7a/
│   ├── arm64-v8a/
│   └── x86/
├── assets/                  # 原始资源（不编译）
├── META-INF/                # 签名和证书信息
│   ├── MANIFEST.MF
│   ├── CERT.RSA
│   └── CERT.SF
└── kotlin/                  # Kotlin元数据
```

### AndroidManifest.xml关键字段

```xml
<!-- 权限声明 -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

<!-- 四大组件 -->
<activity android:name=".MainActivity" android:exported="true" />
<service android:name=".BackgroundService" android:exported="false" />
<receiver android:name=".BootReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
<provider android:name=".FileProvider"
    android:authorities="com.app.fileprovider"
    android:exported="false" />

<!-- 调试标志 -->
android:debuggable="true"    <!-- 危险！ -->
android:allowBackup="true"   <!-- 允许备份 -->
```

## 静态分析工具

### APKTool

APKTool用于反编译APK为Smali代码，以及重新打包APK：

```bash
# 反编译APK
apktool d app.apk -o app_decoded/

# 反编译（不反编译DEX）
apktool d app.apk -s -o app_res/

# 重新打包
apktool b app_decoded/ -o app_modified.apk

# 生成新签名
jarsigner -keystore my.keystore -storepass password \
  -sigalg SHA1withRSA -digestalg SHA1 app_modified.apk alias_name

# 安装
adb install app_modified.apk
```

### JADX

JADX提供一键反编译，将DEX转换为可读的Java源代码：

```bash
# CLI使用
jadx -d output_dir app.apk

# 显示完整反编译过程
jadx --show-bad-code -d output app.apk

# 只反编译指定包
jadx -d output --include-classes com.example app.apk

# GUI模式（直观，推荐）
jadx-gui app.apk
```

JADX功能特性：
- 支持多DEX文件合并反编译
- 支持AAR/AAB格式
- 显示混淆代码的恢复建议
- 交叉引用跳转
- 全局搜索

### dex2jar + JD-GUI

传统逆向工具链：

```bash
# DEX转换为JAR
d2j-dex2jar app.apk -o app.jar

# 使用JD-GUI打开JAR文件
jd-gui app.jar
```

### Smali分析

Smali是DEX字节码的人类可读表示形式：

```smali
# Smali基本语法
.class public Lcom/example/app/MainActivity;
.super Landroidx/appcompat/app/AppCompatActivity;

# 方法定义
.method public onClick(Landroid/view/View;)V
    .registers 3
    
    # 获取当前实例
    iget-object v0, p0, Lcom/example/app/MainActivity;->context:Landroid/content/Context;
    
    # 创建Intent
    new-instance v1, Landroid/content/Intent;
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    
    # 启动Activity
    invoke-virtual {v0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    
    return-void
.end method
```

## 动态分析

### Frida Hook框架

Frida是跨平台的Hook框架，支持JavaScript和Python API：

```python
# Python脚本：Hook Android方法
import frida

device = frida.get_usb_device()
session = device.attach("com.example.app")

script = session.create_script("""
    // Hook Activity.onCreate
    var Activity = Java.use('android.app.Activity');
    Activity.onCreate.implementation = function(savedInstanceState) {
        console.log('[+] Activity.onCreate called');
        console.log('[+] Class name: ' + this.getClass().getName());
        this.onCreate(savedInstanceState);
    };
    
    // Hook String比较
    var String = Java.use('java.lang.String');
    String.equals.implementation = function(str) {
        if (str != null) {
            console.log('[+] String.equals: ' + this.toString() + ' vs ' + str.toString());
        }
        return this.equals(str);
    };
    
    // Hook加密操作
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log('[+] Cipher.doFinal called, data length: ' + data.length);
        var result = this.doFinal(data);
        return result;
    };
    
    // Hook SharedPreferences（获取存储的Token）
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    SharedPreferences.getString.implementation = function(key, defValue) {
        console.log('[+] SharedPreferences.get: ' + key + ' => ' + this.getString(key, defValue));
        return this.getString(key, defValue);
    };
""")

script.load()
input()  # 保持运行
```

### Frida常见Hook场景

```javascript
// Hook密码验证
Java.perform(function() {
    var LoginActivity = Java.use('com.example.app.LoginActivity');
    LoginActivity.checkPassword.implementation = function(password) {
        console.log('[+] Password input: ' + password);
        send({type: 'password', data: password});
        return true;  // 绕过密码验证
    };
});

// Hook SSL Pinning绕过
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    // 实现自定义TrustManager
});

// Hook Root检测
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[+] RootBeer check blocked');
        return false;  // 绕过Root检测
    };
});

// Hook Native方法
var MyClass = Java.use('com.example.app.MyClass');
MyClass.nativeMethod.implementation = function() {
    console.log('[+] Native method called');
    // Frida也可以Hook Native层（使用Interceptor）
};
```

### Objection

Objection是基于Frida的移动安全探索工具：

```bash
# 连接应用
objection -g com.example.app explore

# 禁用SSL Pinning
android sslpinning disable

# 列出所有Activity
android hooking list activities

# 列出所有Service
android hooking list services

# 搜索类
android hooking search classes com.example

# Hook类方法
android hooking watch class com.example.app.LoginActivity

# 导出KeyStore
android keystore list

# 查看SharedPreferences
android sharedpreferences list
```

## 防篡改与绕过

### Root检测绕过

Frida脚本绕过Root检测：

```javascript
Java.perform(function() {
    // 方法1：Hook RootBeer
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    
    // 方法2：Hook文件检测
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ['/su', '/system/bin/su', '/system/xbin/su', 
                      '/system/app/Superuser.apk', '/data/local/tmp'];
        if (blocked.some(p => path.toLowerCase().includes(p))) {
            return false;
        }
        return this.exists();
    };
    
    // 方法3：Hook execute
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        var cmdStr = JSON.stringify(cmd);
        if (cmdStr.includes('which su') || cmdStr.includes('test-root')) {
            return null;
        }
        return this.exec(cmd);
    };
});
```

### 模拟器检测绕过

```javascript
Java.perform(function() {
    // Hook系统属性
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.011/123456:user/release-keys';
    Build.MODEL.value = 'Pixel 2';
    Build.MANUFACTURER.value = 'Google';
    
    // Hook TelephonyManager
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.implementation = function() {
        return '352756100123456';  // 伪造IMEI
    };
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        return 'Test Network';
    };
});
```

### 重新打包与重签名

```bash
# 1. 反编译
apktool d app.apk -o tmp/

# 2. 修改Smali代码或资源
# 3. 移除签名验证（删除/修改META-INF中的检查代码）
# 4. 重新打包
apktool b tmp/ -o patched.apk

# 5. 生成新签名
keytool -genkey -alias release -keystore release.keystore \
  -keyalg RSA -keysize 2048 -validity 3650 -storepass password

jarsigner -keystore release.keystore -storepass password \
  -sigalg SHA1withRSA -digestalg SHA1 patched.apk release

# 6. 安装前需卸载原版（签名不同）
adb uninstall com.example.app
adb install patched.apk
```

## 保护与防御

### 代码混淆

```text
# ProGuard配置
-keepclassmembers class com.example.utils.Crypto {
    public static byte[] encrypt(byte[]);
}
-keep class com.example.model.** { *; }

-dontwarn com.google.**
-optimizationpasses 5
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-allowaccessmodification
-repackageclasses ''

# DexGuard（商业ProGuard升级版）
# 支持：字符串加密、类加密、反射保护、完整性校验
```

### 完整性校验

```java
// APK签名校验
public class IntegrityCheck {
    public static boolean verifySignature(Context context) {
        try {
            PackageInfo pkgInfo = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 
                    PackageManager.GET_SIGNATURES);
            
            byte[] signature = pkgInfo.signatures[0].toByteArray();
            String expectedHash = "已知的签名哈希";
            String actualHash = sha256(signature);
            
            return expectedHash.equals(actualHash);
        } catch (Exception e) {
            return false;
        }
    }
}
```

### 安全存储

```java
// 使用Android Keystore系统
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);

// 生成密钥（存储在硬件安全模块中）
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "app_key", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .build();

KeyGenerator kg = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
kg.init(spec);
kg.generateKey();
```

## 参考资源

- [Frida官方文档](https://frida.re/docs/home/)
- [Objection](https://github.com/sensepost/objection)
- [JADX](https://github.com/skylot/jadx)
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
