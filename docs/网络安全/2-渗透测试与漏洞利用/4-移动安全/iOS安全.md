# iOS安全

## 概述

iOS因其严格的沙盒机制和代码签名策略，被认为比Android更安全。但随着iOS安全研究的深入，研究人员发现通过越狱、动态Hook和二进制分析等技术，仍然可以对iOS应用进行深度安全评估。iOS安全分析涵盖IPA逆向、ARM64反汇编、动态注入、沙盒逃逸和隐私泄露检测等方向。

## IPA文件结构

IPA（iOS App Store Package）本质是一个ZIP压缩包：

```text
App.ipa
└── Payload/
    └── App.app/              # 应用Bundle
        ├── App                # 可执行文件（ARM64 Mach-O）
        ├── Info.plist         # 应用信息配置文件
        ├── embedded.mobileprovision  # 配置文件（签名证书信息）
        ├── _CodeSignature/    # 代码签名目录
        │   └── CodeResources
        ├── Frameworks/        # 内嵌动态库
        ├── PlugIns/           # App Extension
        └── Assets.car         # 资源文件
```

### Info.plist关键字段

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Bundle标识符 -->
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    
    <!-- 传输安全设置 -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>  <!-- 允许非HTTPS → 不安全！ -->
    </dict>
    
    <!-- 权限声明 -->
    <key>NSFaceIDUsageDescription</key>
    <string>需要Face ID进行身份验证</string>
    <key>NSLocationAlwaysUsageDescription</key>
    <string>需要位置信息</string>
    
    <!-- URL Schemes -->
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>myapp</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

## 静态分析

### 二进制分析

ARM64 Mach-O可执行文件分析：

```bash
# 查看文件信息
file App.ipa/Payload/App.app/App

# 使用class-dump导出Objective-C头文件
class-dump -H App -o headers/

# 使用nm查看符号表
nm App | grep -i "encrypt\|decrypt\|password\|token"

# 使用otool查看依赖库
otool -L App

# 查看加密信息
otool -l App | grep -A 4 LC_ENCRYPTION_INFO

# 查看Section
otool -s __TEXT __text App > disasm.txt

# 检查PIE（位置无关可执行文件）
otool -h App | grep PIE
```

### Hopper/Ghidra反编译

```bash
# Hopper Disassembler（macOS GUI工具）
# 打开可执行文件，选择ARM64架构
# 功能：反编译伪代码、控制流图、交叉引用分析

# Ghidra（跨平台开源）
./ghidraRun

# 分析步骤：
# 1. 创建项目
# 2. 导入Mach-O文件
# 3. 自动分析（分析选项全选）
# 4. 定位关键函数
# 5. 使用符号恢复和类型重建
```

### Objective-C Runtime分析

```bash
# 使用nm导出Objective-C类和方法
nm App | grep "OBJC_CLASS"

# 使用class-dump-z显示类继承关系
class-dump-z App

# 使用strings搜索敏感字符串
strings App | grep -i "password\|token\|secret\|api.key\|https://"
strings App | grep -i "jailbreak\|cydia\|substrate\|frida"

# 使用iOS Runtime Headers（已越狱设备）
# /System/Library/Frameworks/下的所有私有Framework头部
```

### 二进制保护检查

```bash
# 检查是否加密（App Store分发的应用默认加密）
otool -l App | grep -A 4 LC_ENCRYPTION_INFO | grep crypt

# 解密（需要越狱设备或使用frida-ios-dump）
# 使用Clutch（越狱设备）
Clutch -d com.example.app

# 使用frida-ios-dump
frida-ios-dump com.example.app
```

## 动态分析

### Frida for iOS

```javascript
// Hook Objective-C方法
if (ObjC.available) {
    // Hook NSUserDefaults
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    NSUserDefaults['- objectForKey:'] = function(key) {
        console.log('[+] NSUserDefaults objectForKey: ' + key);
        var result = this['- objectForKey:'](key);
        if (result !== null) {
            console.log('[+] Value: ' + result.toString());
        }
        return result;
    };
    
    // Hook NSURLSession网络请求
    var NSURLSession = ObjC.classes.NSURLSession;
    NSURLSession['- dataTaskWithRequest:completionHandler:'] = function(request, handler) {
        var url = request.URL().absoluteString();
        console.log('[+] Request URL: ' + url);
        console.log('[+] HTTPMethod: ' + request.HTTPMethod());
        
        if (request.HTTPBody()) {
            var body = NSString.alloc().initWithData_encoding_(request.HTTPBody(), 4);
            console.log('[+] Body: ' + body.toString());
        }
        
        return this['- dataTaskWithRequest:completionHandler:'](request, handler);
    };
    
    // Hook Keychain访问
    var SSKeychain = ObjC.classes.SSKeychain;
    if (SSKeychain) {
        SSKeychain['+ passwordForService:account:'] = function(service, account) {
            console.log('[+] Keychain access - Service: ' + service + ', Account: ' + account);
            return this['+ passwordForService:account:'](service, account);
        };
    }
}
```

### Frida操作实例

```bash
# 连接iOS设备
frida -U -f com.example.app -l script.js

# 使用Frida CLI探索
frida -U com.example.app

# 枚举所有类
ObjC.enumerateLoadedClasses({
    onMatch: function(name) { console.log(name); },
    onComplete: function() {}
});

# 枚举所有方法（特定类）
var methods = ObjC.classes.ViewController.$methods;
methods.forEach(function(m) { console.log(m); });

# 修改NSBundle信息（绕过检测）
var NSBundle = ObjC.classes.NSBundle;
NSBundle['- bundleIdentifier'] = function() {
    return 'com.apple.mobilesafari';
};
```

### Theos Tweak开发

Theos是iOS越狱插件开发工具集：

```makefile
# Makefile
TARGET := iphone:clang:latest:7.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AppMonitor
AppMonitor_FILES = Tweak.x
AppMonitor_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
```

```objc
// Tweak.xm - Hook应用方法
%hook ViewController

- (void)viewDidLoad {
    %orig;  // 调用原始方法
    NSLog(@"[+] ViewController loaded, monitoring security");
    
    // 添加检测逻辑
    UIAlertController *alert = [UIAlertController 
        alertControllerWithTitle:@"Security Notice" 
        message:@"App is being monitored" 
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
}

- (NSString *)getSecretKey {
    NSLog(@"[+] Intercepted getSecretKey call");
    return @"INTERCEPTED_KEY";  // 篡改返回值
}

%end
```

## 越狱与检测绕过

### 越狱检测方法

```objc
// 常见越狱检测方法
@implementation JailbreakDetection

+ (BOOL)isJailbroken {
    // 1. 文件系统检查
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Substrate.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/private/var/tmp/cydia.log"
    ];
    
    for (NSString *path in jailbreakPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    
    // 2. fork()测试（越狱后可fork进程）
    int pid = fork();
    if (pid == 0 || pid > 0) {
        waitpid(pid, NULL, 0);
        return YES;  // fork成功 = 越狱
    }
    
    // 3. dylib注入检测
    // 检查是否加载了MobileSubstrate
    NSArray *loadedLibs = [NSClassFromString(@"NSBundle") 
        performSelector:@selector(allFrameworks)];
    for (NSBundle *bundle in loadedLibs) {
        if ([[bundle bundlePath] containsString:@"MobileSubstrate"]) {
            return YES;
        }
    }
    
    // 4. Sandbox完整性检测
    // 尝试写入系统目录
    NSError *error = nil;
    NSString *testPath = @"/private/test_write";
    [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }
    
    return NO;
}

@end
```

### 越狱检测绕过

```javascript
// Frida绕过越狱检测
if (ObjC.available) {
    // 绕过文件检测
    var NSFileManager = ObjC.classes.NSFileManager;
    NSFileManager['- fileExistsAtPath:'] = function(path) {
        var jailbreakPaths = [
            '/Applications/Cydia.app', '/bin/bash', '/usr/sbin/sshd',
            '/private/var/lib/apt/', '/etc/apt', '/Library/MobileSubstrate/'
        ];
        
        if (jailbreakPaths.contains(path)) {
            console.log('[+] Blocked jailbreak path check: ' + path);
            return false;
        }
        return this['- fileExistsAtPath:'](path);
    };
    
    // 绕过fork检测
    var NSTask = ObjC.classes.NSTask;
    if (NSTask) {
        NSTask['- launch'] = function() {
            console.log('[+] Blocked NSTask.launch');
            return;
        };
    }
    
    // 绕过dylib注入检测
    var NSBundle = ObjC.classes.NSBundle;
    NSBundle['- executablePath'] = function() {
        var orig = this['- executablePath']();
        console.log('[+] Executable path: ' + orig);
        return orig;
    };
}
```

## 安全存储机制

### Keychain

```objc
// Keychain安全存储
#import <Security/Security.h>

// 存储敏感数据
- (void)saveToKeychain:(NSString *)data forKey:(NSString *)key {
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrAccount: key,
        (id)kSecAttrService: @"com.example.app",
        (id)kSecValueData: [data dataUsingEncoding:NSUTF8StringEncoding],
        (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        (id)kSecAttrAccessGroup: @"ABCD123456.com.example.shared"
    };
    
    // 先删除旧数据
    SecItemDelete((CFDictionaryRef)query);
    // 插入新数据
    OSStatus status = SecItemAdd((CFDictionaryRef)query, NULL);
}

// 读取Keychain
- (NSString *)readFromKeychain:(NSString *)key {
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrAccount: key,
        (id)kSecAttrService: @"com.example.app",
        (id)kSecReturnData: (id)kCFBooleanTrue,
        (id)kSecMatchLimit: (id)kSecMatchLimitOne
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess) {
        NSData *data = (__bridge NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}
```

### DataVault

iOS专用安全存储方案：

```objc
// 使用DataVault保护敏感数据
// 需导入DataVault.framework

DVSecureData *secureData = [[DVSecureData alloc] init];
[secureData setObject:@"sensitive_token" forKey:@"api_token"];
[secureData setObject:@"encryption_key_123" forKey:@"enc_key"];

// 数据在内存中进行加密
// 进程退出后自动清除
```

## 企业部署安全

### OTA分发

```xml
<!-- OTA (Over-The-Air) 分发 plist -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>https://cdn.company.com/app.ipa</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>com.company.app</string>
                <key>bundle-version</key>
                <string>1.0.0</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>Corporate App</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

### 企业签名滥用

- **Super Signature**：企业证书签名任意应用
- **重签名攻击**：使用泄露的企业证书重打包恶意应用
- **MDM分发**：通过MDM强制安装未经审核的应用

## 参考资源

- [Frida iOS文档](https://frida.re/docs/ios/)
- [Theos](https://theos.dev/)
- [iOS Security Guide (Apple)](https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf)
- [OWASP iOS Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)
