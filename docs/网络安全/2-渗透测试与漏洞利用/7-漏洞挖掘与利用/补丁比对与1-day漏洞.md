# 补丁比对与1-day漏洞

## 概述

补丁比对（Patch Diffing）是通过分析软件更新（补丁）前后的二进制差异来定位安全修复位置的技术。安全研究人员通过比较补丁前后文件的变化，发现被修复的漏洞并编写针对未打补丁系统的Exploit。1-day漏洞指已知但尚未被广泛修复的漏洞，是攻防对抗中的关键窗口期。

## 补丁比对技术

### 比对方法

```text
# 补丁比对三种主要方法

1. 二进制比对（BinDiff）
   - 比较两个二进制文件的函数级差异
   - 使用图同构算法匹配相似函数
   - 适用于无符号的原始二进制

2. 源码级比对（适用于有源码的情况）
   - diff/patch命令
   - Git比较

3. 动态比对
   - 比较补丁前后执行路径差异
   - 监控系统调用和API调用变化
```

### BinDiff使用

```bash
# BinDiff需要IDA Pro或Ghidra配合

# 1. 生成原始文件的IDB
ida64 -B -A vulnerable.dll

# 2. 生成补丁后文件的IDB
ida64 -B -A patched.dll

# 3. 在IDA中打开BinDiff
File → BinDiff → Compare Databases
# 选择两个IDB文件

# 4. 分析结果
# BinDiff输出信息：
# - Matching Functions（匹配函数）
# - Primary Unmatched（仅原始文件有）
# - Secondary Unmatched（仅补丁文件有）
# - Changed Functions（代码发生变化的函数）
```

### BinDiff结果解读

```text
# 关键指标
- Similarity (0.0-1.0): 函数相似度
- Confidence (0.0-1.0): 匹配可信度
- Address: 函数地址

# 关注重点
- Similarity < 1.0 的函数（代码修改）
- 新增函数（可能添加了安全检测）
- 删除函数（功能移除或重构）
- 边界附近的匹配（误匹配修正）

# 安全相关函数
- 涉及内存操作（memcpy, strcpy → memmove, strncpy）
- 涉及输入验证
- 涉及权限检查
- 涉及加密/解密
```

### Diaphora工具

Diaphora是开源版BinDiff替代方案，支持IDA和Ghidra：

```bash
# 在IDA中安装Diaphora
# 1. 将diaphora.py复制到IDA plugins目录
# 2. 重启IDA
# 3. File → Run Script → diaphora.py

# Diaphora导出
# 打开原始二进制 → Run Diaphora → Export
# 打开补丁后二进制 → Run Diaphora → Import previous export

# Diaphora特点
# - 多种匹配算法（执行图、哈希、汇编等价）
# - 支持批量比对
# - 开源免费
# - 报告生成
```

## 补丁分析流程

### 系统化分析方法论

```text
1. 获取样本
   - 官方补丁/MSRC公告
   - 抓取更新包（Windows Update Catalog）
   - 提取新旧版本DLL/EXE

2. 提取文件
   - Windows: expand, cabextract, 7z
   - Linux: RPM Diff, DEB Diff
   - macOS: pkgutil, pbzx

3. 二进制比对
   - 函数差异分析
   - 基本块差异分析
   - 指令级差异分析

4. 差异验证
   - 确认差异是否与安全相关
   - 构建Proof of Concept
   - 验证漏洞的可利用性

5. Exploit开发
   - 理解漏洞原理
   - 逆向周边函数
   - 开发Exploit（1-day）
```

### Windows补丁分析

```bash
# 1. 手动下载补丁
# Windows Update Catalog: https://www.catalog.update.microsoft.com/

# 2. 提取补丁文件
expand -F:* windows10.0-kb5000000-x64.msu extract/
cd extract/
expand -F:* windows10.0-kb5000000-x64.cab extracted/

# 3. 或使用7z直接提取
7z x windows10.0-kb5000000-x64.cab -oextracted/

# 4. 查找修改的二进制文件
# 比较补丁前后文件时间戳和版本号
# 关注系统DLL: ntdll.dll, kernel32.dll, win32k.sys等

# 5. 从符号服务器获取PDB（可选）
symchk /r extracted/ntdll.dll /s SRV*C:\symbols*http://msdl.microsoft.com/download/symbols
```

### Linux补丁分析

```bash
# 1. 获取源码包
apt-get source package_name
# 或下载RPM
dnf download --source package_name

# 2. 源码比对
diff -urN old_src/ new_src/ > patch.diff

# 3. 仅查看安全相关补丁
git log --oneline --grep="security\|CVE\|fix" -20

# 4. 二进制包差异
# 从更新源获取新旧deb/rpm
dpkg-deb -x old_package.deb old_extract/
dpkg-deb -x new_package.deb new_extract/
diff -r old_extract/ new_extract/

# 5. 内核补丁分析
git log --oneline v5.10..v5.10.1 -- security/
git show CVE-2021-xxxxx
```

## 案例分析

### MS17-010 EternalBlue

EternalBlue是2017年最著名的Windows SMB漏洞，被WannaCry勒索病毒利用：

```text
# 漏洞位置
srv.sys!SrvOs2FeaListSizeToNt
srv.sys!SrvOs2FeaListToNt

# 补丁分析
- 补丁在SrvOs2FeaListSizeToNt函数中添加了长度校验
- 检查FEA（File Extended Attributes）列表的大小
- 补丁前：没有验证FEA列表总长度是否溢出
- 补丁后：添加了对FEA列表大小的边界检查

# 漏洞类型
- 缓冲区溢出（OS/2 FEA列表解析）
- 未检查的整数溢出导致堆溢出

# Exploit特点
- 无需认证
- 远程代码执行（蠕虫传播）
- 针对SMBv1协议
```

### CVE-2021-1678 PrintNightmare

PrintNightmare是Windows Print Spooler服务远程代码执行漏洞：

```text
# 漏洞位置
spoolsv.exe!RpcAddPrinterDriver

# 补丁分析过程
1. 比对前后版本的win32k.sys或spoolsv.exe
2. 发现RpcAddPrinterDriver函数添加了权限检查
3. 补丁要求调用者具有SeLoadDriverPrivilege权限
4. 补丁前：任意用户（包括普通用户）可安装打印机驱动
5. 补丁后：仅管理员可安装

# 绕过分析
- Point and Print权限绕过（允许非管理员安装签名驱动）
- 攻击者利用签名驱动加载恶意DLL

# 补丁演进
- 第一个补丁未完全修复
- 后续补丁添加了更多访问控制检查
```

### CVE-2022-30190 Follina

Microsoft Support Diagnostic Tool (MSDT) 远程代码执行漏洞：

```text
# 漏洞位置
msdt.exe!BinaryDecoder::Decode

# 补丁分析
1. 对比新旧msdt.exe
2. 发现BinaryDecoder::Decode函数添加了URL验证
3. 补丁后阻止了ms-msdt://协议的某些协议调用

# 攻击链
1. 诱导用户打开特制Word文档（或查看预览）
2. Word通过ms-msdt://协议调用PowerShell
3. PowerShell从远程服务器下载并执行恶意负载
4. 无需启用宏

# 补丁绕过
- 最初微软发布的是禁用OLE协议处理的临时修复
- 后续补丁在msdt.exe中实施了更严格的校验
```

## Metasploit模块开发

### 模块结构

```ruby
# Metasploit模块模板：exploit.rb
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking  # 影响等级

  include Msf::Exploit::Remote::Tcp  # 引入TCP远程利用mixin

  def initialize(info = {})
    super(update_info(info,
      'Name'           => '1-day Exploit Module',
      'Description'    => 'Exploits CVE-XXXX-XXXX for RCE',
      'Author'         => ['Your Name'],
      'References'     => [
        ['CVE', '2024-XXXX'],
        ['URL', 'https://example.com/advisory'],
      ],
      'Platform'       => 'win',
      'Targets'        => [
        ['Windows 10 x64', { 'Ret' => 0x41414141 }],
      ],
      'Payload'        => { 'BadChars' => '\x00\x0a\x0d' },
      'DefaultTarget'  => 0
    ))

    register_options([
      Opt::RPORT(445),    # 目标端口
      OptString.new('TARGETURI', [true, 'The target URI', '/vuln']),
    ])
  end

  # 漏洞检查函数
  def check
    connect
    # 发送探测请求检测漏洞是否存在
    disconnect
    return Exploit::CheckCode::Vulnerable
  end

  # 漏洞利用函数
  def exploit
    connect

    print_status("Building exploit payload...")
    # 构造Exploit数据包
    buf = generate_exploit_buffer

    print_status("Sending exploit (#{buf.length} bytes)...")
    sock.put(buf)

    handler  # 处理payload连接
    disconnect
  end

  def generate_exploit_buffer
    # 构造ROP链和Shellcode
    # ...
  end
end
```

### 常用Mixins

```ruby
# 远程服务类mixins
include Msf::Exploit::Remote::Tcp     # TCP协议利用
include Msf::Exploit::Remote::HttpClient  # HTTP/HTTPS利用
include Msf::Exploit::Remote::SMB     # SMB协议利用
include Msf::Exploit::Remote::Ftp     # FTP协议利用

# 辅助功能mixins
include Msf::Exploit::Remote::Seh     # SEH覆盖利用
include Msf::Exploit::Remote::Egghunter  # Egg Hunter支持
include Msf::Exploit::Remote::ROP     # ROP链支持

# 生成payload
include Msf::Exploit::Remote::AutoCheck  # 自动Check
include Msf::Exploit::Powershell     # PowerShell payload
include Msf::Exploit::CmdStager      # 命令分段执行
```

## 1-day漏洞利用生命周期

```text
1. 补丁发布日 (Patch Tuesday)
   - 微软等厂商发布月度安全更新
   - 安全研究人员开始下载和分析补丁

2. 逆向分析阶段 (0-24小时)
   - 自动拆包补丁
   - 提取修改的二进制文件
   - 开始二进制比对

3. 漏洞定位阶段 (1-72小时)
   - 定位安全修复函数
   - 分析补丁添加的检查逻辑
   - 理解原始漏洞原理

4. PoC开发阶段 (1-7天)
   - 构建漏洞触发条件
   - 编写PoC验证漏洞存在
   - 确认漏洞的可利用性

5. Exploit开发阶段 (3-30天)
   - 开发完整Exploit
   - 绕过防护机制（ASLR/DEP/CFG）
   - 适配多个目标版本

6. 大规模利用 (1-30天)
   - Exploit集成到Metasploit
   - 自动化扫描和利用
   - 蠕虫化（高危）
```

## 参考资源

- [BinDiff](https://www.zynamics.com/bindiff.html)
- [Diaphora](https://github.com/joxeankoret/diaphora)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Zerodium Patch Diffing](https://zerodium.com/)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)
- [0patch Blog](https://blog.0patch.com/)
