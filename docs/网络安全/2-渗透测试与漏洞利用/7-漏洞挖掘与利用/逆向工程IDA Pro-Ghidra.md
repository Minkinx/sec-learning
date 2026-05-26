# 逆向工程IDA Pro-Ghidra

## 概述

逆向工程（Reverse Engineering）是分析二进制程序结构、逻辑和算法的过程，是漏洞挖掘、恶意软件分析和Exploit开发的基础。IDA Pro和Ghidra是两大主流逆向工具：IDA Pro是行业标准商业工具，拥有强大的Hex-Rays反编译器；Ghidra是NSA开源的免费框架，内置了Java开发的反编译器并支持团队协作。

## IDA Pro

### 界面与核心功能

```text
# IDA Pro主要视图
- IDA-View (反汇编窗口): 显示汇编代码
- Hex View: 十六进制视图
- Structures: 结构体定义
- Enums: 枚举定义
- Imports/Exports: 导入导出表
- Names: 符号名称列表
- Functions: 函数列表
- Strings: 字符串视图
- Cross-References: 交叉引用分析

# 常用快捷键
Space     - 图形视图/文本视图切换
G         - 跳转到地址
N         - 重命名符号
D         - 切换数据类型 (byte/word/dword/qword)
C         - 转为代码
P         - 创建函数
X         - 查看交叉引用
;         - 添加注释
Alt+M     - 添加书签
Ctrl+S    - 选择段
```

### 交叉引用分析

```text
# Xrefs (交叉引用) 类型
- Code xref: 代码跳转引用（jmp, call, jcc）
- Data xref: 数据访问引用（mov, lea）

# 分析流程
1. Strings窗口搜索敏感字符串
2. Xref追踪到引用代码
3. 向上追踪到函数入口
4. 分析调用关系和参数传递
5. F5反编译为伪代码
```

### Hex-Rays反编译器

```c
// 原始汇编（x86-64）
.text:00401000  push    ebp
.text:00401001  mov     ebp, esp
.text:00401003  sub     esp, 8
.text:00401006  cmp     [ebp+arg_0], 0
.text:0040100A  jle     short loc_401015
.text:0040100C  mov     eax, [ebp+arg_0]
.text:0040100F  imul    eax, [ebp+arg_4]
.text:00401013  jmp     short loc_40101C
.text:00401015  mov     eax, [ebp+arg_0]
.text:00401018  add     eax, [ebp+arg_4]
.text:0040101C  mov     esp, ebp
.text:0040101E  pop     ebp
.text:0040101F  retn

// Hex-Rays反编译结果
int __cdecl sub_401000(int a1, int a2) {
    if (a1 > 0)
        return a1 * a2;
    else
        return a1 + a2;
}
```

### IDAPython脚本

```python
# IDAPython自动化分析

# 获取所有函数
import idautils
for func_addr in idautils.Functions():
    func_name = idc.get_func_name(func_addr)
    print(f"0x{func_addr:x}: {func_name}")

# 搜索特定模式
import ida_search
addr = ida_search.find_binary(0, ida_ida.inf_get_min_ea(), 
    "55 8B EC 83 EC", 16, ida_search.SEARCH_DOWN)
if addr != ida_idaapi.BADADDR:
    print(f"Found pattern at: 0x{addr:x}")

# 添加注释
idc.set_cmt(addr, "This is a key function", 0)

# 枚举导入函数
import ida_nalt
for i in range(ida_nalt.get_import_module_qty()):
    name = ida_nalt.get_import_module_name(i)
    print(f"Imports from: {name}")

# 批量重命名函数
for addr in idautils.Functions():
    name = idc.get_func_name(addr)
    if "sub_" in name:
        # 基于Xrefs自动命名
        xrefs = list(idautils.XrefsTo(addr))
        if xrefs:
            idc.set_name(addr, f"xref_{len(xrefs):04d}_{name}")

# 提取字符串引用
for addr in idautils.Strings():
    if addr.length > 10:
        refs = list(idautils.XrefsTo(addr.ea))
        if refs:
            print(f"String [{addr.ea:x}]: {str(addr)} → refs: {len(refs)}")
```

### IDA Pro插件

```text
# 推荐插件
- FindCrypt2: 自动识别加密算法常量（AES S-Box, SHA常量）
- Keypatch: 内联汇编修补（补丁二进制）
- Lighthouse: 覆盖率映射（配合Fuzzing结果）
- IDAscope: 恶意软件分析
- ret-sync: IDA与调试器同步
- FLIRT签名的lib identification

# 安装路径
# Windows: C:\Program Files\IDA Pro 8.x\plugins\
# Linux: /opt/idapro-8.x/plugins/
```

## Ghidra

### 项目管理和分析

```bash
# 启动Ghidra
./ghidraRun

# 创建项目
File → New Project → Non-Shared Project
# 导入二进制文件
File → Import File → 选择目标

# 自动分析选项
Analysis → Auto Analyze
# 关键选项：
# - Decompile Parameter ID
# - Stack Analyzer
# - Data Reference
# - Function ID
# - Call Convention ID
```

### Ghidra反编译器

```java
// Ghidra反编译伪代码示例
void process_input(undefined4 param_1, char *input) {
    size_t len;
    int i;
    
    len = strlen(input);
    if (len < 8) {
        return;  // 长度不足8
    }
    
    for (i = 0; i < (int)len; i++) {
        input[i] = input[i] ^ 0x55;  // XOR解码
    }
    
    if (strncmp(input, "flag{", 5) == 0) {
        printf("Correct!\n");
    }
}
```

### Ghidra脚本

```python
# Ghidra Python (Jython) 脚本
# 需要放置在 $GHIDRA_SCRIPT_PATH 下

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

def analyze_functions():
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)
    
    for func in functions:
        name = func.getName()
        entry = func.getEntryPoint()
        
        # 检查是否有交叉引用
        ref_count = func.getCallCount()
        
        # 统计基本块数量
        body = func.getBody()
        bb_count = 0
        addr_iter = currentProgram.getListing().getCodeUnits(body, True)
        while addr_iter.hasNext():
            addr_iter.next()
            bb_count += 1
        
        print(f"{entry}: {name} - calls: {ref_count}, blocks: {bb_count}")

    # 搜索特定字符串
    from ghidra.program.model.listing import Data
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.isString():
            txt = data.getDefaultValueRepresentation()
            if "password" in txt.lower() or "secret" in txt.lower():
                print(f"Found sensitive: {txt} at {data.getAddress()}")

analyze_functions()
```

### Ghidra协作分析

```text
# Ghidra Server设置
# 1. 启动Ghidra Server
server/svrAdmin

# 2. 创建仓库
svrAdmin -add repository_name

# 3. 用户管理
svrAdmin -add user_name

# 4. 连接项目
File → Open Project → 选择Shared Project

# 协作优势
- 多人同时分析同一个二进制
- 注释和命名同步
- 分析结果共享
- 版本控制
```

## Ghidra vs IDA Pro对比

| 特性 | IDA Pro | Ghidra |
|------|---------|--------|
| 价格 | 商业（$2300+/年） | 免费开源 |
| 反编译器 | Hex-Rays（另购） | 内置 |
| 平台支持 | Windows/macOS/Linux | 跨平台 |
| 脚本语言 | Python/IDC | Python(Jython)/Java |
| 架构支持 | 极多 | 丰富 |
| 团队协作 | 需额外配置 | 内置服务器 |
| 学习曲线 | 高 | 中 |
| 调试器 | 内置 | 集成但不强 |
| 插件生态 | 成熟丰富 | 快速增长 |

## 调试器集成

### x64dbg (Windows用户态)

```text
# x64dbg主要功能
- 图形化反汇编
- 内存断点、硬件断点、条件断点
- SMC（自修改代码）分析
- 堆栈追踪
- 插件系统（ScyllaHide、xAnalyzer）

# 常用技巧
1. 字符串搜索 → Ctrl+F
2. 修改指令 → 双击汇编行
3. 内存dump → Ctrl+Alt+D
4. API断点 → bp CreateFileW
```

### GDB (Linux)

```bash
# GDB逆向常用命令
gdb ./binary

# 设置反汇编风格为Intel
set disassembly-flavor intel

# 反汇编当前函数
disas

# 反汇编指定函数
disas check_password

# 在特定地址设置断点
b *0x400000 + 0x1234

# 查看内存内容
x/32gx $rsp
x/s $rdi

# 修改寄存器
set $rax = 0

# 条件断点
b *0x401234 if $rax == 0xdeadbeef

# 跳转到指定地址
jump *0x401000

# 调试脚本
gdb -x script.gdb ./binary
```

### WinDbg (Windows内核调试)

```text
# WinDbg命令
kd> !process 0 0    # 查看进程列表
kd> lm              # 加载模块
kd> !analyze -v     # 自动分析崩溃
kd> !address        # 查看虚拟内存布局
kd> bp nt!NtCreateFile  # 设置内核断点
kd> kd> g           # 继续执行
```

## 分析流程实战

```text
# 系统化逆向分析流程

1. 信息收集阶段
   - file命令查看文件类型
   - strings提取字符串
   - readelf/dumpbin查看结构
   - 运行程序了解行为

2. 静态分析阶段
   - 导入到IDA/Ghidra
   - 自动分析
   - 识别库函数（FLIRT/FIRM）
   - 定位main/WinMain入口
   - 追踪敏感API调用

3. 动态验证阶段
   - 设置断点
   - 观察参数传递
   - 跟踪敏感数据流
   - Patch验证分析结论

4. 文档输出阶段
   - 函数重命名
   - 数据结构重建
   - 关键算法提取
   - 生成分析报告
```

## 参考资源

- [IDA Pro Hex-Rays](https://hex-rays.com/ida-pro/)
- [Ghidra](https://ghidra-sre.org/)
- [IDAPython Docs](https://github.com/idapython/src)
- [x64dbg](https://x64dbg.com/)
- [Ghidra Book (Packt)](https://www.packtpub.com/product/ghidra-book-the/9781800206645)
- [Binary Ninja](https://binary.ninja/)
