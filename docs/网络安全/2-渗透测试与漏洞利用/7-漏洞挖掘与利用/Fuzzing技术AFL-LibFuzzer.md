# Fuzzing技术AFL-LibFuzzer

## 概述

模糊测试（Fuzzing）是一种自动化软件测试技术，通过向目标程序输入大量异常、畸形或随机的数据来发现安全漏洞。覆盖率引导的模糊测试（Coverage-Guided Fuzzing）是现代Fuzzing技术的主流，代表工具有AFL（American Fuzzy Lop）和LibFuzzer。Fuzzing在漏洞挖掘中发现了大量高危漏洞，包括Heartbleed、Stagefright和各种浏览器0-day。

## 覆盖率引导Fuzzing

### 核心概念

```text
# 覆盖率引导Fuzzing工作流程
1. 初始化种子语料库（Seed Corpus）
2. 使用种子输入运行目标程序
3. 记录代码覆盖路径（Edge Coverage）
4. 对种子进行变异（Mutation）生成新输入
5. 测试新输入，追踪覆盖变化
6. 如果新输入触发了新路径，加入队列
7. 重复步骤4-6，持续扩展覆盖

# 覆盖率度量
- Edge Coverage（边覆盖）：记录基本块之间的转移
- Hit Counts（命中计数）：记录每条边被执行的次数
- Buckets：将命中次数分桶（1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+）
```

### AFL工作流程

```bash
# 1. 使用afl-gcc/afl-clang编译目标程序
CC=afl-gcc CXX=afl-g++ ./configure
make

# 或使用afl-clang-fast（更高效的插桩）
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure
make -j$(nproc)

# 2. 准备种子语料库
mkdir -p input output
# 放入有效的输入样本
# 例如：fuzzing一个图片解析器，放入几张不同格式的图片
# 种子要小而精，覆盖多种有效格式

# 3. 启动AFL Fuzzer
afl-fuzz -i input -o output -- ./target/program @@

# @@参数表示AFL会自动替换为输入文件路径
# 例如：afl-fuzz -i input -o output -- ./readelf -a @@
```

### AFL状态监控

```bash
# AFL状态界面关键指标

# cycle done: 当前测试周期进度
# total paths: 发现的唯一路径数量（最重要的指标）
# uniq crashes: 唯一崩溃数量
# uniq hangs: 唯一挂起数量

# 监控性能
afl-whatsup output/
afl-stat output/
```

### 崩溃处理

```bash
# 查看崩溃样本
ls output/crashes/

# 最小化崩溃
afl-tmin -i output/crashes/id:000000 -o minimized_crash -- ./target @@

# 崩溃分类（去重）
# 使用GDB或asan_symbolize.py
gdb ./target core
bt

# 使用自动分类工具
# crashwalk: 基于GDB的崩溃分类
# afl-collect: 收集和分类崩溃

# 构建exploit
python3 afl-collect -d crashes.db output/crashes/ ./target
```

## AFL高级技术

### 并行Fuzzing

```bash
# 启动多个AFL实例
# 主实例（Master）
afl-fuzz -i input -o output -M fuzzer01 -- ./target @@

# 从实例（Secondary）
afl-fuzz -i input -o output -S fuzzer02 -- ./target @@
afl-fuzz -i input -o output -S fuzzer03 -- ./target @@
# 从实例自动从主实例同步有趣的种子

# 使用screen管理多个实例
screen -S afl-master -d -m afl-fuzz -M master -i input -o output -- ./target @@
screen -S afl-slave1 -d -m afl-fuzz -S slave1 -i input -o output -- ./target @@
```

### 字典支持

```bash
# 创建字典文件（help AFL生成有效语法输入）
cat > target.dict << 'EOF'
# 协议关键字
token_start="GET "
token_mid=" HTTP/1.1"
token_host="Host: "
token_end="\r\n\r\n"

# 文件魔术头
magic_png="\x89\x50\x4E\x47"
magic_jpg="\xFF\xD8\xFF\xE0"
magic_gif="\x47\x49\x46\x38\x39\x61"

# 数字
number_zero="0"
number_one="1"
number_large="999999999"

# 特殊字符
special_null="\x00"
special_percent="%s"
EOF

# 在FUZZ中使用字典
afl-fuzz -x target.dict -i input -o output -- ./target @@
```

## LibFuzzer

### 基础使用

LibFuzzer是LLVM项目的一部分，与目标程序链接在同一进程中，相对AFL运行速度更快：

```c
// fuzz_target.cc - LibFuzzer测试目标
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Fuzzer输入处理函数
    if (Size < 3) return 0;
    
    // 假设我们要Fuzz一个解析函数
    if (Data[0] == 'G' && Data[1] == 'O' && Data[2] == 'D') {
        if (Size > 100) {
            // 触发一个缓冲区溢出
            volatile char buf[10];
            for (size_t i = 0; i < Size; i++) {
                buf[i] = Data[i];  // 缓冲区溢出！
            }
        }
    }
    return 0;
}
```

```bash
# 编译和运行LibFuzzer
clang++ -fsanitize=fuzzer,address -g -O1 fuzz_target.cc -o fuzz_target

# 运行Fuzzer
./fuzz_target -max_len=1000 -runs=1000000 corpus/

# 常用选项
./fuzz_target \
  -max_len=4096 \           # 最大输入长度
  -runs=1000000 \           # 最大运行次数
  -timeout=5 \              # 超时秒数
  -max_total_time=3600 \    # 总Fuzz时间（秒）
  -workers=4 \              # 并行Worker数
  -jobs=8 \                 # 总任务数
  -print_final_stats=1 \    # 输出最终统计信息
  -seed=12345 \             # 随机种子（可复现）
  corpus/                   # 种子语料库目录
```

### Sanitizer集成

LibFuzzer常与LLVM Sanitizer配合使用：

```bash
# AddressSanitizer (ASan) - 内存错误检测
clang++ -fsanitize=fuzzer,address -g fuzz_target.cc -o fuzz_asan

# UndefinedBehaviorSanitizer (UBSan) - 未定义行为
clang++ -fsanitize=fuzzer,undefined -g fuzz_target.cc -o fuzz_ubsan

# MemorySanitizer (MSan) - 未初始化内存
clang++ -fsanitize=fuzzer,memory -g fuzz_target.cc -o fuzz_msan

# 组合使用
clang++ -fsanitize=fuzzer,address,undefined -g fuzz_target.cc -o fuzz_all

# LeakSanitizer (LSan) - 内存泄漏
ASAN_OPTIONS=detect_leaks=1 ./fuzz_target corpus/
```

### 实际Fuzz示例

```c
// Fuzz libpng
#include <png.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;  // PNG最小尺寸
    
    // 验证PNG签名
    if (png_sig_cmp(Data, 0, 8)) return 0;
    
    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return 0;
    
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }
    
    // 设置错误处理
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }
    
    // 使用自定义读取器
    struct ReaderState {
        const uint8_t *data;
        size_t size;
        size_t pos;
    };
    
    ReaderState state = {Data, Size, 0};
    
    png_set_read_fn(png_ptr, &state, [](png_structp png, 
        png_bytep out, png_size_t length) {
        auto *st = static_cast<ReaderState*>(png_get_io_ptr(png));
        if (st->pos + length <= st->size) {
            memcpy(out, st->data + st->pos, length);
            st->pos += length;
        }
    });
    
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    
    return 0;
}
```

## 语料库管理

### 蒸馏和合并

```bash
# AFL语料库最小化（提取唯一覆盖）
afl-cmin -i input_dir -o minimized_dir -- ./target @@

# LibFuzzer语料库合并
./fuzz_target -merge=1 merged_dir new_corpus_dir/

# 单步蒸馏（保留最小覆盖集）
# 1. 收集所有种子
# 2. 最小化每个种子（afl-tmin）
# 3. 合并到唯一覆盖集（afl-cmin / libfuzzer -merge）
```

### 种子策略

```text
# 优质种子语料库特征
- 小尺寸（减少Fuzzing开销）
- 高覆盖率（多种代码路径）
- 语法正确（帮助Fuzzer探索深层逻辑）
- 边界值覆盖（空文件、大文件、畸形结构）

# 种子来源
1. 格式规范的官方样本
2. 代码测试用例
3. 覆盖工具生成的样本
4. 已有Fuzz结果的种子库
5. 语法生成器（Grammar-based Fuzzer）
```

## 崩溃分类与利用

```bash
# 崩溃栈哈希去重
cat output/crashes/* | while read crash; do
    addr2line -e ./target -f -C $(gdb -batch -ex "bt" -ex "quit" ./target $crash 2>/dev/null | grep "#0" | awk '{print $NF}') | head -1
done | sort -u

# 利用Exploitable框架
python exploitable/exploitable.py -t ./target crash_input

# GDB自动分析
gdb -batch -ex "run < crash_input" -ex "bt" -ex "info registers" -ex "quit" ./target

# ASAN日志分析
# 查看ASAN输出的错误类型
# heap-buffer-overflow, stack-buffer-overflow, use-after-free等
```

## Fuzzing工具对比

| 工具 | 特点 | 适用场景 |
|------|------|----------|
| AFL | 成熟稳定，外置Fuzzer | 通用二进制程序 |
| AFL++ | AFL增强版，性能提升 | AFL的现代替代 |
| LibFuzzer | 进程内，速度最快 | 库函数Fuzz |
| Honggfuzz | 硬件特性，持久Fuzz | 全平台支持 |
| Syzkaller | 系统调用Fuzz | Linux内核Fuzz |
| Jazzer | JVM Fuzzer | Java应用Fuzz |
| OSS-Fuzz | 持续Fuzz服务 | 开源项目审计 |
| Boofuzz | 网络协议Fuzz | 协议实现Fuzz |

## 参考资源

- [AFL](https://lcamtuf.coredump.cx/afl/)
- [AFL++](https://github.com/AFLplusplus/AFLplusplus)
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
- [Fuzzing Book](https://www.fuzzingbook.org/)
- [Syzkaller](https://github.com/google/syzkaller)
