# 全同态加密 (Fully Homomorphic Encryption, FHE)

## FHE 定义

**全同态加密 (Fully Homomorphic Encryption, FHE)** 允许对密文进行任意次数的加法和乘法同态运算，其功能等价于在不解密的情况下对明文进行任意计算。FHE 被称为密码学的"圣杯"，因为它解决了数据在第三方处理时的"可用不可见"问题。

## Bootstrapping：Gentry 的突破

2009 年，Craig Gentry 在博士论文中提出了第一个 FHE 方案，核心创新是 **bootstrapping** 技术：

- **问题**：同态运算会在密文中累积噪声，当噪声超过一定阈值后解密失败。
- **解决思路**：在"密文噪声即将超标"时，对密文进行"刷新"——在加密状态下运行解密电路，输出一个噪声更低的新密文。
- **意义**：Bootstrapping 将 LHE 转变为 FHE，实现了任意深度的计算。

**开销**：Gentry 原始方案的 bootstrapping 需要数十分钟。后续优化将时间降至秒级甚至亚秒级。

## 方案演进

| 方案 | 年份 | 基础 | 核心优化 | 性能特征 |
|------|------|------|---------|---------|
| Gentry's FHE | 2009 | Ideal Lattices | Bootstrapping | 理论突破，性能极低 |
| BGV | 2011-2012 | RLWE | Modulus Switching | 线性性能，深度电路 |
| BFV | 2012 | RLWE | Scale-invariant | 整型运算，与 BGV 互补 |
| CKKS | 2017 | RLWE | Approximate Arithmetic | 实/复数近似计算 |
| TFHE | 2016-2019 | LWE + NAND Gates | Programmable Bootstrapping | 门级快速 bootstrapping |

### TFHE (Torus FHE)
TFHE 是由 Chillotti 等人提出的 FHE 方案，其核心特点包括：

- **快速 bootstrapping** — 可以在 0.1 秒（现已优化到毫秒级）完成 bootstrapping。
- **门级操作** — 支持 NAND、AND、OR 等布尔门操作。
- **适用**：对延迟敏感的交互式协议、隐私信息检索。

## 性能基准

| 方案 | Bootstrapping 延迟 | 单次乘法延迟 | 密文大小 | 适用平台 |
|------|-------------------|------------|---------|---------|
| BGV (HElib) | ~10-60 秒 | ~1-10ms | ~1-10MB | CPU |
| BFV (SEAL) | N/A (需 bootstrapping 扩展) | ~1-5ms | ~0.5-5MB | CPU |
| CKKS (HEAAN/SEAL) | ~0.5-5 秒 | ~0.5-5ms | ~0.5-5MB | CPU |
| TFHE (TFHE-rs/concrete) | ~0.01-0.1 秒 | ~0.1-1ms | ~0.1-1MB | CPU/GPU |

## 主要库

| 库名 | 语言 | 支持的方案 | 特色 |
|------|------|-----------|------|
| **Microsoft SEAL** | C++ / .NET | BFV, CKKS | 文档完善、社区活跃、已停产维护 |
| **HElib** (IBM) | C++ | BGV, CKKS | 功能全面、支持 bootstrapping |
| **Palisade** | C++ / Python | BGV, BFV, CKKS | 模块化设计、GPU 支持 |
| **OpenFHE** (合并版) | C++ / Python | 所有主流方案 | Palisade + HElib + FHEW 合并 |
| **TFHE-rs** | Rust | TFHE | GPU 加速、高性能 bootstrapping |
| **Concrete** (Zama) | Python / Rust | TFHE | Python 接口友好、自动编译 |

**工程建议**：生产环境优先选择 OpenFHE 或 Concrete；性能敏感场景考虑 GPU 加速的 TFHE 方案；CKKS 适合机器学习推理，BFV/BGV 适合精确整数计算。
