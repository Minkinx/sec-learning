# 层次同态加密 (Leveled Homomorphic Encryption, LHE)

## LHE 定义

**层次同态加密 (Leveled Homomorphic Encryption, LHE)** 是一种支持在密文上进行**有限次数**的加法和乘法同态运算的加密方案。与纯全同态加密不同，LHE 要求预先设定电路深度（乘法层级数），在达到深度限制后不可再进行乘法运算（否则解密失败）。LHE 规避了 bootstrapping 的高昂开销，在满足应用需求的前提下性能远优于 FHE。

## 核心方案对比

### BFV (Brakerski/Fan-Vercauteren)
- **基础**：基于 Ring Learning With Errors (RLWE) 问题。
- **特点**：对整数数据进行加密，支持模运算电路。
- **消息空间**：整数模 t（t 为明文模数）。
- **适用**：需要对整数进行加法和乘法的场景。

### BGV (Brakerski-Gentry-Vaikuntanathan)
- **基础**：同样基于 RLWE，采用 modulus switching 技术控制噪声增长。
- **特点**：使用"尺度化"（scaling）技术优化乘法操作。
- **与 BFV 的关系**：BGV 是 BFV 的前身，两者性能在具体参数下各有优劣。
- **适用**：深度较大的乘法电路。

### CKKS (Cheon-Kim-Kim-Song)
- **基础**：基于 RLWE，但采用近似计算 (approximate arithmetic) 方法。
- **特点**：支持实数/复数的近似计算，使用 rescaling 管理噪声。
- **消息空间**：实数/复数（浮点数近似表示）。
- **适用**：机器学习推理、数据科学中的近似计算。
- **注意**：CKKS 的结果是近似值而非精确值，存在精度损失。

## Leveled vs Pure FHE

| 维度 | Leveled HE | Pure FHE |
|------|-----------|----------|
| 电路深度 | 有限（预先设定） | 无限 |
| Bootstrapping | 不需要 | 必须 |
| 性能 | 高（无 bootstrapping 开销） | 低（bootstrapping 极慢） |
| 参数选择 | 根据深度选择参数 | 统一参数 |
| 适用场景 | 深度已知的计算 | 深度不可预测的任意计算 |

## 参数选择

LHE 的参数选择直接影响安全性和性能：

### 环维度 (Ring Dimension, n)
n 通常为 2 的幂（如 4096、8192、16384、32768）。n 越大，安全性越高，支持的计算深度越大，但密文尺寸和计算开销也越大。

### 明文模数 (Plaintext Modulus, t)
t 决定了消息空间的大小。t 越大，密文膨胀率越高（密文大小约为 $n \\cdot \\log q$ 比特，其中 q 是密文模数）。

### 噪声管理
- 每次乘法操作噪声近似平方增长。
- 通过 modulus switching (BGV) 或 rescaling (CKKS) 控制噪声。
- 参数需确保在深度 d 的电路执行后，噪声不超过解密阈值。

## 参数选择示例

| 安全性等级 | n | log q | 支持深度 | 密文大小 |
|-----------|----|-------|---------|---------|
| 128-bit | 4096 | 109 | ~5 层乘法 | ~55KB |
| 128-bit | 8192 | 218 | ~15 层乘法 | ~218KB |
| 128-bit | 16384 | 440 | ~50 层乘法 | ~880KB |

## Bootstrapping

对于 LHE，当需要超过预设深度的计算时，可以使用 **bootstrapping** 重置噪声水平。但 bootstrapping 本身消耗约 5-15 层的乘法预算，且延迟极高（秒级到分钟级）。在 LHE 中，bootstrapping 是可选的"逃生舱"而非核心功能。
