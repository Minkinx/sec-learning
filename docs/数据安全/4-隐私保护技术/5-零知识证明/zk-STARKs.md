# zk-STARKs

## 定义

**zk-STARKs (Zero-Knowledge Scalable Transparent ARgument of Knowledge)** 是由 Eli Ben-Sasson 等人于 2018 年提出的零知识证明协议，旨在解决 SNARKs 的 Trusted Setup 和非抗量子两个核心问题。

与 SNARKs 的关键区别体现在名称中：

- **Scalable** — 证明时间与计算规模呈近似线性关系；验证时间与计算规模呈对数关系（优于 SNARKs 的线性验证）。
- **Transparent** — 无需 Trusted Setup，所有公开随机性来自公开可验证的随机源。

## 透明设置 (Transparent Setup)

zk-STARKs 不需要任何可信设置仪式。所有协议参数通过公开的随机性生成（如使用可验证随机函数 VRF 或哈希函数的输出）。这意味着：

- 没有有毒废物需要销毁。
- 协议的安全性仅依赖于哈希函数的抗碰撞性等标准密码学假设。
- 部署门槛低，任何参与方都可独立验证设置的正确性。

## 后量子安全性

zk-STARKs 的安全性仅依赖于哈希函数和对称密码学原语，**不依赖**配对椭圆曲线或离散对数问题。因此，zk-STARKs 是 **后量子安全 (Post-Quantum Secure)** 的。

相比之下，zk-SNARKs（Groth16、PLONK）依赖的椭圆曲线配对在 Shor 算法下不安全，当前不具备量子安全性。

## 证明大小对比

| 维度 | zk-SNARKs | zk-STARKs |
|------|-----------|-----------|
| 证明大小 | 48-400 字节 | 45-200 KB |
| 验证时间 | 1-10 ms | 10-100 ms |
| 证明生成时间 | 与电路规模线性 | 与电路规模近线性 |
| Trusted Setup | 需要（Groth16）或通用（PLONK） | 不需要 |

zk-STARKs 的证明尺寸显著大于 SNARKs（约 1000x），这是其主要的工程权衡。对于链上验证（如以太坊 blob 空间有限），证明大小是关键限制因素；对于链下验证场景，STARKs 的大小是可接受的。

## 可扩展性

STARKs 的"Scalable"特性体现在：
- **证明者时间**：$O(N \\log N)$，其中 N 为计算规模。
- **验证者时间**：$O(\\log^2 N)$，随计算规模增长极慢。
- **证明大小**：$O(\\log^2 N)$。

这使得 STARKs 特别适合大规模计算验证，如大规模状态转换（starknet 的 Cairo 虚拟机证明）。

## 核心技术

zk-STARKs 的核心技术是 **ARI (Algebraic Representation of IOP)** 和 **FRI (Fast Reed-Solomon Interactive Oracle Proof)**：

- **IOP (Interactive Oracle Proof)** — 将协议转换为多轮交互协议。
- **FRI** — 用于证明某个函数是低度多项式的高效协议。
- **Bootstrapping from IOP to Non-interactive** — 使用 Fiat-Shamir 转换将交互式协议转为非交互式。

## 主要应用

### 区块链扩展
- **StarkNet** — 基于 STARK 的以太坊 Layer 2，使用 Cairo 虚拟机作为智能合约执行环境。
- **dYdX** — 使用 STARK 验证交易所的状态转换。
- **Immutable X** — NFT 交易的零 gas 费用扩展方案。

### 隐私保护
STARKs 可用于隐私交易，但证明尺寸较大使其不如 SNARKs 流行。然而，**递归证明 (Recursive Proofs)** 技术（如 StarkNet 的 SHARP 证明聚合器）可以在 STARK 内验证 STARK 证明，将多个证明合并为一个，降低总证明大小。

## 与 SNARKs 的取舍

| 考虑因素 | 选择 SNARKs | 选择 STARKs |
|----------|-----------|-----------|
| 证明大小敏感（如链上验证） | 最佳选择 | 证明过大可能受限 |
| 需要后量子安全 | 不适用 | 必须选择 |
| Trusted Setup 不可接受 | PLONK (通用设置) 可选 | 天然透明 |
| 大规模计算验证 | 可能受限 | 可扩展最佳 |
