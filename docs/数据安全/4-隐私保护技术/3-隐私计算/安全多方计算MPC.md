# 安全多方计算 (Secure Multi-Party Computation, MPC)

## 定义与背景

**安全多方计算 (Secure Multi-Party Computation, MPC)** 允许多个参与方在不泄露各自私有输入的情况下，共同计算一个函数的结果。MPC 的经典问题——**姚氏百万富翁问题**（1982 年，姚期智）——形象地展示了 MPC 的目标：两位百万富翁希望比较谁更富有，但不向对方透露自己的具体财富值。

## 核心协议

### GMW 协议 (Goldreich-Micali-Wigderson)
基于 **garbled circuits** 和 **secret sharing** 的混合协议，支持一般布尔电路计算。

- **特点**：n 方参与，支持恶意模型（通过 coin-tossing 和 cut-and-choose 技术）。
- **通信**：参与方之间需多次交互。

### SPDZ 协议
SPDZ (由其作者命名) 是应用最广泛的高效 MPC 协议之一，基于 **additive secret sharing** 和 **authenticated shares**。

- **预处理阶段 (Offline)**：生成 Beaver triples 等随机数材料。
- **在线阶段 (Online)**：使用预处理材料高效计算结果。
- **安全性**：恶意模型下安全，支持 dishonest majority。

### ABY3 协议
针对 3 方计算的优化协议，支持混合协议切换（arithmetic/boolean/yeoman sharing）。

- **特点**：在 3 方 honest-majority 设定下性能优越。
- **应用**：机器学习推理中的隐私保护计算。

## 核心技术原语

### 秘密共享 (Secret Sharing)
将秘密拆分为多个份额，分发给各参与方。任何 t 个参与方可以重构秘密（t-out-of-n 门限）。

- **Shamir's Secret Sharing** — 基于多项式插值，支持任意门限值。
- **Additive Secret Sharing** — 秘密表示为份额之和，适合算术运算。

### 混淆电路 (Garbled Circuits)
将目标函数表示为布尔电路，并对每条线路进行加密。评估方在不知道电路内部结构的情况下执行计算。

- **优点**：适合比较、加密等布尔运算。
- **缺点**：电路规模随函数复杂度指数增长。

### 不经意传输 (Oblivious Transfer, OT)
发送方拥有多条消息，接收方选择其中一条接收，但发送方不知道接收方选择了哪一条，接收方也不能获取其他消息。

- **基础 OT**：1-out-of-2 OT 是最基础的变体。
- **扩展 OT**：通过 OT extension 将少量基础 OT 扩展为大量高效 OT。

## Honest Majority vs Dishonest Majority

| 维度 | Honest Majority | Dishonest Majority |
|------|----------------|-------------------|
| 容忍腐败方数量 | < n/2 | < n |
| 协议效率 | 较高（不需要复杂校验） | 较低（需抵御更多攻击） |
| 典型协议 | ABY3、Rep3 | SPDZ、MASCOT |
| 安全性假设 | 多数参与方诚实 | 任何参与方可能腐败 |

## 性能特征

| 操作 | 通信量 | 计算开销 |
|------|--------|----------|
| 加法 (secret shared) | 无 | O(1) |
| 乘法 (Beaver triple) | O(1) 轮次 | O(1) |
| 比较 | O(k) 比特 / O(log k) 轮 | O(k) |
| 矩阵乘法 | O(mnk) | O(mnk) |

## 实际应用

- **金融**：多家银行联合计算反洗钱评分而不暴露各自客户数据。
- **医疗**：多家医院联合进行疾病关联分析。
- **供应链**：在多方供应链中计算零知识库存核对。
