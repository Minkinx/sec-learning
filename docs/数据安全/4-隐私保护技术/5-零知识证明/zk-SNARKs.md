# zk-SNARKs

## 定义

**zk-SNARKs (Zero-Knowledge Succinct Non-interactive ARgument of Knowledge)** 是一种零知识证明协议，允许证明者 (prover) 向验证者 (verifier) 证明自己掌握某个秘密信息，而无需泄露该信息本身。其名称中的关键特性：

- **Zero-Knowledge** — 证明过程中不泄露任何关于秘密的信息。
- **Succinct** — 证明的大小极小（通常为几十到几百字节），验证时间极短（毫秒级）。
- **Non-interactive** — 证明只需一轮交互（证明者发送证明，验证者验证）。
- **Argument of Knowledge** — 证明者需要知道秘密才能生成有效证明。

## 证明系统对比

### Groth16
Groth16 (2016) 是目前证明尺寸最小、验证最快的 zk-SNARKs 方案之一。

**特点**：
- **证明大小**：3 个群元素（约 48-144 字节，取决于曲线）。
- **验证时间**：约 1-5ms（配对的常数次运算）。
- **证明时间**：与电路规模线性相关。
- **要求**：每个电路需要一次 **trusted setup**（可信设置仪式），且设置参数不可更新。

**Trusted Setup**：
- 产生公共参考字符串 (CRS) 用于证明生成和验证。
- 设置过程中的有毒废物 (toxic waste) 必须被销毁，否则可伪造证明。
- 多方参与的计算仪式（如 Zcash 的 Powers of Tau 仪式）降低了信任风险。

### PLONK
PLONK (2020, Protocol Labs) 是一种通用可更新的 zk-SNARKs 方案。

**特点**：
- **通用可信设置** — CRS 可被所有电路共享，无需为每个电路重新设置。
- **可更新性 (Updatability)** — 新参与方可随时加入更新 CRS。
- **证明大小**：约 200-400 字节（比 Groth16 略大）。
- **验证时间**：约 5-10ms（稍慢于 Groth16）。
- **灵活性**：支持任意电路，适合通用系统。

## 电路模型

zk-SNARKs 将计算问题表示为 **算术电路 (Arithmetic Circuit)** 或 **R1CS (Rank-1 Constraint System)**：

```
Witness (秘密输入) + 公共输入 → 电路约束满足 → 生成证明
```

电路规模以"门数"衡量，门数越多，证明生成时间越长。一般的隐私交易电路约 1 万-10 万门，复杂的验证计算可达百万门级别。

## 主要应用

### zk-Rollups
以太坊 Layer 2 扩展方案，将数千笔交易的执行证明打包为单个 SNARK，提交到 Layer 1 链验证。

- **代表性项目**：zkSync (PLONK)、StarkNet (STARK)、Scroll (Halo2)。
- **优势**：降低 gas 成本 100x+，提高 TPS 至数千。

### 隐私交易
隐藏交易的发送方、接收方和金额信息。

- **Zcash** — 首个大规模使用 Groth16 的隐私加密货币。
- **Tornado Cash** — 使用 SNARK 实现以太坊上的隐私转账。

## 局限性

- **Trusted Setup 依赖** — Groth16 需要可信设置，存在秘密泄露风险。
- **非抗量子** — SNARKs 依赖的配对密码学在量子计算机下不安全。
- **电路设计复杂** — 目标计算需手工编译为算术电路，工程难度高。
