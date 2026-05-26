# 安全多方计算 (MPC)

## 概述

安全多方计算 (Secure Multi-Party Computation, MPC) 允许多个参与方在不泄露各自输入的情况下联合计算一个函数。MPC 通过密码学协议保证输入隐私和计算正确性，是隐私计算的核心技术之一。

## 秘密共享 (Secret Sharing)

### Shamir's Secret Sharing

Shamir 的 (t, n) 门限秘密共享方案将秘密拆分为 n 份，任意 t 份可恢复：

```python
# 生成: 将秘密 S 拆分为 n 份，阈值 t
# f(x) = S + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹ (mod p)
# 份额: (1, f(1)), (2, f(2)), ..., (n, f(n))

# 恢复: 任意 t 个份额通过 Lagrange 插值恢复 S
# S = f(0) = Σᵢ f(i) × Πⱼ≠ᵢ (0 - j) / (i - j)
```

| 参数 | 说明 | 典型值 |
|------|------|--------|
| n | 总份额数 | 3-10 |
| t | 恢复门限 | n/2 + 1 或 2n/3 |
| p | 素数模数 | 256-bit prime |
| 安全类型 | Information-theoretic | — |

### Additive Secret Sharing

```
将秘密 x 拆分为 x₁, x₂, ..., xₙ:
  x = x₁ + x₂ + ... + xₙ (mod p)
  
每个参与方持有 xᵢ
所有参与方加起来恢复 x

加法同态:
  x ⊕ y = (x₁ + y₁) + (x₂ + y₂) + ... + (xₙ + yₙ) (mod p)
  无需交互即可计算加法
```

## 混淆电路 (Garbled Circuits)

### Yao's Garbled Circuits

Yao 的混淆电路是两方计算的基础协议：

```
Alice (输入 a) ──→ 混淆电路 ──→ Bob (输入 b)
                          ↓
                      计算结果 f(a, b)

协议流程:
1. Alice 生成混淆电路:
   - 为电路的每条线生成两个随机密钥 (0 和 1)
   - 对每个门的真值表加密混淆
   - 发送混淆电路和 Alice 的输入密钥给 Bob

2. Bob 通过 OT 获得自己的输入密钥
   - 不知道 Alice 的输入，不暴露自己的输入
   - 通过 Oblivious Transfer 获取对应密钥

3. Bob 逐门解密电路
   - 获得最终的输出密钥
   - 根据输出密钥映射恢复结果

4. Bob 将结果分享给 Alice
```

## Oblivious Transfer (不经意传输)

OT 是 MPC 的基础原语，允许接收方从发送方的多条消息中选择一条获取，而不暴露选择了哪一条。

### 1-out-of-2 OT

```
发送方: m₀, m₁ (两段消息)
接收方: b ∈ {0, 1} (选择位)

结果:
  接收方获得 m_b
  发送方不知道 b
  接收方不知道 m_{1-b}
```

### OT 扩展 (IKNP03)

基础 OT 的计算成本很高（公钥操作），OT 扩展将少量基础 OT 扩展为大量高效 OT：

| OT 类型 | 公钥操作 | 对称操作 | 适用场景 |
|---------|---------|---------|----------|
| 基础 OT | O(n) 公钥 | 0 | 小规模计算 |
| OT 扩展 | O(κ) 公钥 | O(n) 哈希 | 大规模计算 |
| Correlated OT | O(κ) 公钥 | O(n) PRG | Garbled Circuit 优化 |

## SPDZ 协议

SPDZ 协议族是多方计算中应用最广的协议之一，支持 dishonest majority 下的恶意安全计算。

### SPDZ 协议组件

```
离线阶段 (Preprocessing):
  生成:
    - Beaver Triples ([a], [b], [c=ab]) 用于乘法
    - Random Bits ([r]) 用于比较
    - Random Shares 用于输入掩码
  此阶段可预先执行，性能取决于底层加密

在线阶段 (Online):
  输入: 各参与方提供输入共享
  加法: 本地加法即可 (秘密共享的加法同态)
  乘法: 消耗一个 Beaver Triple
  比较: 消耗 Random Bits + 比特分解
  输出: 开放结果
```

### SPDZ 性能特征

| 操作 | 离线阶段 | 在线阶段 | 通信轮次 |
|------|---------|---------|----------|
| 加法 (+) | 0 | 0 | 0 round |
| 乘法 (×) | 1 triple | 2 次开放 + 1 次乘法 | 2 rounds |
| 比较 (<) | ~100 bit | ~10 次开放 | ~10 rounds |
| 随机数 (rand) | 0 | 1 次开放 | 1 round |

## Honest Majority vs Dishonest Majority

| 维度 | Honest Majority | Dishonest Majority |
|------|-----------------|-------------------|
| 容忍合谋方数 | n/2 - 1 | n - 1 |
| 安全类型 | 允许不诚实但遵守协议 | 允许任意恶意行为 |
| 基础协议 | Shamir SS | SPDZ, MASCOT |
| 计算开销 | 低 | 高 (10-100x) |
| 通信开销 | 低 | 高 |
| 预处理 | 无 | 需要 (预处理阶段) |
| 典型代表 | ABY3, Fantastic Four | SPDZ, MASCOT, Overdrive |

### 安全性假设对性能的影响

```
Honest Majority (e.g., n=3, t=1):
  在线吞吐量: ~1M 百万次乘法/秒 (局域网)
  延迟: ~10ms per multiplication

Dishonest Majority (e.g., n=2):
  在线吞吐量: ~10K 乘法/秒 (局域网)
  延迟: ~100ms per multiplication
  预处理消耗: 额外 10x 离线时间
```

## 性能开销分析

### 计算开销

```
MPC 中的主要计算成本:
  1. 公钥加密 (RSA/ECC): 用于基础 OT
  2. 对称加密 (AES-Hash): 用于 OT 扩展
  3. 有限域运算: 用于秘密共享算术
  4. 电路计算: 用于布尔电路

典型延迟:
  LAN (1Gbps, <1ms RTT):
    - 算术电路: 1-10ms per gate
    - 布尔电路: 10-100ms per gate
    
  WAN (100Mbps, 50ms RTT):
    - 算术电路: 50-500ms per gate
    - 布尔电路: 500-5000ms per gate
```

### 通信开销

| 协议 | 通信量 (per multiplication) | 通信轮次 |
|------|---------------------------|----------|
| SPDZ (n=2) | 2 个 field element | 2 rounds |
| ABY3 (n=3, HM) | 1 个 field element | 1 round |
| Garbled Circuit (n=2) | ~4 个 ciphertext per AND gate | O(depth) rounds |

### 优化方向

| 优化技术 | 效果 | 研究进展 |
|----------|------|----------|
| 算术电路优化 | 减少乘法门数量 | 深度优化至 O(log n) |
| 预计算 | 减少在线时间 | 生产环境常用 |
| 并行化 | 利用多核/GPU | 吞吐量提升 10-100x |
| 专用硬件 | FPGA/ASIC 加速 | 实验阶段 |
| 混合协议 (ABY) | 各协议取长补短 | 学术 + 工业实践 |

## 参考标准

- Shamir, A. (CACM 1979) How to Share a Secret
- Yao, A. (FOCS 1982) Protocols for Secure Computations
- Goldreich-Micali-Wigderson (STOC 1987) GMW Protocol
- SPDZ: Damgard et al. (CRYPTO 2012, Eurocrypt 2013)
- NIST IR 8215 (Secure Multi-Party Computation)
