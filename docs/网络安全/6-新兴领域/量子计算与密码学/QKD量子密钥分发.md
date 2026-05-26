# QKD量子密钥分发

## 概述

量子密钥分发（Quantum Key Distribution, QKD）是一种利用量子力学原理实现安全密钥交换的技术。与基于数学困难问题的传统密码学不同，QKD的安全性基于物理定律——任何窃听行为都会不可避免地留下可检测的痕迹。

## QKD基本原理

### 核心物理原理

QKD的安全性建立在以下量子力学原理之上：

| 原理 | 描述 | 安全意义 |
|------|------|---------|
| 量子不可克隆定理 | 未知量子态无法被完美复制 | 窃听者无法复制密钥光子 |
| 测量扰动 | 对量子态的测量会改变其状态 | 窃听行为必然留下痕迹 |
| 海森堡不确定性 | 互补属性不能同时精确测量 | 窃听者无法完全获取密钥 |
| 纠缠态相关性 | 纠缠光子对之间存在非局域关联 | 可检测传输信道安全性 |

### 量子比特编码方式

QKD中的密钥比特通过光子的量子态编码：

| 编码方式 | 物理实现 | 特性 |
|---------|---------|------|
| 偏振编码 | 光子偏振方向 | 自由空间QKD适合 |
| 相位编码 | 光子的相对相位 | 光纤QKD常用 |
| 时间箱编码 | 光子到达时间 | 抗环境干扰 |
| 频率编码 | 光子频率 | 抗色散 |

## BB84协议

BB84是世界上第一个QKD协议，由Charles Bennett和Gilles Brassard于1984年提出，也是目前应用最广泛的QKD协议。

### 协议流程

```
步骤1: 量子传输

Alice 发送编码在4种偏振态中的随机光子序列
  基A (rectilinear, +):   |→⟩ (0°) = 0,  |↑⟩ (90°) = 1
  基B (diagonal, ×):      |↗⟩ (45°) = 0,  |↘⟩ (135°) = 1

Alice 随机选择基和比特，制备并发送光子序列:

时间槽:  1  2  3  4  5  6  7  8  9  10 ...
Alice基: +  ×  ×  +  ×  +  ×  +  +  × ...
Alice比特: 0  1  0  0  1  1  0  1  0  0 ...
发送光子: → ↗ ↘ ↑ ↗ → ↘ → ↑ ↗

Bob 使用随机选择的基测量每个光子:

Bob基:    ×  +  ×  ×  ×  +  +  ×  +  × ...
Bob比特:  1  0  0  0  1  1  1  1  0  0 ...

步骤2: 基比对

Alice和Bob通过经典信道交换各自使用的基（而不是比特值）:
比对结果:
  时间槽:  1   2   3   4   5   6   7   8   9   10 ...
  Alice基: +   ×   ×   +   ×   +   ×   +   +   × ...
  Bob基:   ×   +   ×   ×   ×   +   +   ×   +   × ...
  匹配?    ✗   ✗   ✓   ✗   ✓   ✓   ✗   ✗   ✓   ✓ ...

保留基匹配的时间槽: 3, 5, 6, 9, 10
对应比特:           0, 1, 1, 0, 0
原始密钥: 01100 (100位中约保留50%的基匹配)
```

### 窃听检测

```
步骤3: 错误率估计

Alice和Bob随机选择部分匹配基的比特进行公开比对:

公开比对位: 时间槽3(0), 时间槽5(1)
对比结果: Alice=0, Bob=0 ✓, Alice=1, Bob=1 ✓
错误率: 0/2 = 0% (样本小，实际需更多)

如果错误率超过阈值（通常3-11%），说明存在窃听:
  QBER (Quantum Bit Error Rate):
    - 无窃听: 2-5% (系统噪声)
    - 有窃听: 11-25%+ (异常增加)
    - 决定阈值: 11%（超过则终止协议）

步骤4: 信息协调与隐私放大

如果错误率在可接受范围内:
  1. 信息协调: 使用Cascade等纠错码纠正剩余的比特错误
  2. 隐私放大: 使用通用哈希函数压缩密钥，消除窃听者可能获取的有限信息

最终结果: Alice和Bob共享完全安全的密钥K
```

### BB84实现示例

```python
# BB84协议简化实现概念（非真实量子硬件）

import random
import hashlib

class BB84_Simulator:
    def __init__(self, length=100):
        self.length = length
        self.bases = ['+', '×']
        self.bits = []
        self.alice_bases = []
        self.bob_bases = []
        self.bob_bits = []

    def alice_prepare(self):
        """Alice制备和发送光子"""
        self.alice_bases = [random.choice(self.bases)
                           for _ in range(self.length)]
        self.bits = [random.randint(0, 1)
                    for _ in range(self.length)]
        return self.alice_bases, self.bits

    def bob_measure(self):
        """Bob随机选择基测量"""
        self.bob_bases = [random.choice(self.bases)
                         for _ in range(self.length)]
        # 基匹配时正确接收，不匹配时50%错误
        self.bob_bits = []
        for i in range(self.length):
            if self.alice_bases[i] == self.bob_bases[i]:
                self.bob_bits.append(self.bits[i])
            else:
                self.bob_bits.append(random.randint(0, 1))

    def basis_reconciliation(self):
        """基比对，保留匹配位"""
        matching_indices = []
        for i in range(self.length):
            if self.alice_bases[i] == self.bob_bases[i]:
                matching_indices.append(i)
        return matching_indices

    def estimate_qber(self, matching_indices, sample_ratio=0.5):
        """估计量子误码率"""
        sample_size = int(len(matching_indices) * sample_ratio)
        sample = random.sample(matching_indices, sample_size)
        errors = sum(1 for i in sample
                    if self.bits[i] != self.bob_bits[i])
        return errors / sample_size if sample_size > 0 else 0

    def privacy_amplification(self, raw_key, output_length=128):
        """隐私放大：使用SHA-256压缩密钥"""
        key_bytes = ''.join(str(b) for b in raw_key).encode()
        return hashlib.sha256(key_bytes).digest()

# 模拟BB84
bb84 = BB84_Simulator(1000)
bb84.alice_prepare()
bb84.bob_measure()
matching = bb84.basis_reconciliation()
qber = bb84.estimate_qber(matching, 0.3)

print(f"总光子数: 1000")
print(f"基匹配数: {len(matching)}")
print(f"QBER: {qber:.2%}")

if qber < 0.11:
    raw_key = [bb84.bits[i] for i in matching
              if i not in random.sample(
                  matching, int(len(matching) * 0.3))]
    secure_key = bb84.privacy_amplification(raw_key)
    print(f"安全密钥: {secure_key.hex()}")
else:
    print("警告: 检测到窃听！丢弃密钥")
```

## E91协议（基于纠缠）

E91协议由Artur Ekert于1991年提出，使用量子纠缠态的EPR对实现密钥分发：

```
Alice ←─── 纠缠光子对 ───→ Bob
               ↑
           纠缠源
  （位于Alice、Bob或第三方）

原理:
  1. 纠缠源产生Bell态光子对 |Φ⁺⟩ = (|00⟩ + |11⟩)/√2
  2. Alice和Bob分别测量各自的光子
  3. Alice测得|0⟩时，Bob一定测得|0⟩（量子关联性）
  4. 使用CHSH不等式检测纠缠破坏（即窃听）
  5. 基匹配部分的测量结果构成共享密钥

优势:
  - 不需要信任光源（纠缠源可交由不可信第三方）
  - 更高的安全性保证（基于Bell不等式）
  - 更适合量子中继和量子网络
```

## QKD网络部署

### 点对点QKD

最基本的QKD部署方式，两台QKD设备通过光纤直连：

```yaml
物理层限制:
  最大距离: 100-200 km（光纤）
  限制原因: 量子信号无法放大（量子不可克隆定理）
  信号衰减: ~0.2 dB/km (标准单模光纤在1550nm)
  
速率限制:
  100 km: ~10 kbps (实际安全密钥率)
  50 km: ~100 kbps
  10 km: ~1 Mbps
  影响因素: 探测器效率、暗计数、系统噪声
```

### 可信中继QKD

为突破距离限制，使用中间节点作为可信中继：

```
[A站点] ─── 100km ─── [中继节点] ─── 100km ─── [B站点]
  |                     |                      |
  |←─── 共享密钥K1 ───→|                       |
  |                     |←─── 共享密钥K2 ───→  |
  |                     |                      |
  |  ←─── K = K1 ⊕ K2 ───→                   |
```

**安全假设**：
- 中继节点必须是**可信的**
- 如果中继被攻破，密钥不再安全
- 使用多个中继时，只需要**至少一个**中继可信

### 卫星QKD

卫星QKD通过大气信道实现远程量子密钥分发：

```
墨子号量子科学实验卫星 (2016年发射):

关键成果:
  · 星地量子纠缠分发: 1200 km
  · 星地QKD: 双向密钥分发
  · 纠缠源在轨运行: 6 ns时间同步
  · 量子隐形传态: 地面站之间

技术挑战:
  · 大气湍流对光子偏振态的干扰
  · 白天光子被太阳光淹没
  · 卫星与地面跟踪精度要求极高
  · 窄束发散
```

#### 卫星QKD流程

```
1. 卫星上的纠缠源产生纠缠光子对
2. 卫星同时向两个地面站发送纠缠光子
3. 两个地面站独立测量接收到的光子
4. 通过经典信道比对基信息
5. 基匹配的测量结果形成共享密钥
6. 卫星位置、大气条件影响密钥生成率

北京站 ←── 量子链路 ──→ 卫星 ──→ 维也纳站
 (为了纠错)            (1200km)   (纠缠分发)
```

## QKD局限性

| 限制 | 描述 | 当前解决方案 |
|------|------|-------------|
| 距离限制 | 光纤QKD最大~200km | 可信中继、量子中继（实验） |
| 速率限制 | 安全密钥率低（100km约10kbps） | 高效率探测器、WDM复用 |
| 硬件成本 | 单光子探测器极其昂贵 | InGaAs APD、SNSPD |
| 频率同步 | 需要ns级时间同步 | GPS/北斗授时 |
| 噪声敏感 | 环境光子、温度、振动 | 屏蔽、滤波、符合计数 |
| 侧信道攻击 | 探测器控制、亮盲攻击 | 探测器监控、测量设备无关QKD |
| 认证要求 | 经典信道需要认证 | 预置密钥、PQC辅助认证 |
| 隐蔽信道 | 公开通信可能泄露信息 | 信息论安全的隐私放大 |

### 几种QKD攻击类型

| 攻击名称 | 攻击方式 | 防御方法 |
|---------|---------|---------|
| 光子数分离（PNS） | 分离多光子脉冲 | 诱骗态协议 |
| 亮盲攻击 | 用强光致盲探测器 | 探测器监控、随机基选择 |
| 时移攻击 | 操控光子到达时间 | 时间窗监控 |
| 波长攻击 | 利用探测器波长依赖 | 光谱滤波 |
| 木马攻击 | 向Alice注入光信号 | 隔离器、光监控 |

## QKD与PQC的互补关系

QKD和PQC不是替代关系，而是互补的防御手段：

| 对比维度 | QKD | PQC (Lattice-based) |
|---------|-----|--------------------|
| 安全基础 | 量子物理定律 | 数学困难问题 |
| 安全假设 | 量子力学正确 | 格问题难解（非证明） |
| 实现方式 | 专用硬件（昂贵） | 软件算法（低成本） |
| 密钥速率 | ~kbps级（受距离限制） | Mbps-Gbps级 |
| 传输距离 | <200km（需中继） | 无距离限制 |
| 应用场景 | 政府/金融/能源骨干网 | 通用网络通信 |
| 成熟度 | 小规模商用 | 标准化完成，大规模部署 |
| 抗量子攻击 | 理论上绝对安全 | 对抗已知量子算法 |

### 混合方案建议

在实际部署中，建议同时使用QKD和PQC实现纵深防御：

```
[Alice]                                      [Bob]
   |                                           |
   |── QKD信道 ─────────────────────────────→ |
   |   (量子密钥K_qkd)                        |
   |                                           |
   |── PQC信道 ─────────────────────────────→ |
   |   (PQC封装会话密钥K_pqc)                  |
   |                                           |
   |  最终密钥 = KDF(K_qkd || K_pqc)          |
   |                                           |
   |  安全性: 量子物理 + 格密码的双保险        |
```

## 总结

QKD利用量子力学基本原理实现了理论上信息论安全的密钥分发。BB84协议作为最成熟的QKD协议已在多个城域网和远程卫星链路中成功验证。然而QKD面临距离限制、硬件成本和实际系统安全性的挑战。QKD与PQC并非对立而是互补——QKD提供物理层安全保障，PQC提供可扩展的软件密码学支持。在构建未来量子安全网络基础设施时，两者协同部署是最佳策略。
