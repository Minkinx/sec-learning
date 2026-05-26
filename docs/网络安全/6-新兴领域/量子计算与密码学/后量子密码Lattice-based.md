# 后量子密码：Lattice-based密码学

## 概述

后量子密码（PQC）是指能够抵抗量子计算机攻击的密码算法。在NIST的PQC标准化进程中，基于格（Lattice-based）的密码学成为主要技术路线，CRYSTALS-Kyber（密钥封装机制）和CRYSTALS-Dilithium（数字签名）已被选为标准算法。

## 格密码理论基础

### 什么是格

格（Lattice）是n维欧几里得空间中具有周期结构的离散子群。形式上，格由一组线性无关的基向量生成：

```
L(b₁, b₂, ..., bₙ) = { Σ xᵢbᵢ | xᵢ ∈ ℤ }

其中 b₁, b₂, ..., bₙ 是格的基向量
所有整系数线性组合构成整个格
```

### 核心困难问题

#### 最短向量问题（SVP）

在格中寻找最短的非零向量。在高维格中，这是一个公认的困难问题。

```
给定格 L 的基 B:
  寻找 v ∈ L 使得 ||v|| 最小且 v ≠ 0
  
  二维直观: 在二维平面上分布的点阵中
  找到离原点最近的那个点
```

#### 学习带误差问题（LWE）

LWE由Oded Regev在2005年提出，是格密码领域最具影响力的困难问题：

```
给定:
  随机矩阵 A (m × n)
  秘密向量 s (n维)
  误差向量 e (小噪声)
  
  计算 b = A·s + e (mod q)
  
困难问题: 已知 A 和 b, 恢复 s
  
  直观理解: 求解带噪声的线性方程组
  没有噪声: 高斯消元轻松求解
  加入噪声: 问题变得极其困难
```

#### 环LWE（Ring-LWE）

Ring-LWE是LWE在多项式环上的变体，密钥更小，计算效率更高：

```
场景: 在环 R = ℤq[x]/(xⁿ + 1) 上操作
  
  一次Ring-LWE操作相当于n次LWE操作
  密钥和密文尺寸缩小n倍
  Kyber和Dilithium都基于Module-LWE（Ring-LWE的模块化版本）
```

## CRYSTALS-Kyber (ML-KEM / FIPS 203)

### 概述

Kyber是基于Module-LWE的密钥封装机制（KEM），2024年被NIST选为FIPS 203标准的ML-KEM算法。它用于安全建立共享密钥，替代当前TLS中使用的ECDH。

### 参数与安全等级

| 实例 | NIST等级 | 量子安全等价 | 公钥大小 | 密文大小 |
|------|---------|-------------|---------|---------|
| Kyber-512 | Level 1 | AES-128 | 800字节 | 768字节 |
| Kyber-768 | Level 3 | AES-192 | 1184字节 | 1088字节 |
| Kyber-1024 | Level 5 | AES-256 | 1568字节 | 1568字节 |

对比RSA-2048：公钥256字节，但Kyber的密钥生成和封装/解封装操作快得多。

### 算法流程

```
Kyber.KeyGen()
  1. 生成随机种子 d
  2. 从d扩展生成矩阵 A ∈ Rq^(k×k)
  3. 从中心二项分布采样 s, e
  4. 计算 t = A·s + e
  5. 公钥: pk = (t, d), 私钥: sk = s

Kyber.Encaps(pk)
  1. 生成随机消息 m ∈ {0,1}²⁵⁶
  2. 计算哈希 H(m) 生成r
  3. 从r扩展生成 s', e', e''
  4. 计算 u = Aᵀ·s' + e'
  5. 计算 v = tᵀ·s' + e'' + Decompress(m)
  6. 计算共享密钥 K = H(s', H(m))
  7. 密文: c = (u, v)

Kyber.Decaps(sk, c)
  1. 从密文c恢复 u, v
  2. 计算 m' = v - sᵀ·u
  3. 重新封装验证
  4. 计算共享密钥 K
```

### 性能对比

```yaml
操作速度对比 (Intel Xeon @ 3.0GHz):
  Kyber-768 KeyGen:  ~80,000 ops/sec
  Kyber-768 Encaps:  ~65,000 ops/sec
  Kyber-768 Decaps:  ~55,000 ops/sec
  
  RSA-2048 KeyGen:   ~500 ops/sec  (慢2个数量级)
  RSA-2048 Encrypt:  ~25,000 ops/sec
  RSA-2048 Decrypt:  ~1,500 ops/sec
  
  ECDH X25519:       ~100,000 ops/sec
  ECDH P-256:        ~70,000 ops/sec
  ECDH P-384:        ~18,000 ops/sec
```

## CRYSTALS-Dilithium (ML-DSA / FIPS 204)

### 概述

Dilithium是基于Module-LWE + Module-SIS的数字签名算法，被NIST选为FIPS 204标准的ML-DSA。它主要用于替代RSA、ECDSA和EdDSA进行数字签名认证。

### 参数与签名大小

| 实例 | NIST等级 | 公钥大小 | 签名大小 | 私钥大小 |
|------|---------|---------|---------|---------|
| Dilithium-2 | Level 2 | 1312字节 | 2420字节 | 2528字节 |
| Dilithium-3 | Level 3 | 1952字节 | 3293字节 | 4000字节 |
| Dilithium-5 | Level 5 | 2592字节 | 4595字节 | 4864字节 |

对比RSA-2048签名（256字节）和ECDSA P-256签名（64字节），Dilithium的签名明显更大。

### 签名流程

```
Dilithium.Sign(sk, M)
  1. 计算 μ = H(tr || M)     // tr: 公钥哈希
  2. 生成随机掩码 r' 和 y
  3. 计算 w = A·y (高精度)
  4. 计算 c = H(μ || w₁)     // w₁: w的高位
  5. 计算 z = y + c·s₁
  6. 拒绝采样（确保z不泄露密钥信息）
  7. 签名: σ = (z, h, c)     // h: 提示位

Dilithium.Verify(pk, M, σ)
  1. 计算 μ = H(tr || M)
  2. 计算 w'₁ = HighBits(A·z - c·t)
  3. 计算 c' = H(μ || w'₁)
  4. 验证 c == c'
  5. 验证 z 在允许范围内
```

### 签名大小对比

```
签名算法          | 签名大小 | 公钥大小 | 验证速度
─────────────────────────────────────────────
RSA-2048          | 256 B    | 256 B   | 慢
RSA-4096          | 512 B    | 512 B   | 很慢
ECDSA P-256       | 64 B     | 32 B    | 快
Ed25519           | 64 B     | 32 B    | 非常快
Dilithium-2       | 2.4 KB   | 1.3 KB  | 快
Dilithium-3       | 3.3 KB   | 1.9 KB  | 快
Falcon-512        | 666 B    | 897 B   | 非常快
SPHINCS+-128s     | 8 KB     | 32 B    | 慢
```

## NIST PQC标准化

### 选型与评价

NIST的PQC标准化进程分为多个轮次：

| 轮次 | 时间 | 事件 |
|------|------|------|
| 第1轮 | 2017年 | 收到69个候选算法 |
| 第2轮 | 2019年 | 缩小到26个候选 |
| 第3轮 | 2020-2022年 | 缩小到7个决赛算法 |
| 第1批标准 | 2024年 | 选定Kyber (KEM) + Dilithium (签名) |
| 第4轮 | 2024+ | 评估备用算法 |

### 最终标准化算法

```
NIST FIPS 203: ML-KEM (Kyber)
  - 类型: 密钥封装机制 (KEM)
  - 基础: Module-LWE
  - 用途: TLS密钥协商、通用密钥封装

NIST FIPS 204: ML-DSA (Dilithium)
  - 类型: 数字签名
  - 基础: Module-LWE + Module-SIS
  - 用途: 通用数字签名、认证

NIST FIPS 205: SLH-DSA (SPHINCS+)
  - 类型: 数字签名（备用）
  - 基础: 哈希函数（无格假设）
  - 用途: 格密码备选方案

NIST FIPS 206: FN-DSA (FALCON)
  - 类型: 数字签名（紧凑）
  - 基础: 格 (NTRU)
  - 用途: 需要小签名的场景
```

### 第4轮评估算法

NIST正在评估备用KEM算法，以防上述格密码算法未来被破解：

| 算法 | 类型 | 特点 |
|------|------|------|
| BIKE | 基于编码 | 小尺寸密钥，基于QC-MDPC码 |
| Classic McEliece | 基于编码 | 极大公钥（~1MB），极小密文 |
| HQC | 基于编码 | 中等尺寸，保守安全性 |

## PQC算法对比总览

| 算法 | 类型 | 基础问题 | 密钥/签名大小 | 速度 | 特点 |
|------|------|---------|-------------|------|------|
| **Kyber** | KEM | Lattice (MLWE) | 中小 | 很快 | 首选KEM |
| **Dilithium** | 签名 | Lattice (MLWE+SIS) | 大签名 | 快 | 首选签名 |
| Falcon | 签名 | Lattice (NTRU) | 小签名 | 验证很快 | 紧凑签名 |
| SPHINCS+ | 签名 | 哈希 | 大签名 | 慢 | 保守安全 |
| Classic McEliece | KEM | 编码 | 巨大公钥 | 快 | 最保守 |
| BIKE | KEM | 编码 | 中小 | 中等 | 备用 |

## 混合模式迁移

### 混合TLS

在实际部署中，推荐使用混合模式（经典 + PQC同时使用）：

```
TLS 1.3 混合密钥交换模式:

  Client                                  Server
    |                                      |
    |------ ClientHello ------------------>|
    |      KeyShare:                       |
    |        - X25519 (经典)               |
    |        - Kyber-768 (PQC)            |
    |                                      |
    |<---- ServerHello --------------------|
    |      KeyShare:                       |
    |        - X25519 共享密钥              |
    |        - Kyber-768 密文              |
    |                                      |
    | 计算会话密钥:                         |
    |   HKDF(X25519_secret || Kyber_secret) |
    |                                      |
    |  安全性 = min(X25519安全, Kyber安全)   |
    |  两者都安全则连接安全                  |
```

```python
# 使用OpenSSL (3.2+) 的Hybrid配置示例

# 服务端配置
server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
server_context.set_ciphers('TLS_AES_256_GCM_SHA384')
server_context.set_ecdh_curve('X25519MLKEM768')

# 客户端配置
client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
client_context.set_ecdh_curve('X25519MLKEM768')
```

### PQC在DNSSEC中的应用

```yaml
DNSSEC迁移到PQC:
  当前: RSA/SHA-256 (DNSSEC signing)
  目标: Dilithium或Falcon (PQC签名)

  挑战:
    - DNSSEC的UDP数据包大小限制（512/1232字节）
    - Dilithium-2签名2420字节远超限制
    - 需要EDNS0扩展或TCP回退
    - Falcon-512签名666字节更具可行性

  混合签名策略:
    1. 同时签名RSA + Dilithium
    2. 验证时检查任一签名有效即可
    3. 过渡期后移除RSA签名
```

### PQC在代码签名中的应用

```bash
# 使用Dilithium/ML-DSA进行代码签名

# 生成Dilithium密钥对
openssl genpkey -algorithm dilithium3 \
    -out code_signing_private.pem

# 提取公钥
openssl pkey -in code_signing_private.pem \
    -pubout -out code_signing_public.pem

# 使用双签名（PQC + RSA）用于迁移
# 原文签名 - 使用Dilithium
openssl pkeyutl -sign -inkey code_signing_private.pem \
    -in binary_file.bin -out binary_file.dilithium.sig

# 同时使用RSA签名（向后兼容）
openssl pkeyutl -sign -inkey rsa_key.pem \
    -in binary_file.bin -out binary_file.rsa.sig

# 验证
openssl pkeyutl -verify -pubin -inkey code_signing_public.pem \
    -in binary_file.bin -sigfile binary_file.dilithium.sig
```

## 总结

格密码（Lattice-based cryptography）是后量子密码学的核心技术路线。Kyber和Dilithium作为NIST首批标准化的PQC算法，为TLS密钥协商、数字签名和通用加密提供了量子安全替代方案。虽然它们的密钥和签名尺寸大于经典算法，但在计算性能上具有竞争力，甚至在某些场景下超越RSA。组织应开始实验混合模式的PQC部署，在真正需要的场景（长期数据保护、长寿命系统）优先迁移，同时保持密码敏捷性以应对未来可能的标准更新。
