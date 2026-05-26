# 可信执行环境 (TEE)

## 概述

可信执行环境 (Trusted Execution Environment, TEE) 通过硬件级隔离在 CPU 内创建安全区域（Enclave），保证代码和数据在运行时免受主机操作系统、管理程序和其他进程的访问。TEE 为隐私计算提供了接近明文性能的安全执行方案。

## Intel SGX / ARM TrustZone / AMD SEV 对比

| 特性 | Intel SGX | ARM TrustZone | AMD SEV |
|------|-----------|---------------|---------|
| 隔离粒度 | Enclave (进程级) | Normal World / Secure World | VM 级 |
| 内存加密 | 硬件内存加密引擎 | Secure World 独占加密 | AES-256 加密引擎 |
| 信任根 | CPU 固件 | TrustZone 安全世界 | AMD 安全处理器 (PSP) |
| 远程证明 | Intel Attestation Service | Mbed TLS PA | AMD SEV-SNP Attestation |
| 最大 Enclave 内存 | 128-512 MB (EPC) | 整个 Secure World | 全量 VM 内存 |
| 主机兼容性 | 需 Intel CPU (6th gen+) | ARM SoC | AMD EPYC CPUs |
| 适用场景 | 应用级隔离 | 移动端安全 | 虚拟机保护 |
| 攻击面 | L1TF/Foreshadow/SGX FEP | TrustZone 侧信道 | SEV-ES/SNP 增强 |

### 内存加密对比

| 技术 | 加密粒度 | 密钥管理 | 性能影响 |
|------|----------|----------|----------|
| SGX MEE | 128-bit 块 | CPU 内部密钥 | 5-10% (密集内存访问) |
| SEV-ES | 缓存行级 | AMD PSP 管理 | 5-15% (全内存加密) |
| TrustZone | 区域级 | SoC 安全控制器 | 1-5% |
| TME (Total Memory Encryption) | 缓存行级 | CPU 内部 | < 1% |

## Trusted Computing Base (TCB)

TCB 是系统安全依赖的硬件和软件组件的总和。TEE 的目标是最小化 TCB。

### TCB 范围对比

```
传统架构 TCB:
  [BIOS/UEFI] + [Hypervisor] + [OS Kernel] + [Drivers] + [App Runtime] = Large TCB

SGX TCB:
  [CPU Hardware] + [Intel ME Firmware] = Minimal TCB
  
SEV TCB:
  [CPU Hardware] + [AMD PSP] + [Hypervisor (部分)] = Small TCB

TrustZone TCB:
  [CPU Hardware] + [Secure World Software] + [Monitor Mode] = Moderate TCB
```

### TCB 攻击面

| TCB 组件 | 潜在风险 | 缓解措施 |
|----------|----------|----------|
| CPU 微代码 | 微代码更新引入漏洞 | 只接受签名更新 |
| TEE Firmware | 固件漏洞 | 及时更新 + 迁移 |
| 内存控制器 | 物理攻击 | 封装内存（非所有 TEE） |
| 缓存 | 侧信道攻击 | flush 指令 + 恒定时间代码 |
| 片上网络 | 窥探攻击 | 加密片上总线 |

## 远程证明 (Attestation)

远程证明允许远程验证方确认 Enclave 运行在真实的 TEE 环境中且未被篡改。

### SGX 远程证明流程

```
Client (Verifier)                    
    │                                    SGX Platform
    │  Request Proof                         │
    │─────────────────────────────────────→  │
    │                                        │ 1. Quote Provider 收集
    │                                        │    硬件度量 (MRENCLAVE, MRSIGNER)
    │                                        │ 2. EPID 群签名生成 Quote
    │  ←── 返回 Quote (Attestation Data) ───│
    │                                        │
    │ 3. 发送 Quote 到 IAS (Intel Attestation Service)
    │    IAS 验证:
    │    - EPID 群签名有效性
    │    - TCB 是否在撤销列表
    │    - 度量值与期望值一致
    │ 4. IAS 返回 Verification Report
    │
    │ 5. 建立安全信道 (基于证明结果)
```

### 证明类型

| 证明类型 | 说明 | 适用场景 |
|----------|------|----------|
| 本地证明 (Local Attestation) | 同一平台内 Enclave 间验证 | 多 Enclave 协作 |
| 远程证明 (Remote Attestation) | 跨平台验证 | 云服务、数据提供方 |
| 组证明 (Group Attestation) | 证明 Enclave 属于特定组 | 多方联合计算 |
| 连续证明 (Continuous Attestation) | 运行时周期性验证 | 高安全要求场景 |

## 内存加密与隔离

### Enclave 内存保护机制

```
Normal Memory (不受保护)
  ┌────────────────────────┐
  │ OS Kernel              │
  │ User Processes         │
  │ ...                    │
  └────────────────────────┘

Enclave Memory (EPC)
  ┌────────────────────────┐
  │ Enclave Code + Data    │ ← 硬件加密和解密
  │ CPU Encryption Engine  │ ← 集成在 CPU 中
  │ Memory Encryption Key  │ ← CPU 内部、OS 不可访问
  └────────────────────────┘
    ↓
  内存加密:
  - 加密: CPU 将明文写入 EPC 时自动加密
  - 解密: CPU 从 EPC 读取时自动解密
  - 完整性: 对所有 EPC 访问进行 MAC 校验
```

## 侧信道攻击

### 已知攻击向量

| 攻击名称 | 目标 | 方法 | 缓解状态 |
|----------|------|------|----------|
| Spectre (CVE-2017-5753) | 所有 CPU | 分支预测推断 | 微代码 + 软件缓解 |
| Meltdown (CVE-2017-5754) | Intel CPU | 乱序执行越权 | 内核页表隔离 (KPTI) |
| Foreshadow (CVE-2018-3615) | SGX | L1 缓存推断 | 微代码 + L1 刷新 |
| SGAxe (CVE-2020-0561) | SGX | 缓存侧信道 + LVI | 微代码 + enclave 代码加固 |
| PLATYPUS (CVE-2021-0123) | SGX | 功耗侧信道 | 固件更新 + 限制 RAPL 访问 |
| AEPIC Leak (CVE-2023-27504) | AMD SEV | APIC 侧信道 | SEV-SNP + 固件更新 |

### 防御策略

```
硬件层:
  - CPU 微代码更新
  - L1 缓存刷写 (VERW 指令)
  - 降低计时器精度

软件层:
  - 恒定时间代码 (避免与秘密数据相关的分支/内存访问)
  - Enclave 敏感数据使用后 clear 内存
  - 使用 oblivious 数据结构和访问模式

架构层:
  - 迁移至新 CPU 代次 (SGX TME, SEV-SNP)
  - 混合方案: TEE + 差分隐私 (即使 TEE 被攻破仍有限制)
```

## 参考标准

- GlobalPlatform TEE System Architecture
- Intel SGX Documentation (SDK/PSW/DCAP)
- AMD SEV-SNP Whitepaper (Secure Encrypted Virtualization)
- NIST SP 800-207 (Zero Trust Architecture, TEE 章节)
- Confidential Computing Consortium (CCC) 规范
