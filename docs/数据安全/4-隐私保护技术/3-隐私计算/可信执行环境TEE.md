# 可信执行环境 (Trusted Execution Environment, TEE)

## TEE 定义

**可信执行环境 (Trusted Execution Environment, TEE)** 是 CPU 硬件层面提供的一个安全区域 (secure enclave)，确保在内部加载的代码和数据在机密性和完整性方面受到硬件级保护，即使操作系统或 hypervisor 被攻破也无法访问 enclave 内部的数据。

## TEE 实现对比

### Intel SGX (Software Guard Extensions)
- **架构**：CPU 创建称为 enclave 的受保护内存区域。
- **内存限制**：EPC (Enclave Page Cache) 大小有限（SGX1 约 128MB，SGX2 支持动态扩展）。
- **安全假设**：信任 Intel CPU，对操作系统和 BIOS 不信任。
- **威胁模型**：Enclave 代码和数据的机密性 + 完整性。

### ARM TrustZone
- **架构**：将物理处理器分为 Normal World（富操作系统）和 Secure World（可信应用）。
- **内存隔离**：通过硬件总线级别隔离实现。
- **优势**：在移动设备领域广泛应用（Android 设备中的指纹、支付处理）。
- **劣势**：上下文切换开销较大。

### AMD SEV-SNP (Secure Encrypted Virtualization-Secure Nested Paging)
- **架构**：在虚拟机级别提供加密隔离，每个 VM 拥有独立的加密密钥。
- **优势**：无需修改客户操作系统即可使用。
- **适用**：云环境中的虚拟机隔离。

## TCB 比较

**可信计算基础 (Trusted Computing Base, TCB)** 指系统安全所必须信任的软硬件组件：

| TEE 方案 | TCB 大小 | 信任链 |
|----------|---------|--------|
| Intel SGX | 最小（仅 CPU 微码） | CPU → Enclave 代码 |
| ARM TrustZone | 中等（Secure Monitor + Secure OS）| 硬件 → Secure OS → TA |
| AMD SEV-SNP | 中等（CPU + 固件） | CPU → 固件 → VM |
| 软件 TEE (如 Gramine) | 较大（包含库操作系统） | CPU → 库操作系统 → 应用 |

## 远程证明

**远程证明 (Remote Attestation)** 是 TEE 的核心功能，允许远程验证者确认：

1. **代码完整性** — Enclave 内运行的代码是预期的未经篡改的版本。
2. **硬件真实性** — 代码真正运行在 TEE 硬件中而非模拟环境。

Intel SGX 的远程证明流程：
1. Enclave 向 quoting enclave (QE) 请求 quote。
2. QE 使用 EPID (Enhanced Privacy ID) 或 DCAP (Data Center Attestation Primitives) 签名 quote。
3. 验证方联系 Intel Attestation Service (IAS) 验证签名。
4. 验证方接收验证结果并决定是否信任该 enclave。

## 内存加密

TEE 使用硬件级内存加密保护 enclave 数据：

- **MEE (Memory Encryption Engine)** — Intel SGX 使用 MEE 在 memory controller 层面对 EPC 进行加密和完整性校验。
- **AEAD 加密** — 使用 AES-GCM 等方案保障机密性和完整性。
- **内存加解密延迟** — 约为 5-10% 性能开销。

## 侧信道漏洞与缓解

### 已知攻击
- **Foreshadow / L1TF** — 从 L1 cache 恢复 enclave 数据。
- **SGAxe / CacheOut** — 从 CPU 缓存中提取 SGX 数据。
- **Plundervolt** — 通过电压操控诱导 CPU 错误。

### 缓解措施
- 及时应用 Intel/AMD 微码更新。
- 使用 constant-time 编程避免时序泄漏。
- 对数据访问模式进行混淆处理（Oblivious RAM, ORAM）。
- 在安全敏感的 TEE 代码中加入数据无关的执行路径。

**结论**：TEE 为隐私计算提供了强大的硬件信任基座，尤其适合需要高性能计算的场景，但需关注侧信道攻击和 TCB 管理。
