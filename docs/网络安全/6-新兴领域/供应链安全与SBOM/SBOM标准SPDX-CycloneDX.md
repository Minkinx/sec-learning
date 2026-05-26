# SBOM标准：SPDX与CycloneDX

## SBOM概述

SBOM（Software Bill of Materials，软件物料清单）是软件组件、许可证、依赖关系和已知漏洞的详细清单。它借鉴了制造业的物料清单概念，在软件供应链安全中扮演着核心角色。

### SBOM的核心用途

| 用途 | 描述 | 受益方 |
|------|------|--------|
| 漏洞管理 | 快速识别受CVE影响的组件 | 安全团队 |
| 许可证合规 | 管理开源许可证兼容性问题 | 法务团队 |
| 组件审计 | 盘点所有第三方依赖 | 开发团队 |
| 供应链透明 | 了解软件供应链构成 | 采购/合规 |
| 风险评估 | 评估依赖的维护活跃度和安全性 | 管理层 |

### SBOM的最小元素

```
┌───────────────────────────────┐
│           SBOM                │
├───────────────────────────────┤
│ · 供应商名称                   │
│ · 组件名称和版本               │
│ · 唯一标识符（PURL, CPE, SWID）│
│ · 依赖关系                     │
│ · SBOM作者和创建时间           │
│ · 许可证信息                   │
└───────────────────────────────┘
```

## SPDX标准

### 概述

SPDX（Software Package Data Exchange）由Linux Foundation发起的SPDX工作组维护，是国际上最成熟的SBOM标准。SPDX 2.2版本在2021年成为ISO/IEC 5962国际标准。

### SPDX 2.3规范

SPDX 2.3文档包含多个核心信息域：

| 域 | 描述 | 必需性 |
|----|------|--------|
| Document Creation | 文档创建信息 | 必需 |
| Package Information | 包元数据 | 条件必需 |
| File Information | 文件级别信息 | 可选 |
| Snippet Information | 代码片段信息 | 可选 |
| Relationship | 组件间关系 | 条件必需 |
| Annotation | 注释/审计记录 | 可选 |
| License Information | 许可证声明 | 必需 |

### SPDX Tag:Value格式示例

```spdx
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: my-application-1.0.0
DocumentNamespace: http://spdx.org/spdxdocs/my-app-1.0.0-abc123

## Package: my-application
PackageName: my-application
SPDXID: SPDXRef-Package-Main
PackageVersion: 1.0.0
PackageSupplier: Person: Example Corp
PackageDownloadLocation: git+https://github.com/example/my-app.git
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
PackageCopyrightText: Copyright 2024 Example Corp

## Package: log4j-core
PackageName: log4j-core
SPDXID: SPDXRef-Package-log4j
PackageVersion: 2.17.0
PackageSupplier: Organization: Apache Software Foundation
PackageDownloadLocation: https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.17.0/
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
ExternalRef: SECURITY cpe23Type cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*
ExternalRef: PACKAGE pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0

## Relationship
Relationship: SPDXRef-Package-Main DEPENDS_ON SPDXRef-Package-log4j
```

### SPDX JSON格式

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-application-1.0.0",
  "packages": [
    {
      "name": "my-application",
      "SPDXID": "SPDXRef-Package-Main",
      "versionInfo": "1.0.0",
      "licenseConcluded": "Apache-2.0",
      "licenseDeclared": "Apache-2.0",
      "supplier": "Person: Example Corp",
      "downloadLocation": "git+https://github.com/example/my-app.git",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:github/example/my-app@1.0.0"
        }
      ]
    },
    {
      "name": "log4j-core",
      "SPDXID": "SPDXRef-Package-log4j",
      "versionInfo": "2.17.0",
      "licenseConcluded": "Apache-2.0",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-Package-Main",
      "relatedSpdxElement": "SPDXRef-Package-log4j",
      "relationshipType": "DEPENDS_ON"
    }
  ]
}
```

### SPDX 3.0

SPDX 3.0（2023年发布）是重大版本更新，引入了基于Profile的简化方法：

- **Core Profile**: 所有实现必须支持的基础功能
- **Software Profile**: 软件包和文件建模
- **Licensing Profile**: 许可证信息
- **Security Profile**: 漏洞引用和评估
- **Build Profile**: 构建信息出处

```json
// SPDX 3.0 简化结构（JSON-LD）
{
  "@type": "Software_Package",
  "spdxId": "urn:example:1.0.0#package-log4j",
  "name": "log4j-core",
  "version": "2.17.0",
  "supplier": {
    "@type": "Organization",
    "name": "Apache Software Foundation"
  },
  "security": {
    "cve": "urn:example:1.0.0#cve-2021-44228"
  }
}
```

## CycloneDX标准

### 概述

CycloneDX由OWASP基金会维护，是面向安全分析的SBOM标准。相比SPDX的合规/许可证侧重点，CycloneDX更关注安全漏洞管理和依赖关系分析。

### 格式支持

CycloneDX支持XML、JSON和Protocol Buffers三种序列化格式：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5"
     serialNumber="urn:uuid:3e671687-395b-41f5-a30f-589c0ce1b7c5"
     version="1">
  <metadata>
    <timestamp>2024-01-15T10:00:00Z</timestamp>
    <tools>
      <tool>
        <vendor>anchore</vendor>
        <name>syft</name>
        <version>0.80.0</version>
      </tool>
    </tools>
    <component type="application">
      <name>my-application</name>
      <version>1.0.0</version>
      <purl>pkg:github/example/my-app@1.0.0</purl>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0">
      <name>log4j-core</name>
      <version>2.17.0</version>
      <purl>pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0</purl>
      <licenses>
        <license>
          <id>Apache-2.0</id>
        </license>
      </licenses>
    </component>
  </components>
  <dependencies>
    <dependency ref="pkg:github/example/my-app@1.0.0">
      <dependency ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"/>
    </dependency>
  </dependencies>
  <vulnerabilities>
    <vulnerability ref="urn:uuid:...">
      <id>CVE-2021-44228</id>
      <ratings>
        <rating>
          <severity>critical</severity>
          <score>10.0</score>
          <method>CVSSv3</method>
        </rating>
      </ratings>
    </vulnerability>
  </vulnerabilities>
</bom>
```

### CycloneDX JSON示例

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-589c0ce1b7c5",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z",
    "component": {
      "type": "application",
      "name": "my-application",
      "version": "1.0.0",
      "purl": "pkg:github/example/my-app@1.0.0",
      "properties": [
        {"name": "src:sha256", "value": "a1b2c3d4..."}
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.17.0",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "evidence": {
        "identity": {
          "field": "purl",
          "confidence": 1.0,
          "methods": [
            {"technique": "manifest-analysis", "value": "pom.xml"}
          ]
        }
      }
    },
    {
      "type": "library",
      "name": "jackson-databind",
      "version": "2.13.0",
      "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:github/example/my-app@1.0.0",
      "dependsOn": [
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0"
      ]
    }
  ]
}
```

### 核心特性

CycloneDX的特点包括：

1. **组件类型丰富**：library, framework, OS, device, container, file, service
2. **依赖关系图**：完整的有向无环依赖关系
3. **漏洞关联**：BOM-link机制建立SBOM产物与漏洞的关系
4. **谱系信息**：组件来源和历史记录
5. **元数据**：构建时间、工具信息、属性扩展

| 组件类型 | 适用场景 | 示例 |
|---------|---------|------|
| library | 第三方库 | npm包、JAR文件 |
| framework | 开发框架 | Spring Boot, React |
| OS | 操作系统 | Ubuntu 22.04, Alpine 3.18 |
| container | 容器镜像 | Docker镜像层 |
| file | 特定文件 | 配置文件、二进制文件 |
| service | 外部服务 | AWS S3, PostgreSQL |

## 标准对比

| 维度 | SPDX | CycloneDX |
|------|------|-----------|
| 维护组织 | Linux Foundation | OWASP |
| ISO标准 | ISO/IEC 5962 | 否（事实标准） |
| 侧重点 | 许可证合规、法律 | 安全、漏洞管理 |
| 许可证字段 | 详细、多层 | 简洁 |
| 依赖关系 | 基础支持 | 完整图结构 |
| 漏洞引用 | Security Profile(3.0) | 原生支持 |
| 谱系信息 | 有限 | Pedigree字段 |
| 工具支持 | 广泛 | 安全工具生态丰富 |
| 序列化 | Tag:Value, RDF/XML, JSON, YAML | JSON, XML, Protobuf |

### 选择建议

- **需要许可证合规审计**：优先选择SPDX（完善的许可证字段和合规场景）
- **安全团队主导SBOM项目**：优先选择CycloneDX（天然支持漏洞关联）
- **两个都支持**：同时生成SPDX和CycloneDX格式（工具如Syft支持多格式输出）

## 工具生态

### SBOM生成工具

**Syft**：Anchore出品的高性能SBOM生成工具，支持多种格式输出：

```bash
# 从容器镜像生成SBOM
syft nginx:latest -o spdx-json > nginx-sbom.spdx.json
syft nginx:latest -o cyclonedx-json > nginx-sbom.cdx.json
syft nginx:latest -o cyclonedx-xml > nginx-sbom.cdx.xml

# 从文件系统目录生成SBOM
syft packages /app -o spdx-json > app-sbom.spdx.json

# 从Docker存档生成
syft docker-archive://image.tar -o cyclonedx-json
```

**Trivy**：Aqua Security的多功能扫描器，支持SBOM生成和漏洞扫描：

```bash
# 生成SBOM
trivy image --format spdx-json --output result.spdx.json nginx:latest

# 使用SBOM作为输入进行漏洞扫描
trivy sbom result.spdx.json

# CycloneDX格式输出
trivy image --format cyclonedx --output result.cdx.json nginx:latest
```

### SBOM分析平台

**Dependency-Track**：OWASP的SBOM分析平台：

```bash
# 使用Docker部署Dependency-Track
docker run -d -p 8081:8081 \
  --name dependency-track \
  -v dtrack-data:/data \
  dependencytrack/apiserver

# 登录前端（默认端口8080）
# 通过API上传SBOM
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "project=my-project" \
  -F "bom=@sbom.cyclonedx.json"
```

Dependency-Track支持：
- 持续SBOM分析
- 自动CVE匹配
- 策略违规告警
- 组件审计和审批工作流

### GitHub SBOM导出

```bash
# 通过GitHub API导出SBOM
curl -H "Authorization: token ${GITHUB_TOKEN}" \
  https://api.github.com/repos/owner/repo/dependency-graph/sbom

# 使用gh CLI
gh api repos/owner/repo/dependency-graph/sbom
```

## 总结

SPDX和CycloneDX作为两大SBOM标准各有侧重。SPDX依托ISO标准化地位在许可证合规领域占优，CycloneDX以安全漏洞管理见长。两者在工具层面已有良好的互操作性（Syft、Trivy等工具可同时输出两种格式）。对于组织的SBOM战略，同时采用两种标准并根据使用场景选择合适的格式是最佳实践。结合Dependency-Track等分析平台，SBOM可以从静态文档变为动态的安全管理基础设施。
