# CI-CD安全门禁

> CI/CD安全门禁（Security Gates）是在流水线中嵌入安全检查和阻断点的实践。通过在构建、测试、部署的每个阶段实施自动化安全控制，确保只有通过安全检查的代码才能进入生产环境。

## CI/CD流水线中的安全阶段

```
[开发] → [Pre-commit] → [CI Pipeline] → [Artifact] → [Deploy] → [Post-deploy]
          ↓                     ↓            ↓           ↓            ↓
       gitleaks           SAST+SCA       Trivis 审查    DAST     持续监控
      lint检查          单元测试+SAST    SBOM生成  安全部署策略  运行时监控
      secret扫描         容器扫描        签名验证   金丝雀发布    威胁检测
```

## Pre-commit安全门禁

### gitleaks密钥检测

```yaml
# .gitleaks.toml 自定义规则
title = "Company Secret Scanner"

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''(AKIA|ASIA)[0-9A-Z]{16}'''
tags = ["aws", "credential"]

[[rules]]
id = "github-token"
description = "GitHub Personal Access Token"
regex = '''gh[pousr]_[A-Za-z0-9_]{36,}'''
tags = ["github", "credential"]

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY-----'''
tags = ["key", "credential"]

[allowlist]
paths = [
  "test/",
  "*.test.*",
  "node_modules/",
  ".terraform/"
]
```

```bash
# pre-commit框架配置
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: detect-private-key
      - id: check-merge-conflict
  
  - repo: https://github.com/rhysd/actionlint
    rev: v1.6.26
    hooks:
      - id: actionlint
        args: [-shellcheck=]
EOF

# 安装pre-commit钩子
pre-commit install
```

## CI Pipeline安全门禁

### GitHub Actions安全流水线

```yaml
name: Security CI Pipeline
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  # Stage 1: 代码安全扫描
  code-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Secret scan
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
      
      - name: SAST - CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python,javascript
      - uses: github/codeql-action/analyze@v3
  
  # Stage 2: 依赖扫描
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: SCA - Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=all
      
      - name: SCA - Trivy FS scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
  
  # Stage 3: 构建与容器扫描
  build-and-scan:
    needs: [code-scan, dependency-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .
      
      - name: Container vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: image
          image-ref: app:${{ github.sha }}
          format: sarif
          output: container-scan.sarif
          severity: CRITICAL,HIGH
          exit-code: '1'  # 发现Critical/HIGH漏洞时失败
      
      - name: Generate SBOM
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: image
          image-ref: app:${{ github.sha }}
          format: cyclonedx
          output: sbom-cyclonedx.json
      
      - name: Sign container image
        run: |
          cosign sign --key env://COSIGN_KEY \
            --tlog-upload=true \
            registry.company.com/app:${{ github.sha }}
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom-cyclonedx.json
```

### GitLab CI安全流水线

```yaml
# .gitlab-ci.yml
stages:
  - security-scan
  - build
  - deploy-gate
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  SECURE_LOG_LEVEL: error

# 安全扫描阶段
sast:
  stage: security-scan
  image: registry.gitlab.com/security-products/sast:latest
  variables:
    SAST_EXCLUDED_PATHS: "test,node_modules,vendor"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  artifacts:
    reports:
      sast: gl-sast-report.json

secret_detection:
  stage: security-scan
  image: registry.gitlab.com/security-products/secret-detection:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

dependency_scanning:
  stage: security-scan
  image: registry.gitlab.com/security-products/dependency-scanning:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json

# 构建阶段
build:
  stage: build
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE
    - cosign sign --key $COSIGN_KEY $DOCKER_IMAGE

# 部署前门禁
deploy-gate:
  stage: deploy-gate
  script:
    - |
      # 检查所有安全报告，如果存在CRITICAL漏洞则阻断
      if [ -f gl-sast-report.json ]; then
        critical_count=$(jq '.vulnerabilities | map(select(.severity == "Critical")) | length' gl-sast-report.json)
        if [ "$critical_count" -gt 0 ]; then
          echo "SAST发现 $critical_count 个Critical漏洞，阻断部署"
          exit 1
        fi
      fi
      
      # 检查容器签名
      cosign verify --key $COSIGN_PUB_KEY $DOCKER_IMAGE
  needs:
    - sast
    - secret_detection
    - dependency_scanning
    - build

# 部署
deploy:
  stage: deploy
  script:
    - helm upgrade --install app ./chart
  environment:
    name: production
  needs:
    - deploy-gate
```

## 工件签名与完整性

### Cosign容器签名

```bash
# Cosign密钥生成
cosign generate-key-pair
# 生成 cosign.key（私钥）和 cosign.pub（公钥）

# 签名容器镜像
cosign sign --key cosign.key \
  registry.company.com/web-app:v2.1.0

# 签名时生成透明日志条目（ReKor）
# 可选keyless签名（通过OIDC + Fulcio）
cosign sign \
  --fulcio-url=https://fulcio.sigstore.dev \
  --rekor-url=https://rekor.sigstore.dev \
  registry.company.com/web-app:v2.1.0

# 验证签名
cosign verify --key cosign.pub \
  registry.company.com/web-app:v2.1.0

# 验证结果包含：
# - 签名有效性
# - 签名者身份
# - 镜像摘要匹配
# - ReKor透明日志条目
```

### Notation (Notary v2) OCI签名

```bash
# Notation初始化
notation cert generate-test --default "company-ca"

# 为OCI工件签名
notation sign \
  --key "company-ca" \
  --signature-manifest "application/vnd.cncf.notary.v2.signature" \
  registry.company.com/app@sha256:abc123...

# 验证签名
notation verify \
  --cert "company-ca" \
  registry.company.com/app@sha256:abc123...
```

## SBOM生成与依赖管理

### Syft SBOM生成

```bash
# 从容器镜像生成SBOM
syft registry.company.com/web-app:latest \
  -o cyclonedx-json=sbom.cyclonedx.json

# 从Docker存档生成
syft docker-archive:/tmp/app.tar \
  -o spdx-json=sbom.spdx.json

# 从文件系统生成
syft dir:/path/to/project \
  -o cyclonedx-json=sbom.json

# 查看SBOM内容
cat sbom.cyclonedx.json | jq '.components[].name + "@" + .components[].version'
```

### Dependency-Track集成

```bash
# 上传SBOM到Dependency-Track进行持续监控
curl -X POST "https://dtrack.company.com/api/v1/bom" \
  -H "X-API-Key: $DTRACK_API_KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "project=<project_uuid>" \
  -F "bom=@sbom.cyclonedx.json"

# 检查项目漏洞状态
curl -s "https://dtrack.company.com/api/v1/vulnerability/project/$PROJECT_UUID" \
  -H "X-API-Key: $DTRACK_API_KEY" | jq '.metrics.critical'
```

## SLSA（供应链安全等级）

SLSA（Supply-chain Levels for Software Artifacts）是Google提出的软件供应链安全框架：

| 等级 | 要求 | 描述 |
|------|------|------|
| SLSA L0 | 无保证 | 无特殊安全措施 |
| SLSA L1 | 构建过程已记录 | 构建可重现、来源可追溯 |
| SLSA L2 | 构建过程可验证 | 构建过程有签名，来源已验证 |
| SLSA L3 | 全过程可验证+防篡改 | 两方审查、机密构建、来源不可伪造 |

```yaml
# SLSA L3 构建要求
slsa_l3_requirements:
  build_process:
    - "构建定义不存在构建者控制的参数"  # hermetic build
    - "所有传递依赖项都声明在构建定义中"
    - "构建步骤作为独立脚本执行"
  
  provenance:
    - "来源声明由构建平台签名"
    - "来源包含所有材料和构建步骤的哈希值"
    - "构建平台身份经过验证"
  
  security:
    - "构建平台禁用用户覆盖"
    - "构建步骤之间隔离"
    - "构建在预定义的环境中运行"
```

```yaml
# GitHub Actions SLSA生成器
name: SLSA
on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  build:
    outputs:
      attestation: ${{ steps.attest.outputs.attestation }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Build artifact
        run: |
          make build
          echo "digest=$(sha256sum artifact.bin | cut -d ' ' -f1)" >> $GITHUB_ENV
      
      - name: Generate provenance
        id: attest
        uses: slsa-framework/slsa-github-generator/generate-attestation@v1
        with:
          artifact-path: artifact.bin
          artifact-digest: ${{ env.digest }}
```

## 流水线完整性保护

### Pipeline-as-Code签名

```bash
# 使用cosign对CI/CD配置进行签名
cosign sign-blob --key cosign.key \
  .github/workflows/deploy.yaml > deploy.yaml.sig

# 验证流水线签名
cosign verify-blob --key cosign.pub \
  --signature deploy.yaml.sig \
  .github/workflows/deploy.yaml
```

### 防止流水线覆盖

```yaml
# GitHub Protected Branches设置
branch_protection_rules:
  - branch: main
    required_status_checks:
      - security-scan/pass
      - dependency-scan/pass
      - build-scan/pass
    
    restrictions:
      - users: [devops-team]
      - prevent_self_review: true
    
    required_pull_request_reviews:
      required_approving_review_count: 1
      dismiss_stale_reviews: true
```

## 安全门禁度量指标

```yaml
security_gates_metrics:
  pre_commit:
    - secret_scan_pass_rate: "扫描通过率 >= 99%"
    - lint_pass_rate: "lint通过率 >= 95%"
  
  ci_pipeline:
    - sast_zero_critical: "SAST零Critical发现"
    - sca_no_critical: "SCA无Critical漏洞"
    - image_scan_pass: "容器镜像扫描通过"
    - sbom_generated: "SBOM已生成"
    - artifact_signed: "工件已签名"
  
  deployment:
    - provenance_verified: "来源已验证"
    - slsa_level: "SLSA等级 >= L2"
    - approval_required: "需要手动审批"
  
  post_deploy:
    - runtime_scan_pass: "运行时扫描通过"
    - no_security_regression: "无安全回退"
```

## 总结

CI/CD安全门禁确保安全不再是开发流程的瓶颈，而是自动化的质量关卡。从pre-commit的秘密扫描到部署前的SLSA验证，每一道门禁都应提供明确的安全保障。关键在于：安全策略即代码（Security Policy as Code）、自动化执行、结果可追溯。结合容器签名（Cosign）、SBOM（Syft）和供应链安全（SLSA），构建从代码到部署的全链路安全流水线。
