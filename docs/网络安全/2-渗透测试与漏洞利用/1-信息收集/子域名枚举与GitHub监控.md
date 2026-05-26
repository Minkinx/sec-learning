# 子域名枚举与GitHub监控

## 概述

子域名枚举是扩大攻击面的关键手段。一个主域名下可能隐藏着数十甚至数百个子域名——包括开发环境、测试站点、API服务、管理后台等，它们往往比主站更脆弱。GitHub监控则针对代码托管平台上的敏感信息泄露，包括凭据、密钥、配置文件和内部文档。

## 被动子域名枚举

### 证书透明度日志

CA会将签发的每个SSL证书记录到CT（Certificate Transparency）日志中，这些日志包含了证书中所有Subject Alternative Name（SAN）条目，是子域名枚举的重要数据源。

**crt.sh查询：**

```bash
# 基本查询
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# 排除通配符结果
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | grep -v '\\*' | sort -u

# 通配符查询（含多级子域名）
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

**Certspotter：**

```bash
# API查询
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
```

### DNS记录分析

分析DNS记录可间接发现子域名和服务信息：

```bash
# 查询MX记录（邮件服务器）
dig target.com MX

# 查询NS记录（DNS服务器）  
dig target.com NS

# 查询TXT记录（SPF, DKIM, DMARC）
dig target.com TXT

# 查询CNAME记录
dig www.target.com CNAME

# 批量DNS查询
for sub in $(cat subdomains.txt); do
  echo "$sub.target.com" $(dig +short "$sub.target.com" A)
done
```

### 第三方DNS数据平台

- **SecurityTrails**：提供完整的DNS历史记录，包括已删除的子域名
- **DNSDumpster**：可视化域名DNS映射关系
- **AlienVault OTX**：威胁情报平台，包含被动DNS数据
- **VirusTotal**：提交域名可查看关联子域名和DNS解析历史

SecurityTrails API：

```bash
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_API_KEY" | jq -r '.subdomains[]'
```

## 主动子域名枚举

### Subfinder

Subfinder是目前最流行的子域名发现工具之一，集成多个被动和主动数据源：

```bash
# 基础枚举
subfinder -d target.com

# 所有数据源
subfinder -d target.com -all

# 输出到文件
subfinder -d target.com -o subdomains.txt

# 递归枚举
subfinder -d target.com -recursive

# 仅使用被动源（无主动交互）
subfinder -d target.com -only-sources
```

### DNSx与HTTPx组合

dnsx用于DNS记录验证，httpx用于HTTP服务确定：

```bash
# 子域名发现并验证DNS解析
subfinder -d target.com | dnsx -a -resp

# 验证HTTP可达性和标题信息
subfinder -d target.com | httpx -title -status-code -web-server

# 完整管道
subfinder -d target.com | httpx -title -status-code -tech-detect -follow-redirects

# JSON输出
subfinder -d target.com | httpx -json -o results.json
```

### 置换枚举

利用alterx工具基于已知子域名生成排列组合：

```bash
# 基于单词列表生成置换
alterx -l subdomains.txt -w permutations.txt

# 使用内置模式
alterx -l subdomains.txt -enrich

# 管道模式
subfinder -d target.com | alterx | dnsx -a
```

### Massdns高速解析

Massdns利用异步DNS解析实现百万级QPS：

```bash
# 准备域名列表（格式：sub.target.com）
# 使用massdns批量解析
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt

# 解析并提取有效IP
massdns -r resolvers.txt -t A -o J -w results.json subdomains.txt
jq -r 'select(.resp_type == "A") | .name + " " + .data.answers[].data' results.json
```

### JavaScript文件提取

从JS文件中提取子域名和API端点：

```bash
# gospider提取JS中的URL和子域名
gospider -s "https://target.com" -d 2 -c 50 -t 3 -o output

# subjs工具
subjs -i targets.txt -o js_endpoints.txt

# nuclei配合JS提取
nuclei -t exposures/ -l urls.txt
```

## 完整子域名枚举工作流

```bash
#!/bin/bash
# 综合子域名枚举流程
TARGET="target.com"
OUTPUT_DIR="./recon"

# 1. 被动收集
subfinder -d $TARGET -all -o $OUTPUT_DIR/passive.txt

# 2. 证书透明度
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | \
  jq -r '.[].name_value' | grep -v '*' | sort -u > $OUTPUT_DIR/crtsh.txt

# 3. 合并去重
cat $OUTPUT_DIR/passive.txt $OUTPUT_DIR/crtsh.txt | sort -u > $OUTPUT_DIR/all_subs.txt

# 4. 置换生成
alterx -l $OUTPUT_DIR/all_subs.txt -o $OUTPUT_DIR/permutations.txt

# 5. 主动验证
cat $OUTPUT_DIR/all_subs.txt $OUTPUT_DIR/permutations.txt | sort -u | \
  dnsx -a -resp-only -o $OUTPUT_DIR/resolved.txt

# 6. HTTP服务探测
httpx -l $OUTPUT_DIR/resolved.txt -title -status-code -tech-detect -o $OUTPUT_DIR/live.txt
```

## GitHub监控

### 敏感信息类型

通过GitHub监控可发现以下敏感信息：

| 类型 | 示例 | 风险等级 |
|------|------|----------|
| API密钥 | `AWS_ACCESS_KEY_ID`, `AIzaSyD...` | 严重 |
| 数据库凭据 | `DB_PASSWORD`, `mongodb://user:pass@` | 严重 |
| 私钥/证书 | `-----BEGIN RSA PRIVATE KEY-----` | 严重 |
| 配置文件 | `.env`, `config.php`, `application.yml` | 高危 |
| 内部URL | `https://internal-api.company.com` | 中危 |
| 员工Token | `github_token`, `slack_token` | 高危 |

### .git目录泄露

Web服务器错误配置可能导致`.git/`目录可访问：

```bash
# 检测.git泄露
curl -s "https://target.com/.git/HEAD"

# 下载整个.git目录
git-dumper https://target.com/.git/ ./git-dump/

# 恢复文件
git-dumper https://target.com/.git/ ./recovered/
cd recovered && git log --oneline
```

### 工具对比

| 工具 | 语言 | 特点 | 适用场景 |
|------|------|------|----------|
| git-secrets | Shell | AWS模式内置，pre-commit钩子 | 本地提交前防护 |
| truffleHog | Python | 熵值检测，深挖Git历史 | 历史提交分析 |
| gitleaks | Go | 正则+熵值，支持自定义规则 | CI/CD集成 |
| GitGuardian | SaaS | 实时监控，200+检测模式 | 企业级监控 |

### gitleaks使用

```bash
# 扫描本地仓库
gitleaks detect --source . --verbose

# 扫描GitHub仓库
gitleaks detect --source https://github.com/org/repo

# 基于Docker扫描
docker run -v $(pwd):/path zricethezav/gitleaks:latest detect \
  --source="/path" --verbose

# 配置自定义规则
gitleaks detect --config=custom.toml --source=.

# 输出JSON格式
gitleaks detect --source . --report-format json --report-path report.json
```

### truffleHog使用

```bash
# 扫描GitHub仓库
trufflehog https://github.com/org/repo

# 扫描GitHub组织（需Token）
trufflehog --token=YOUR_GITHUB_TOKEN https://github.com/org

# 扫描本地目录
trufflehog filesystem ./

# 熵值检测阈值调整
trufflehog --regex --entropy=True --max_depth=50 target.com
```

### GitHub防护最佳实践

- **提交前检查**：配置pre-commit钩子（git-secrets或gitleaks pre-commit）
- **CI/CD集成**：在CI管道中加入密钥扫描步骤
- **最小Token权限**：GitHub Token仅授予必要权限
- **密钥轮换**：定期轮换所有API密钥和凭据
- **分支保护**：禁止force push到主分支
- **扫描监控**：持续监控组织的GitHub账户

## 参考资源

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [crt.sh](https://crt.sh/)
