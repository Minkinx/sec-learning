# OSINT与被动侦察

## 概述

开源情报（Open Source Intelligence, OSINT）是指从公开可用信息源收集和分析数据的过程。在渗透测试中，OSINT是第一步也是最关键的一步——在不与目标系统直接交互的前提下，最大限度获取攻击面信息。被动侦察强调"零接触"原则：不向目标系统发送任何探测数据包，仅依赖第三方数据源和公开记录。

## Domain与Whois信息收集

### Whois查询基础

Whois协议用于查询域名注册信息，包括注册人、注册商、注册日期、过期日期、DNS服务器等。常用命令行工具：

```bash
whois target.com
```

关键字段分析：
- **Registrant Name/Organization**：注册人/组织名称，可用于关联其他域名
- **Name Servers**：NS服务器，可揭示DNS托管商
- **Creation Date**：注册日期，新注册域名可能安全防护较弱
- **Registrar**：注册商，部分注册商对冒用注册信息审核不严

### 历史Whois对比

域名注册信息存在变更记录，通过Whois历史数据库可以发现：
- **注册人信息变更**：可能暗示域名所有者变更
- **隐私保护开启/关闭**：隐私保护开启前的原始记录可能已暴露敏感信息
- **DNS服务器变更**：可追踪域名的基础设施迁移

常用历史Whois服务：WhoisXML、DomainTools、SecurityTrails。

### Whois隐私保护的影响

GDPR实施后，大量域名启用Whois Privacy/Redaction，注册人信息被隐藏。但这并不意味着无法侦察：
- 隐私保护开启本身可作为情报：说明注册方对隐私有意识
- 部分TLD（如.cn、.us）不允许隐私保护
- 隐私保护服务商信息（如WhoisGuard, PrivacyProtect）可用于交叉关联

## 搜索引擎侦察

### Google Dorking

Google高级搜索操作符可以精准定位敏感信息：

| 操作符 | 示例 | 用途 |
|--------|------|------|
| `site:` | `site:target.com` | 限定搜索域名 |
| `filetype:` | `filetype:pdf site:target.com` | 搜索特定文件类型 |
| `intitle:` | `intitle:"index of" site:target.com` | 搜索页面标题 |
| `inurl:` | `inurl:admin site:target.com` | 搜索URL包含关键词 |
| `intext:` | `intext:"password" filetype:log` | 搜索页面正文 |
| `cache:` | `cache:target.com` | 查看Google缓存的页面 |

常用敏感信息Dork组合：

```text
# 目录遍历
intitle:"index of" site:target.com

# 配置文件泄露
filetype:env site:target.com
filetype:sql site:target.com

# 日志文件
filetype:log site:target.com

# 管理员后台
inurl:admin intitle:login site:target.com

# 备份文件
filetype:bak site:target.com
```

### Shodan搜索语法

Shodan是互联网设备搜索引擎，可发现目标暴露的服务和资产：

```text
# 按域名搜索
hostname:target.com

# 按组织搜索
org:"Target Organization"

# 按端口搜索
port:22,3306,3389 hostname:target.com

# 按HTTP标题搜索
http.title:"target" ssl:target.com

# 过滤特定服务
product:Apache hostname:target.com
```

### 社交媒体侦察

- **LinkedIn**：员工信息、组织结构、技术栈（从招聘信息推断）、IT人员定位
- **GitHub**：代码泄露、API Key/Token泄露、内部文档、配置文件
- **Twitter/Weibo**：企业动态、技术分享、员工个人账号信息
- **Facebook**：员工信息、企业管理页面

## 子域名被动枚举

### 证书透明度（Certificate Transparency）

CA签发SSL证书时会将记录写入CT Log，这些日志对公众开放查询：

- **crt.sh**：提供最全面的证书透明日志查询，支持通配符搜索`%.target.com`
- **Certspotter**：监控新签发证书，实时发现新增子域名

API查询示例：

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### DNS记录分析

通过分析DNS记录可以间接发现子域名和网络架构：

- **MX记录**：邮件服务器子域名
- **NS记录**：DNS服务器子域名
- **TXT记录**：SPF, DKIM, DMARC记录—可能暴露第三方服务商
- **CNAME记录**：揭示云服务使用情况（AWS S3, CloudFront, Akamai等）

## OSINT工具对比

| 工具 | 类型 | 功能特点 | 适用场景 |
|------|------|----------|----------|
| theHarvester | 被动收集 | 邮箱、子域名、IP、主机名 | 快速侦察阶段 |
| Recon-ng | 模块化框架 | 内置丰富模块，支持API集成 | 综合性侦察 |
| Maltego | 图形化分析 | 实体关系图，数据关联分析 | 关联分析和报告 |
| Shodan | 设备搜索引擎 | 暴露服务、设备、ICS系统 | 基础设施暴露面评估 |
| crt.sh | CT日志查询 | SSL证书记录，子域名发现 | 子域名被动枚举 |
| SpiderFoot | 自动化OSINT | 200+模块，自动化扫描 | 全量侦察 |

### theHarvester基础使用

```bash
theHarvester -d target.com -b google,linkedin,dnsdumpster,shodan
```

参数说明：
- `-d`：目标域名
- `-b`：数据源（google, bing, linkedin, dnsdumpster, shodan等）
- `-l`：每个数据源的结果数量限制

### Recon-ng工作流

```text
recon-ng > marketplace install all
recon-ng > workspace create target
recon-ng > use recon/domains-hosts/certificate_transparency
recon-ng > set SOURCE target.com
recon-ng > run
```

## 伦理边界与法律考量

### 被动侦察的法律界定

- **合法**：访问公开信息（网页、DNS记录、证书透明度日志、Whois数据库）
- **需授权**：任何向目标系统发送数据包的动作（即使是一个DNS查询在某些司法管辖区也可能被视为主动侦察）
- **需明确授权**：社会工程学（钓鱼、电话询问、物理访问）

### 渗透测试范围界定

在获得书面授权前，应严格遵守以下原则：
1. **不触碰目标系统**：不发送任何数据包
2. **不利用漏洞**：发现的任何漏洞不应在未授权情况下利用
3. **不存储敏感数据**：无意获取的个人信息应及时清除
4. **仅限于公开信息**：不试图绕过任何访问控制措施

### Bug Bounty中的OSINT

Bug Bounty项目中OSINT的范围通常更宽松，但仍需注意：
- 严格遵守项目范围（Scope）
- 不进行拒绝服务式的数据采集
- 不涉及第三方服务（除非明确包含）
- 发现的用户数据立即报告不扩散

## 参考资源

- [crt.sh](https://crt.sh/) - 证书透明度日志查询
- [Shodan](https://www.shodan.io/) - 网络设备搜索引擎
- [Exploit-DB Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
- [Recon-ng](https://github.com/lanmaster53/recon-ng) - 侦察框架
- [theHarvester](https://github.com/laramies/theHarvester)
