# SAST-DAST-SCA

> 安全测试体系包含静态应用安全测试（SAST）、动态应用安全测试（DAST）、交互式应用安全测试（IAST）和软件组成分析（SCA）四大核心技术。本文深入对比各类工具的原理、优劣和最佳实践。

## SAST（静态应用安全测试）

SAST通过分析源代码来发现安全漏洞，是一种白盒测试方法。

### SAST工作原理

```
SAST检测流程：
源代码 → 语法分析 → 抽象语法树（AST） → 数据流分析 → 发现漏洞
                   ↓
              控制流图 → 路径分析 → 发现逻辑漏洞
```

```python
# Semgrep规则示例：检测不安全的密码使用
rules:
  - id: hardcoded-password
    patterns:
      - pattern: |
          $VAR = "$PASSWORD"
      - pattern-either:
          - metavariable-regex:
              metavariable: $VAR
              regex: .*(password|passwd|pwd|secret|token).*
          - metavariable-regex:
              metavariable: $PASSWORD
              regex: .*(?i)(?=.*[a-z])(?=.*[0-9]).*
    message: "检测到硬编码密码"
    languages: [python, javascript, go, java, ruby]
    severity: ERROR
```

### Semgrep vs CodeQL

| 特性 | Semgrep | CodeQL |
|------|---------|--------|
| 分析引擎 | 模式匹配 + 数据流 | Datalog逻辑查询语言 |
| 查询方式 | YAML规则（模式匹配） | QL声明式查询语言 |
| 支持语言 | Python, Go, Java, JS/TS, Ruby, C, C++等30+语言 | Java, C#, JS/TS, C++, Python, Go |
| 数据流分析 | 有限（跨函数间数据流有限制） | 深度数据流分析（跨文件） |
| 自定义规则 | 简单（YAML编写） | 较复杂（需要学习QL） |
| 误报率 | 中等 | 较低（深度分析） |
| 集成方式 | CLI、GitHub Action、GitLab CI | GitHub Code Scanning |
| 无代码文件 | 不支持 | 支持（需要构建） |
| 社区规则 | Semgrep Registry（2000+规则） | 数百条标准查询 |

```ql
// CodeQL查询示例：查找Java中的SQL注入
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(Node source) {
    // 用户输入来源：HTTP请求参数
    source.asExpr() instanceof Expr and
    source.asExpr().(MethodAccess).getMethod().getName() in [
      "getParameter", "getQueryString", "getHeader"
    ]
  }

  override predicate isSink(Node sink) {
    // 危险的SQL执行方法
    exists(MethodAccess ma |
      ma.getMethod().getName() in ["executeQuery", "execute", "prepareStatement"]
      and sink.asExpr() = ma.getArgument(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), sink.getNode(), "SQL注入发现"
```

### SonarQube集成

```yaml
# sonar-project.properties - Java项目SAST配置
sonar.projectKey=com.company:payment-api
sonar.projectName=Payment API
sonar.projectVersion=2.1.0
sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.java.binaries=target/classes
sonar.java.libraries=target/dependency/*.jar

# 质量门禁
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300
```

```bash
# 在CI中集成SonarQube扫描
sonar-scanner \
  -Dsonar.host.url=https://sonarqube.company.com \
  -Dsonar.login=$SONAR_TOKEN \
  -Dsonar.qualitygate.wait=true \
  -Dsonar.qualitygate.timeout=300

# 检查质量门禁结果
if [ $? -ne 0 ]; then
  echo "SonarQube质量门禁未通过，阻断构建"
  exit 1
fi
```

## DAST（动态应用安全测试）

DAST通过模拟攻击者行为对运行中的应用进行黑盒测试。

### Burp Suite与OWASP ZAP对比

| 特性 | Burp Suite Professional | OWASP ZAP |
|------|------------------------|-----------|
| 许可证 | 商业（349美元/年） | 开源免费 |
| 自动化 | 通过REST API，需扩展 | 原生支持自动化（ZAP API） |
| 主动扫描 | 高级（深度crawl+audit） | 基础+社区扩展 |
| 扩展性 | BApp Store扩展 | ZAP Add-on市场 |
| CI集成 | 通过CLI，需要Pro License | 原生支持（zap-cli, zap-api） |
| 报告 | 丰富的报告模板 | 多种格式（HTML/XML/Markdown） |

```python
# OWASP ZAP API自动化扫描脚本
from zapv2 import ZAPv2
import time

class ZAPScanner:
    def __init__(self, api_key, target_url, zap_proxy="http://localhost:8080"):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': zap_proxy, 'https': zap_proxy})
        self.target = target_url
    
    def spider(self):
        """爬取目标应用的所有页面"""
        print(f"开始爬取: {self.target}")
        scan_id = self.zap.spider.scan(self.target)
        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"爬取进度: {self.zap.spider.status(scan_id)}%")
            time.sleep(5)
        print("爬取完成")
    
    def active_scan(self):
        """执行主动扫描"""
        print(f"开始主动扫描: {self.target}")
        scan_id = self.zap.ascan.scan(self.target)
        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"主动扫描进度: {self.zap.ascan.status(scan_id)}%")
            time.sleep(10)
        print("主动扫描完成")
    
    def get_alerts(self):
        """获取所有告警"""
        alerts = self.zap.core.alerts(baseurl=self.target)
        for alert in alerts:
            print(f"[{alert['risk']}] {alert['alert']} - {alert['url']}")
        return alerts
    
    def generate_report(self):
        """生成HTML报告"""
        report = self.zap.core.htmlreport()
        with open("zap-report.html", "w") as f:
            f.write(report)

# 使用示例
scanner = ZAPScanner("api-key", "https://staging.company.com")
scanner.spider()
scanner.active_scan()
scanner.get_alerts()
scanner.generate_report()
```

## IAST（交互式应用安全测试）

IAST通过在应用运行时植入Agent，将SAST的代码可见性和DAST的运行时覆盖优势结合。

### IAST工作原理

```
IAST架构：
┌─────────────────┐
│   Web应用服务器    │
│  ┌──────────────┐│
│  │ IAST Agent    ││  ← 植入应用运行时
│  │  (Java Agent)  ││
│  └──────────────┘│
│        ↓         │
│  ┌──────────────┐│
│  │  监控引擎      ││  ← 监控代码执行路径
│  │  安全分析器    ││
│  └──────────────┘│
│        ↓         │
│  ┌──────────────┐│
│  │  漏洞报告      ││  ← 输出精确的漏洞定位
│  └──────────────┘│
└─────────────────┘
```

```bash
# Contrast Security IAST Agent启动示例（Java）
java -javaagent:/opt/contrast/contrast.jar \
  -Dcontrast.api.url=https://app.contrastsecurity.com \
  -Dcontrast.api.api_key=YOUR_API_KEY \
  -Dcontrast.api.service_key=YOUR_SERVICE_KEY \
  -Dcontrast.api.user_name=agent_user@company.com \
  -jar app.jar

# IAST Agent自动分析：
# - 数据流追踪：从用户输入到SQL查询的完整路径
# - 代码上下文：精确到行号
# - 真实触发：只在代码实际执行时报告
```

## SCA（软件组成分析）

SCA分析应用依赖的第三方组件，检测已知漏洞（CVE）和许可证合规问题。

### SCA工具对比

| 特性 | Snyk | Dependabot | Trivy | OWASP Dependency-Check |
|------|------|-----------|-------|----------------------|
| 类型 | 商业+免费版 | 免费（GitHub内置） | 开源 | 开源 |
| 数据库 | Snyk VulnDB + NVD | GitHub Advisory | Trivy DB + NVD | NVD + CVE |
| 修复建议 | 自动PR修复 | 自动PR更新 | 仅报告 | 仅报告 |
| 许可证审计 | 支持 | 有限 | 支持 | 支持 |
| 容器扫描 | 支持 | 不支持 | 原生支持 | 不支持 |
| IaC扫描 | 支持 | 有限 | 支持 | 不支持 |
| CI集成 | GitHub/GitLab/Jenkins | GitHub原生 | GitHub/GitLab/Harbor | Jenkins/Maven/Gradle |

### Snyk集成示例

```yaml
# Snyk GitHub Action CI集成
name: Snyk Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Container scan
        uses: snyk/actions/docker@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          image: your-image:latest
          args: --severity-threshold=medium
```

### Trivy容器扫描

```bash
# Trivy扫描容器镜像
trivy image --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --format html \
  --output trivy-report.html \
  registry.company.com/web-app:latest

# Trivy扫描本地文件系统
trivy filesystem --severity CRITICAL \
  /path/to/project

# Trivy扫描Kubernetes集群
trivy k8s --report summary cluster

# Trivy SBOM生成
trivy image --format cyclonedx \
  --output sbom.json \
  alpine:latest
```

## 安全测试工具矩阵

```
              ┌─────────────┬────────────┬────────────┬────────────┐
              │  SAST        │    DAST    │    IAST    │    SCA     │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 测试阶段      │ 编码阶段      │ 测试阶段    │ 测试阶段    │ 构建阶段    │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 是否需要源码  │   需要       │   不需要   │   不需要   │   需要     │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 是否需要运行  │   不需要     │   需要     │   需要     │   不需要   │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 漏洞类型      │ 逻辑漏洞     │ 运行时漏洞  │ SAST+DAST  │ 已知CVE    │
│             │ 代码质量     │ 配置错误    │ 综合能力    │ 许可问题   │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 误报率        │ 中-高       │ 中        │ 低         │ 低-中      │
├─────────────┼─────────────┼────────────┼────────────┼────────────┤
│ 检出率        │ 高          │ 中        │ 高         │ 高         │
└─────────────┴─────────────┴────────────┴────────────┴────────────┘
```

## 误报管理流程

```
SAST/DAST/SCA结果 → 自动分类
     ├── Critical/High → 自动创建Ticket → 分配给开发人员
     ├── Medium → 纳入Triage队列 → 安全团队审查
     └── Low/Info → 自动忽略或纳入下次Sprint

Triage流程：
1. 确认漏洞是否真实 → 误报 → 添加suppression规则
2. 是真实漏洞 → 判断修复优先级
3. 修复 → 重新扫描验证 → 关闭
4. 无法立即修复 → 创建临时缓解措施（WAF规则、最小权限）
```

## 总结

SAST、DAST、IAST、SCA各有优势和局限，在DevSecOps实践中应该组合使用。推荐的最小配置是：SAST + SCA（CI门禁）+ DAST（测试环境扫描），高安全需求场景再加入IAST。误报管理是安全测试体系长期运行的关键，需要建立完善的Triage流程和Suppression规则库。
