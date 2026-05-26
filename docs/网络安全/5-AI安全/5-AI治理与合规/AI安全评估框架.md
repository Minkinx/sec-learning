# AI安全评估框架

> AI安全评估框架为系统化评估和验证AI系统的安全性提供了结构化方法论。与传统软件安全评估不同，AI安全评估需要覆盖模型特有的攻击面——对抗性攻击、数据投毒、后门、隐私泄露等。本章介绍威胁建模、鲁棒性基准、模型文档化和安全评估流程。

## ML系统威胁建模

### ML-STRIDE 框架

借鉴传统 STRIDE 威胁建模方法论，针对ML系统特点的威胁分类：

| 威胁类型 | AI/ML 特定含义 | 攻击示例 | 影响 |
|---------|---------------|---------|------|
| Spoofing（欺骗） | 欺骗模型做出错误预测 | 对抗性输入导致误分类 | 模型完整性 |
| Tampering（篡改） | 篡改训练数据或模型 | 数据投毒、后门注入 | 模型完整性 |
| Repudiation（抵赖） | 无模型行为审计日志 | 无法追溯模型决策原因 | 可审计性 |
| Info Disclosure（信息泄露） | 泄露训练数据或模型参数 | 成员推理、模型提取 | 隐私性 |
| Denial of Service（拒绝服务） | 耗尽计算或API资源 | 输入放大、算力消耗攻击 | 可用性 |
| Elevation of Privilege（权限提升） | 模型执行非预期操作 | 提示注入后Agent执行恶意操作 | 权限控制 |

### ML系统攻击树

```text
ML系统攻击树：
├── 训练阶段攻击
│   ├── 数据投毒
│   │   ├── 后门触发器注入
│   │   ├── 标签翻转
│   │   └── 干净标签投毒
│   ├── 模型篡改
│   │   ├── 微调后门植入
│   │   ├── 权重修改
│   │   └── 转换过程注入
│   └── 供应链攻击
│       ├── 恶意预训练模型
│       ├── 投毒公开数据集
│       └── 第三方库后门
│
├── 推理阶段攻击
│   ├── 对抗性攻击
│   │   ├── 白盒攻击（FGSM, PGD, C&W）
│   │   ├── 黑盒攻击（SimBA, HopSkipJump）
│   │   └── 物理世界攻击（patch, 3D）
│   ├── 模型窃取
│   │   ├── Knockoff Nets
│   │   ├── 主动学习提取
│   │   └── 超参数侧信道
│   └── 隐私攻击
│       ├── 成员推理（LiRA）
│       ├── 属性推断
│       └── 训练数据提取
│
└── 部署阶段攻击
    ├── 提示注入
    │   ├── 直接注入
    │   ├── 间接注入
    │   └── 越狱
    ├── 拒绝服务
    │   ├── 输入放大
    │   ├── 长上下文攻击
    │   └── 递归查询
    └── 滥用
        ├── 深度伪造
        ├── 自动化欺诈
        └── 恶意内容生成
```

## 鲁棒性基准测试

### RobustBench

RobustBench 是标准化对抗鲁棒性评估的权威基准平台：

| 基准数据集 | 评估攻击 | 评估指标 | SOTA 鲁棒精度 |
|-----------|---------|---------|--------------|
| CIFAR-10 L∞ ε=8/255 | AutoAttack | 鲁棒准确率 | ~70% |
| CIFAR-10 L2 ε=0.5 | AutoAttack | 鲁棒准确率 | ~80% |
| ImageNet L∞ ε=4/255 | AutoAttack | 鲁棒准确率 | ~50% |
| ImageNet L2 ε=0.5 | AutoAttack | 鲁棒准确率 | ~70% |

```python
def robustbench_evaluation(model, dataset="cifar10", threat_model="Linf", epsilon=8/255):
    """使用RobustBench标准评估模型鲁棒性"""
    from robustbench import load_model
    from robustbench.utils import clean_accuracy
    from autoattack import AutoAttack
    
    # 加载标准测试集
    _, test_loader = load_dataset(dataset)
    
    # 评估干净精度
    clean_acc = clean_accuracy(model, test_loader)
    print(f"Clean Accuracy: {clean_acc:.2%}")
    
    # 使用AutoAttack评估对抗鲁棒性
    adversary = AutoAttack(model, norm=threat_model, eps=epsilon)
    
    robust_acc = 0
    for x, y in test_loader:
        x_adv = adversary.run_standard_evaluation(x, y)
        batch_acc = (model(x_adv).argmax(1) == y).float().mean()
        robust_acc += batch_acc.item()
    
    robust_acc /= len(test_loader)
    print(f"Robust Accuracy (AutoAttack): {robust_acc:.2%}")
    
    return {"clean_accuracy": clean_acc, "robust_accuracy": robust_acc}
```

## 模型卡（Model Card）

模型卡是标准化的模型文档模板，由 Mitchell 等人提出，现已成为 AI 透明度的行业标准：

```yaml
# 模型卡模板
model_details:
  name: "模型名称"
  version: "1.0.0"
  type: "图像分类 / LLM / 目标检测"
  date: "2024-01-01"
  organization: "开发组织"
  model_architecture: "ResNet-50 / GPT-4 / YOLOv8"

intended_use:
  primary_purpose: "模型的核心用途描述"
  target_users: "目标用户群体"
  out_of_scope: "超出使用范围的场景"

factors:
  relevant_groups: "可能受影响的群体（年龄、性别、地域等）"
  instrumentation: "影响评估的硬件/软件因素"
  evaluation_factors: "影响模型表现的关键因素"

metrics:
  performance: 
    accuracy: 0.95
    f1_score: 0.93
    latency_ms: 45
  robustness:
    adversarial_accuracy_Linf: 0.65
    ood_detection_auroc: 0.92
  fairness:
    demographic_parity_diff: 0.03
    equal_opportunity_diff: 0.02
  privacy:
    mia_attack_auc: 0.62
    dp_epsilon: 8.0

training_data:
  dataset: "数据集名称和来源"
  size: "训练样本数量"
  distribution: "数据分布描述（标注分布、地域分布等）"
  preprocessing: "数据预处理步骤"
  sensitive_attributes: "包含的敏感属性（种族、性别等）"

ethical_considerations:
  bias_analysis: "偏差分析结果"
  potential_risks: "已识别的潜在风险"
  mitigation: "已实施的缓解措施"

caveats_and_recommendations:
  known_limitations: "已知的局限性"
  deployment_constraints: "部署条件限制"
  maintenance: "模型更新和维护计划"
```

## 红队测试标准

AI红队测试需要标准化的流程和报告格式：

### 测试范围定义

```python
class RedTeamTestPlan:
    """AI红队测试计划模板"""
    
    def __init__(self):
        self.scope = {
            "attack_types": [
                "prompt_injection",
                "jailbreak",
                "adversarial_examples",
                "data_poisoning",
                "model_extraction",
            ],
            "test_budget": {
                "api_queries": 50000,
                "compute_hours": 100,
                "time_days": 14,
            },
            "severity_thresholds": {
                "critical": "可导致数据泄露或系统控制权丢失",
                "high": "可导致严重的错误输出或服务中断",
                "medium": "可在特定条件下造成有限影响",
                "low": "需要特殊条件且影响有限",
            }
        }
    
    def report_template(self):
        return {
            "executive_summary": "",
            "findings": [
                {
                    "id": "AI-2024-001",
                    "severity": "high",
                    "attack_type": "prompt_injection",
                    "description": "...",
                    "evidence": "...",
                    "impact": "...",
                    "remediation": "...",
                    "status": "open"
                }
            ],
            "risk_matrix": {},
            "recommendations": []
        }
```

## 安全评估工作流程

### 全流程评估

```text
阶段1: 资产识别
├── 识别AI资产（模型文件、训练数据、推理API）
├── 确定资产价值和敏感度等级
└── 建立资产清单

阶段2: 威胁建模
├── 使用ML-STRIDE进行威胁分类
├── 构建攻击树
└── 识别高优先级威胁路径

阶段3: 漏洞扫描
├── 对抗鲁棒性测试（AutoAttack）
├── 数据投毒检测（频谱签名）
├── 隐私泄露评估（LiRA成员推理）
├── 提示注入扫描（GARAK）
└── 供应链安全审查

阶段4: 渗透测试
├── 白盒攻击评估（PGD, C&W）
├── 黑盒攻击评估（Boundary Attack）
├── 模型提取模拟（Knockoff Nets）
├── 后门检测（Neural Cleanse）
└── 越狱攻击测试

阶段5: 风险评估
├── 基于CVSS的AI风险评分
├── 风险优先级矩阵
├── 残余风险评估
└── 风险接受/缓解决策

阶段6: 缓解实施
├── 修复高优先级漏洞
├── 部署防御机制（对抗训练、DP-SGD）
├── 建立监控和告警
└── 更新事件响应计划

阶段7: 重新评估
├── 回归测试验证修复效果
├── 对抗性鲁棒性再评估
└── 生成最终安全评估报告
```

### 风险评分矩阵

| 可能性 \ 影响 | 轻微 | 中等 | 严重 | 灾难性 |
|--------------|------|------|------|--------|
| 非常可能 | 中 | 高 | 严重 | 严重 |
| 可能 | 低 | 中 | 高 | 严重 |
| 不太可能 | 低 | 中 | 中 | 高 |
| 几乎不可能 | 低 | 低 | 中 | 中 |

AI安全评估不是一次性的合规检查，而应该嵌入到AI系统的持续开发与运营流程中。随着攻击技术的演进和监管要求的变化，安全评估框架需要定期更新。建议组织建立AI安全评估的自动化流水线，将上述评估流程CI/CD化，实现"安全左移"和持续合规监控。
