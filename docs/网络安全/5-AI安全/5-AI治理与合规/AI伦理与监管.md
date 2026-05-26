# AI伦理与监管

> 随着AI系统在社会关键领域的广泛部署，AI伦理与监管已成为各国政府和国际组织的核心议题。不同的监管框架反映了不同的价值取向和治理理念，理解这些框架对于构建符合合规要求的AI系统至关重要。

## EU AI Act（欧盟人工智能法案）

EU AI Act 是首个全面的人工智能监管法律框架，采用基于风险的分级监管方法：

### 风险分类框架

| 风险等级 | 定义 | 监管要求 | 示例 |
|---------|------|---------|------|
| 不可接受风险 | 禁止部署 | 完全禁止 | 社会评分系统、公共场所实时人脸识别、操纵人类行为 |
| 高风险 | 严格监管 | 合格评定、风险管理、透明度、人工监督 | 医疗设备、关键基础设施、教育评估、执法工具 |
| 有限风险 | 透明度义务 | 告知用户正在与AI交互 | 聊天机器人、深度伪造内容标记 |
| 最低风险 | 无额外义务 | 自愿行为准则 | 垃圾邮件过滤器、AI游戏 |

### 高风险AI系统的合规要求

根据 EU AI Act，高风险系统必须满足以下要求：

| 要求类别 | 具体要求 |
|---------|---------|
| 风险管理 | 建立持续的风险识别、评估和缓解流程 |
| 数据治理 | 训练数据必须满足质量、偏差和隐私标准 |
| 技术文档 | 记录模型架构、训练方法、性能评估结果 |
| 透明度 | 提供清晰的系统能力、限制和使用说明 |
| 人工监督 | 设计人机交互界面，允许人工干预 |
| 准确性 | 确保达到预期的准确性和鲁棒性水平 |
| 网络安全 | 防范对抗性攻击和数据投毒 |

```text
EU AI Act 风险分类示意：

不可接受风险 ⛔ ──┬── 社交评分系统
                 ├── 实时生物识别监控
                 └── 对儿童的危险游戏化诱导

高风险 ⚠️ ────┬── AI医疗诊断系统
              ├── AI招聘筛选工具
              ├── 信用评估系统
              └── 关键基础设施管理

有限风险 ℹ️ ──┬── 客服聊天机器人
              └── 情感分析系统

最低风险 ✅ ──┬── AI游戏
              └── 垃圾邮件过滤
```

## 中国AI监管框架

中国已建立多层次的AI监管体系，核心法规包括：

### 生成式人工智能服务管理暂行办法（2023年8月生效）

该办法是当前中国AI监管的核心规范，要求：

1. **算法备案**：提供生成式AI服务的组织需完成算法备案（互联网信息服务算法备案系统）
2. **内容安全**：生成内容必须符合社会主义核心价值观，不得包含违法信息
3. **透明度要求**：合成内容应当进行标识，让用户知道内容是AI生成的
4. **数据合规**：训练数据不得侵犯他人知识产权，应包含真实、准确、客观、多样的数据
5. **安全评估**：面向公众提供的生成式AI服务需通过安全评估

```python
# 中国AI监管合规检查清单
def check_ai_compliance_china(ai_service):
    """检查AI服务是否符合中国监管要求"""
    checks = {
        "algorithm_filing": check_algorithm_filing(ai_service),
        "content_safety": check_content_safety_filter(ai_service),
        "ai_labeling": check_synthetic_content_labeling(ai_service),
        "data_compliance": check_training_data_compliance(ai_service),
        "security_assessment": check_security_assessment(ai_service),
        "user_privacy": check_privacy_policy(ai_service),
    }
    
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return {"compliant": False, "failed_checks": failed}
    return {"compliant": True}
```

### 其他重要法规

| 法规/标准 | 发布年份 | 核心内容 |
|----------|---------|---------|
| 个人信息保护法（PIPL） | 2021 | AI系统处理个人数据的合法性要求 |
| 数据安全法（DSL） | 2021 | 数据分类分级保护、重要数据出境 |
| 网络安全法（CSL） | 2017 | 网络运营者安全义务、关键信息基础设施保护 |
| 互联网信息服务深度合成管理规定 | 2022 | 深度合成服务标识、内容管理 |
| 新一代AI伦理规范 | 2021 | 伦理原则：人类福祉、公平公正、隐私安全 |

## NIST AI RMF（美国AI风险管理框架）

NIST AI RMF 提供了一个自愿性的风险管理框架，帮助组织管理AI系统的风险：

### 框架核心（Framework Core）

| 功能 | 描述 | 关键活动 |
|------|------|---------|
| GOVERN（治理） | 建立组织级AI治理文化 | 制定AI政策、分配责任、建立风险偏好 |
| MAP（映射） | 理解AI系统使用场景和风险 | 识别上下文、评估风险、确定风险优先级 |
| MEASURE（评估） | 量化AI系统风险 | 测试性能、评估公平性、审计透明度 |
| MANAGE（管理） | 采取措施管理已识别的风险 | 实施控制、监控运行、响应事件 |

```text
NIST AI RMF 核心流程（GOVERN → MAP → MEASURE → MANAGE）：

GOVERN
  ├── 建立AI风险管理团队
  ├── 制定AI伦理准则
  └── 确定风险评估方法论
      ↓
MAP
  ├── 明确AI系统使用场景
  ├── 识别利益相关者
  ├── 映射AI全生命周期风险
  └── 排序风险优先级
      ↓
MEASURE
  ├── 量化模型准确性和鲁棒性
  ├── 评估公平性（偏差审计）
  ├── 测试透明度和可解释性
  ├── 评估安全性和隐私保护
  └── 文档记录评估结果
      ↓
MANAGE
  ├── 实施风险缓解措施
  ├── 制定事件响应计划
  ├── 持续监控和报告
  └── 定期重新评估
```

### AI风险分类

NIST AI RMF 将AI风险分为以下几类：

| 风险类别 | 核心问题 | 评估方法 |
|---------|---------|---------|
| 准确性 | 模型是否产生正确输出？ | 基准测试、交叉验证 |
| 偏差（Bias） | 模型是否对不同群体不公平？ | 公平性指标审计 |
| 透明度 | 模型的行为是否可理解？ | 可解释性技术（SHAP, LIME） |
| 安全性 | 模型是否对抗攻击鲁棒？ | 红队测试、对抗性评估 |
| 隐私 | 训练数据隐私是否受保护？ | 成员推理测试、DP审计 |
| 鲁棒性 | 模型在边缘情况下的表现？ | 压力测试、分布外检测 |

## 算法公平性（Algorithmic Fairness）

### 公平性度量指标

| 指标 | 定义 | 公式 | 适用场景 |
|-----|------|------|---------|
| 人口统计均等 | 不同群体的正预测率相等 | $P(\hat{Y}=1 \mid A=a) = P(\hat{Y}=1 \mid A=b)$ | 招聘、贷款 |
| 均等机会 | 真实正例率在各群体间相等 | $P(\hat{Y}=1 \mid Y=1, A=a) = P(\hat{Y}=1 \mid Y=1, A=b)$ | 医疗诊断 |
| 均等赔率 | 假正率和真正率同时相等 | TPR和FPR在各群体间相等 | 刑事司法 |
| 预测均等 | 各组精确率相等 | $P(Y=1 \mid \hat{Y}=1, A=a) = P(Y=1 \mid \hat{Y}=1, A=b)$ | 信用评分 |

```python
def compute_fairness_metrics(y_true, y_pred, sensitive_attr):
    """计算不同群体间的公平性指标"""
    groups = np.unique(sensitive_attr)
    metrics = {}
    
    for group in groups:
        mask = sensitive_attr == group
        y_true_g = y_true[mask]
        y_pred_g = y_pred[mask]
        
        tp = np.sum((y_pred_g == 1) & (y_true_g == 1))
        fp = np.sum((y_pred_g == 1) & (y_true_g == 0))
        fn = np.sum((y_pred_g == 0) & (y_true_g == 0))
        
        # 统计均等：正预测率
        ppv = np.mean(y_pred_g == 1)
        # 均等机会：真正率
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        # 预测精确率
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        
        metrics[group] = {
            "positive_rate": ppv,
            "true_positive_rate": tpr,
            "precision": precision
        }
    
    # 计算差异
    groups_list = list(metrics.keys())
    disparity = {
        "statistical_parity_diff": abs(
            metrics[groups_list[0]]["positive_rate"] - 
            metrics[groups_list[1]]["positive_rate"]
        ),
        "equal_opportunity_diff": abs(
            metrics[groups_list[0]]["true_positive_rate"] - 
            metrics[groups_list[1]]["true_positive_rate"]
        )
    }
    
    return metrics, disparity
```

### 偏差缓解方法

| 阶段 | 方法 | 原理 | 效果 |
|-----|------|------|------|
| 训练前 | 数据重采样 | 平衡不同群体的样本比例 | 中等 |
| 训练前 | 特征选择 | 移除与敏感属性相关的特征 | 有限 |
| 训练中 | 对抗性去偏置 | 训练模型同时使判别器无法预测敏感属性 | 高 |
| 训练中 | 公平性正则化 | 在损失函数中加入公平性约束 | 高 |
| 训练后 | 阈值调整 | 为不同群体设置不同的分类阈值 | 中等 |
| 训练后 | 输出重校准 | 调整模型输出的概率校准 | 中等 |

AI监管是一个快速演进的领域。建议组织建立跨学科的AI治理团队（包含法律、安全、工程和伦理专家），持续跟踪各国监管要求的变化，并将合规要求嵌入到AI系统的全生命周期开发流程中。
