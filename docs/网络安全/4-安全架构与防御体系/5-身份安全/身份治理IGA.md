# 身份治理IGA

> 身份治理与管理（Identity Governance and Administration, IGA）是确保组织内的数字身份在整个生命周期中得到适当管理的框架。IGA涵盖身份生命周期管理、访问权审批、角色管理、认证和合规审计等核心功能。

## IGA的核心能力

```
IGA功能矩阵：
┌─────────────────────────────────────────────────────────────┐
│                      Identity Governance                       │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ 身份生命周期   │ 访问治理     │ 角色管理      │ 合规与审计     │
├──────────────┼──────────────┼──────────────┼────────────────┤
│ ● 入职创建    │ ● 访问请求   │ ● 角色挖掘    │ ● 认证活动     │
│ ● 权限变更    │ ● 审批工作流 │ ● RBAC定义   │ ● 访问报告     │
│ ● 离职删除    │ ● SOD检查   │ ● 角色分配    │ ● 审计跟踪     │
│ ● 账号同步    │ ● 临时访问  │ ● 角色管理    │ ● 违规检测     │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

## 身份生命周期管理

### Joiner-Mover-Leaver模型

```
入职（Joiner）：
┌─ 接收HR通知 → 创建AD/LDAP账号 → 分配默认组 → 预配应用账号 → 发送欢迎邮件

转岗（Mover）：
┌─ 接收HR变更 → 移除旧角色权限 → 添加新角色权限 → 触发权限认证

离职（Leaver）：
┌─ 接收HR通知 → 禁用所有账号 → 撤销SSO会话 → 转移数据所有权 → 归档账号
```

```python
# 身份生命周期自动化（Python示例）
class IdentityLifecycle:
    def __init__(self, hr_system, directory, app_connectors):
        self.hr = hr_system      # HR系统（如Workday）
        self.directory = directory  # 目录服务（AD/Azure AD）
        self.apps = app_connectors  # 各应用连接器
    
    def handle_joiner(self, employee):
        """处理新员工入职"""
        user_id = employee["email"].split("@")[0]
        
        # 1. 在AD中创建用户
        ad_user = self.directory.create_user(
            username=user_id,
            display_name=employee["name"],
            department=employee["department"],
            manager=employee["manager_email"]
        )
        
        # 2. 根据部门分配默认组
        default_groups = {
            "Engineering": ["Engineering-Team", "Code-Repo-Access", "Jira-Users"],
            "Finance": ["Finance-Team", "ERP-Users", "Report-Readers"],
            "HR": ["HR-Team", "HR-System", "Employee-DB-Readers"]
        }
        
        for group in default_groups.get(employee["department"], []):
            self.directory.add_user_to_group(ad_user["id"], group)
        
        # 3. 预配应用账号
        for app_config in employee.get("required_apps", []):
            self.apps[app_config["app_id"]].create_account(
                user_id=user_id,
                role=app_config["role"]
            )
        
        return {"user_id": user_id, "status": "provisioned"}
    
    def handle_mover(self, employee, new_department):
        """处理员工转岗"""
        # 1. 获取当前所有权限
        current_entitlements = self.get_user_entitlements(employee["email"])
        
        # 2. 移除旧部门的权限
        old_department_rules = self.role_mapping.get(employee["department"], [])
        for rule in old_department_rules:
            self.remove_entitlement(employee["email"], rule)
        
        # 3. 添加新部门权限
        new_department_rules = self.role_mapping.get(new_department, [])
        for rule in new_department_rules:
            self.add_entitlement(employee["email"], rule)
        
        # 4. 触发重新认证
        self.trigger_certification(employee["email"], 
            reason=f"Department change: {employee['department']} -> {new_department}")
        
        return {"status": "updated", "new_department": new_department}
    
    def handle_leaver(self, employee_email):
        """处理员工离职"""
        # 1. 禁用所有账号
        self.directory.disable_user(employee_email)
        for app in self.apps.values():
            app.disable_account(employee_email)
        
        # 2. 撤销所有活跃的SSO会话
        self.revoke_sso_session(employee_email)
        
        # 3. 获取经理信息
        user_info = self.directory.get_user(employee_email)
        manager_email = user_info["manager"]
        
        # 4. 转移数据所有权
        self.transfer_data_ownership(employee_email, manager_email)
        
        # 5. 发送通知
        self.send_notification("security-team", 
            f"离职处理完成: {employee_email}, 数据已转移至 {manager_email}")
        
        return {"status": "deprovisioned", "user": employee_email}
```

## 角色挖掘（Role Mining）

角色挖掘是从现有用户权限中分析并定义最优角色集合的过程。

### Top-Down vs Bottom-Up

| 方法 | 描述 | 适用场景 |
|------|------|---------|
| Top-Down（自上而下） | 根据组织结构和业务职能定义角色 | 组织架构清晰的企业 |
| Bottom-Up（自下而上） | 分析现有用户权限，通过聚类算法发现角色 | 权限复杂、历史悠久的组织 |

```python
# 简化的角色挖掘算法
import pandas as pd
from collections import defaultdict

def role_mining(permission_data):
    """
    permission_data: DataFrame, columns=[user_id, resource, access_type]
    分析用户权限模式，自动推荐角色定义
    """
    # 1. 构建用户权限矩阵
    user_perm_matrix = pd.crosstab(
        permission_data['user_id'], 
        permission_data['resource'],
        values=permission_data['access_type'],
        aggfunc='count'
    ).fillna(0)
    
    # 2. 计算用户相似度
    from sklearn.metrics.pairwise import cosine_similarity
    user_similarity = cosine_similarity(user_perm_matrix)
    
    # 3. 基于相似度聚类用户
    from sklearn.cluster import DBSCAN
    clustering = DBSCAN(eps=0.3, min_samples=3)
    clusters = clustering.fit_predict(user_perm_matrix)
    
    # 4. 生成角色建议
    roles = {}
    for cluster_id in set(clusters):
        if cluster_id == -1:
            continue  # 未聚类的用户（单独处理）
        
        cluster_users = user_perm_matrix.index[clusters == cluster_id]
        cluster_perms = user_perm_matrix.loc[cluster_users].sum()
        
        # 取该集群中80%以上用户共有的权限
        common_perms = cluster_perms[cluster_perms >= len(cluster_users) * 0.8]
        
        roles[cluster_id] = {
            "users": cluster_users.tolist(),
            "common_permissions": common_perms.index.tolist(),
            "size": len(cluster_users)
        }
    
    return roles
```

## 访问认证活动（Campaign）

认证活动是定期审查用户权限的过程，通常每季度或每年执行一次。

### 认证流程

```
认证活动生命周期：

创建阶段 ──→ 执行阶段 ──→ 审批阶段 ──→ 关闭阶段
    │            │            │            │
    │ 定义范围    │ 发送通知   │ 自动提醒   │ 执行变更
    │ 选取审查人  │ 审查人审批 │ 升级处理   │ 生成报告
    │ 设定时间线  │ 标记拒绝   │ 被拒权限   │ 关闭活动
    │           │            │ 自动移除   │
```

### 认证活动自动化

```python
class CertificationCampaign:
    def __init__(self, iga_system):
        self.iga = iga_system
    
    def create_campaign(self, config):
        """创建认证活动"""
        campaign = {
            "name": config["name"],
            "type": config["type"],  # "entitlement", "role", "user"
            "reviewers": config["reviewers"],  # {user: [reviewer_email]}
            "deadline": config["deadline"],
            "reminder_intervals": [7, 3, 1],  # 截止前7,3,1天提醒
            "escalation": {
                "after_days": 2,  # 超期2天后升级
                "escalate_to": config.get("escalation_manager")
            }
        }
        
        # 创建活动任务
        tasks = []
        for user, reviewer in config["reviewers"].items():
            tasks.append({
                "user": user,
                "reviewer": reviewer,
                "entitlements": self.iga.get_user_entitlements(user),
                "status": "pending",
                "assigned_at": datetime.now()
            })
        
        campaign["tasks"] = tasks
        self.iga.create_campaign(campaign)
        return campaign
    
    def process_decision(self, task_id, decision, comment=""):
        """处理认证决策"""
        task = self.iga.get_task(task_id)
        
        if decision == "approve":
            task["status"] = "approved"
        elif decision == "revoke":
            # 标记等待执行撤销
            task["status"] = "revoked"
            self.scheduled_actions.append({
                "type": "remove_entitlement",
                "user": task["user"],
                "entitlements": task["entitlements"],
                "execute_at": task.get("revoke_delay_days", 7)  # 宽限期
            })
        elif decision == "delegate":
            # 委托给他人审查
            task["status"] = "delegated"
            task["reviewer"] = comment
            task["assigned_at"] = datetime.now()
        
        return task
```

## IGA工具对比

| 特性 | SailPoint | Saviynt | Omada |
|------|-----------|---------|-------|
| 架构 | 支持本地+云+混合 | 云原生 | 支持本地+云 |
| 连接器数量 | 200+ | 150+ | 100+ |
| 角色挖掘 | AI驱动的角色建议 | 基于ML的角色优化 | 基于规则的角色发现 |
| 认证活动 | 灵活的工作流配置 | 自动认证+升级 | 多维度认证 |
| 访问分析 | IdentityNow Analytics | 可视化访问分析 | 内置报告套件 |
| AI/ML能力 | AI驱动的身份分析（AIA） | 异常访问检测 | 智能角色建议 |
| 云支持 | IdentityNow（SaaS） | 原生云 | Identity as a Service |

### SailPoint配置示例

```yaml
# SailPoint IdentityNow 访问请求策略
access_request_policy:
  name: "Production DB Access"
  
  # 审批工作流
  approval_workflow:
    steps:
      - step: 1
        approver: "${user.manager}"
        type: "MANAGER"
        timeout_days: 3
        escalation: "HR_ROTATION"
      
      - step: 2
        approver: "data_owners@company.com"
        type: "GROUP"
        timeout_days: 5
        escalation: "security_team"
  
  # 职责分离（SOD）检查
  sod_checks:
    - name: "不可同时拥有开发和生产权限"
      check_type: "MUTUALLY_EXCLUSIVE"
      entitlements:
        - "PROD_DB_WRITE"
        - "DEV_DB_ADMIN"
      action: "BLOCK_REQUEST"
    
    - name: "不可同时拥有读写和审计权限"
      check_type: "MUTUALLY_EXCLUSIVE"
      entitlements:
        - "FINANCIAL_REPORT_WRITE"
        - "FINANCIAL_AUDIT"
      action: "FLAG_FOR_REVIEW"
  
  # 主动认证有效期
  certification_renewal: "QUARTERLY"
```

## 职责分离（SOD）

SOD是防止利益冲突和欺诈的关键控制：

| 角色组合 | 风险描述 | 风险等级 |
|---------|---------|---------|
| 创建供应商 + 审批付款 | 创建虚假供应商并付款 | 关键 |
| 采购下单 + 验收货物 | 虚构采购并确认收货 | 关键 |
| 系统管理 + 审计日志查看 | 管理员可消除自身痕迹 | 高 |
| 薪资核算 + 员工数据管理 | 篡改薪资数据 | 高 |

## 总结

身份治理IGA是身份安全体系的基础。通过自动化的Joiner-Mover-Leaver生命周期管理，结合角色挖掘和定期认证活动，IGA确保正确的用户在正确的时间拥有正确的权限。SOD控制进一步降低了内部的欺诈风险。在零信任架构中，IGA提供了"身份"这一核心维度的治理基础。
