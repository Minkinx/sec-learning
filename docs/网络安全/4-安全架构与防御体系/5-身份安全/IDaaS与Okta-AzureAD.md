# IDaaS与Okta-AzureAD

> 身份即服务（Identity as a Service, IDaaS）将身份管理能力以云服务形式交付。Okta和Azure AD（Entra ID）是目前最主流的IDaaS平台，提供SSO、MFA、身份生命周期管理和条件访问等能力。

## IDaaS架构概览

```
IDaaS云身份架构：
┌─────────────────────────────────────────────────────────────┐
│                     IDaaS Provider (Okta/Azure AD)             │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐  │
│  │              统一身份目录（Universal Directory）        │  │
│  │   用户         │   组         │   设备       │   应用    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐ │
│  │  认证服务  │ │  授权服务  │ │ 生命周期  │ │  安全分析     │ │
│  │ SSO/MFA   │ │ 条件访问  │ │ SCIM同步  │ │ 风险检测      │ │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
              │                    │
              ▼                    ▼
    ┌──────────────────┐  ┌──────────────────┐
    │   SaaS应用        │  │   自建应用        │
    │  Salesforce/Workday│  │   (SAML/OIDC)    │
    │  Slack/Zoom       │  │   (反向代理)      │
    └──────────────────┘  └──────────────────┘
```

## Okta

Okta是市场领先的独立IDaaS提供商，不依附于某一云平台。

### Okta核心组件

| 组件 | 功能 |
|------|------|
| Universal Directory | 统一用户目录，支持自定义属性和架构扩展 |
| Single Sign-On | 7000+预集成应用，SAML/OIDC认证 |
| Adaptive MFA | 基于上下文的MFA策略（位置、设备、风险） |
| Lifecycle Management | SCIM协议自动用户预配和解除 |
| Okta Workflows | 低代码自动化工作流引擎 |
| API Access Management | OAuth 2.0/OIDC API保护 |

### Okta SSO配置示例

```yaml
# Okta应用配置（简化YAML）
app_config:
  label: "Salesforce"
  sign_on_mode: "SAML 2.0"
  
  saml_settings:
    acs_url: "https://company.my.salesforce.com?so=00D..."
    entity_id: "https://company.my.salesforce.com"
    audience: "https://saml.salesforce.com"
    name_id_format: "EMAIL"
    attribute_statements:
      - name: "email"
        value: "user.email"
      - name: "firstName"
        value: "user.firstName"
      - name: "lastName"
        value: "user.lastName"
      - name: "department"
        value: "user.department"
    
  lifecycle:
    provisioning: "SCIM 2.0"
    scim_base_url: "https://company.my.salesforce.com/services/scim/v2"
    auth_method: "OAuth Bearer Token"
    features:
      - CREATE_USER
      - UPDATE_USER
      - DEACTIVATE_USER
      - SYNC_GROUPS
  
  assignment:
    groups:
      - "Salesforce-Users"
      - "Salesforce-Admin"
    users: ""
```

### Okta Adaptive MFA策略

```json
{
  "policy": {
    "name": "Adaptive Access Policy for Engineering",
    "priority": 1,
    "conditions": {
      "users": {
        "include": ["Engineering-Team"]
      },
      "network": {
        "connection": "ANYWHERE"
      },
      "risk": {
        "levels": ["LOW", "MEDIUM", "HIGH"]
      },
      "device": {
        "platform": "ANY",
        "managed": true
      }
    },
    "actions": {
      "signon": {
        "access": "ALLOW",
        "requireFactor": [
          {
            "factorType": "password"
          },
          {
            "factorType": "webauthn"  // FIDO2安全密钥
          }
        ],
        "factorSequence": "REQUIRE_ALL"
      },
      "idp": {
        "providers": ["OKTA", "CORP_AD"]
      }
    }
  }
}
```

## Azure AD / Entra ID

Azure AD已更名为Microsoft Entra ID，是Microsoft云身份平台。

### Entra ID核心能力

### 条件访问策略

```json
{
  "displayName": "Block legacy auth and require MFA for external access",
  "state": "enabled",
  "conditions": {
    "applications": {
      "includeApplications": ["All"]
    },
    "users": {
      "includeUsers": [],
      "includeGroups": ["All-Employees"],
      "excludeUsers": ["emergency_admin@company.com"]
    },
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["Trusted-Office-IPs"]
    },
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "builtInControls": [
      "mfa",
      "compliantDevice"
    ],
    "operator": "AND",
    "authenticationStrength": {
      "displayName": "MFA with TOTP or FIDO2"
    }
  },
  "sessionControls": {
    "sessionLifetime": {
      "type": "absolute",
      "expiration": 480  // 8小时
    },
    "signInFrequency": {
      "value": 4,
      "type": "hours"
    }
  }
}
```

### Identity Protection（身份保护）

```powershell
# Azure AD Identity Protection风险策略配置（PowerShell）

# 配置用户风险策略（高危用户自动阻止）
$userRiskPolicy = New-MgIdentityProtectionRiskDetectionPolicy `
  -DisplayName "User Risk Policy" `
  -State "enabled" `
  -UserRiskLevel "high" `
  -UserRiskDurationInDays 1 `
  -GrantControl @{
    BuiltInControls = @("blockAccess")
  }

# 配置登录风险策略（中高风险登录要求MFA）
$signInRiskPolicy = New-MgIdentityProtectionSignInRiskPolicy `
  -DisplayName "Sign-in Risk Policy" `
  -State "enabled" `
  -SignInRiskLevel "medium" `
  -GrantControl @{
    BuiltInControls = @("mfa")
  }

# 风险检测类型
$riskDetections = @(
  @{type="AtypicalTravel"; severity="medium"},
  @{type="AnonymousIPAddress"; severity="medium"},
  @{type="MalwareLinkedIPAddress"; severity="high"},
  @{type="UnfamiliarSignInProperties"; severity="high"},
  @{type="LeakedCredentials"; severity="high"},
  @{type="SuspiciousSendingPatterns"; severity="medium"}
)
```

## Okta vs Azure AD对比

| 特性 | Okta | Azure AD (Entra ID) |
|------|------|-------------------|
| 核心定位 | 独立身份云平台 | Microsoft云身份底座 |
| 预集成应用 | 7000+ | 3000+（含Microsoft应用） |
| 协议支持 | SAML/OIDC/SCIM/WS-Fed | SAML/OIDC/SCIM/WS-Fed/Kerberos |
| 生命周期管理 | SCIM + Okta Workflows | SCIM + Microsoft Identity Manager |
| MFA能力 | Adaptive MFA（基于风险） | Conditional Access（丰富条件） |
| 设备管理 | Okta Device Trust | Intune集成（更深度） |
| B2B场景 | 强（Okta B2B） | 强（Azure AD B2B/B2C） |
| 离线能力 | 有OIN集成但深度有限 | 深度集成Office 365/Teams |
| 自动化 | Okta Workflows（低代码） | Power Automate + Logic Apps |
| 身份治理 | Identity Governance模块 | Entra ID Governance |
| 定价 | 按用户/月（独立定价） | 包含在E5/E3许可中 |

### 选择建议

| 场景 | 推荐IDaaS | 理由 |
|------|----------|------|
| 以Office 365/Teams为核心 | Azure AD | 原生集成，管理统一 |
| 多云/异构环境 | Okta | 应用集成最丰富，厂商中立 |
| 混合身份场景 | 两者结合 | Okta处理SAML应用，Azure AD处理Microsoft生态 |
| B2C客户身份 | Azure AD B2C / Okta | 两者都支持，看需求 |
| 高安全合规行业 | Okta（独立审计合规） | 独立的SOC 2/ISO认证 |

## Federation配置（SAML/OIDC）

### SAML 2.0 Federation配置示例

```xml
<!-- SAML IdP元数据文件（Okta导出的IDP元数据） -->
<EntityDescriptor entityID="http://www.okta.com/exkabcdef123456789">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>
            MIIDazCCAlOgAwIBAgIETm7jVzANBgkqhkiG9w0BAQsF...
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="https://company.okta.com/app/salesforce/exkabcdef123456789/sso/saml"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://company.okta.com/app/salesforce/exkabcdef123456789/sso/saml"/>
  </IDPSSODescriptor>
</EntityDescriptor>
```

```bash
# 使用saml2test验证SAML配置
saml2test \
  --idp-metadata idp-metadata.xml \
  --sp-metadata sp-metadata.xml \
  --acs-url https://app.company.com/saml/acs \
  --entity-id https://app.company.com/saml \
  --name-id admin@company.com
```

### OIDC Federation配置

```python
# OIDC客户端配置（Python Flask示例）
from flask import Flask, redirect, session
from flask_oidc import OpenIDConnect
import requests

app = Flask(__name__)
app.config.update({
    'OIDC_CLIENT_ID': 'your-client-id',
    'OIDC_CLIENT_SECRET': 'your-client-secret',
    'OIDC_PROVIDER_ISSUER': 'https://company.okta.com/oauth2/default',
    'OIDC_SCOPES': ['openid', 'profile', 'email', 'groups'],
    'SECRET_KEY': 'your-secret-key',
    'OIDC_ID_TOKEN_COOKIE_SECURE': True,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
})

oidc = OpenIDConnect(app)

@app.route('/')
@oidc.require_login
def index():
    # 用户信息来自ID Token
    return f"""
    <h1>Welcome, {oidc.user_getfield('name')}</h1>
    <p>Email: {oidc.user_getfield('email')}</p>
    <p>Groups: {oidc.user_getfield('groups')}</p>
    <p>Issuer: {oidc.user_getfield('iss')}</p>
    <a href="/logout">Logout</a>
    """

@app.route('/logout')
def logout():
    # 通过与IdP的RP-initiated SSO注销
    id_token = session.get('oidc_auth_token', {}).get('id_token')
    oidc.logout()
    
    # 重定向到Okta注销端点
    params = {
        'id_token_hint': id_token,
        'post_logout_redirect_uri': 'https://app.company.com/logged-out',
    }
    logout_url = 'https://company.okta.com/oauth2/default/v1/logout'
    return redirect(f"{logout_url}?{urllib.parse.urlencode(params)}")

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

## SCIM用户预配

SCIM（System for Cross-domain Identity Management）是身份生命周期管理的标准协议：

```json
// SCIM 2.0 创建用户请求（POST /scim/v2/Users）
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "zhangsan@company.com",
  "name": {
    "givenName": "San",
    "familyName": "Zhang"
  },
  "emails": [
    {
      "value": "zhangsan@company.com",
      "type": "work",
      "primary": true
    }
  ],
  "active": true,
  "groups": [
    {"value": "salesforce-users", "display": "Salesforce Users"},
    {"value": "engineering-core", "display": "Engineering Core"}
  ]
}
```

```python
# SCIM客户端实现示例
import requests
import json

class SCIMClient:
    def __init__(self, scim_url, token):
        self.base_url = scim_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def create_user(self, user_data):
        """在目标应用中创建用户"""
        response = requests.post(
            f"{self.base_url}/Users",
            headers=self.headers,
            json=user_data
        )
        return response.json()
    
    def update_user(self, user_id, updates):
        """更新用户属性"""
        response = requests.patch(
            f"{self.base_url}/Users/{user_id}",
            headers=self.headers,
            json=updates
        )
        return response.json()
    
    def deactivate_user(self, user_id):
        """停用用户"""
        return self.update_user(user_id, {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {"active": False}
            }]
        })
    
    def list_users(self, filter_query=""):
        """列出用户"""
        params = {"filter": filter_query} if filter_query else {}
        response = requests.get(
            f"{self.base_url}/Users",
            headers=self.headers,
            params=params
        )
        return response.json()
```

## 总结

IDaaS是现代企业身份管理的基石。Okta以丰富的应用集成和中立生态见长，Azure AD以深度Microsoft集成和条件访问能力著称。选择IDaaS平台需要综合考虑现有的云生态、应用组合、合规要求和预算。在零信任架构中，IDaaS承担了策略决策点（PDP）的角色，为所有应用提供统一的认证、授权和生命周期管理能力。
