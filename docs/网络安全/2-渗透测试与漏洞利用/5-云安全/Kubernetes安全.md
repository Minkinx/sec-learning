# Kubernetes安全

## 概述

Kubernetes（K8s）是事实上的容器编排标准，但其默认配置通常不足以满足生产安全要求。K8s安全涵盖集群组件安全、RBAC配置、Pod安全策略、网络安全策略、镜像安全和运行时安全等多个方面。错误配置的K8s集群可能导致容器逃逸、数据泄露和控制平面被接管。

## 控制平面安全

### API Server安全

API Server是K8s集群的入口，所有管理请求都通过它：

```bash
# 检查API Server是否匿名访问
kubectl create clusterrolebinding anonymous-admin \
  --clusterrole=cluster-admin --user=system:anonymous

# 检测API Server配置
# 查看API Server Pod的参数
kubectl get pods -n kube-system -l component=kube-apiserver -o yaml

# 关键安全参数
# --anonymous-auth=false     # 禁止匿名访问
# --enable-admission-plugins=NodeRestriction,PodSecurity,...
# --authorization-mode=RBAC,Node
# --tls-cert-file, --tls-private-key-file  # 配置TLS证书
```

### etcd安全

etcd存储集群所有状态和密钥，是最高价值目标：

```bash
# 检查etcd是否可未经认证访问
# 默认监听localhost:2379，但可能暴露
curl http://etcd-endpoint:2379/v2/keys/

# 从etcd读取密钥
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:2379 get /registry/secrets/default/

# 通过Pod直接访问etcd
kubectl exec -it -n kube-system etcd-master -- sh
ETCDCTL_API=3 etcdctl get /registry/secrets/default/secret-name

# 检查etcd配置
kubectl get pods -n kube-system -l component=etcd -o yaml | grep -A 5 command

# 安全配置
# --client-cert-auth=true    # 客户端证书认证
# --peer-client-cert-auth=true  # 节点间证书认证
# --cert-file, --key-file    # etcd自身证书
```

## RBAC审计

### 默认服务账号权限

```bash
# 检查默认命名空间的服务账号
kubectl get serviceaccounts

# 检查默认服务账号是否绑定过高权限
kubectl get rolebinding,clusterrolebinding --all-namespaces | grep default

# 创建风险：允许从Pod内访问API
kubectl describe serviceaccount default -n default
# Mountable secrets:  default-token-xxxxx
# 自动挂载Token

# 禁止自动挂载服务账号Token
# 在Pod声明中添加
automountServiceAccountToken: false
```

### 常见RBAC配置错误

```yaml
# 错误的ClusterRole（权限过大）
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]        # 所有API组
  resources: ["*"]        # 所有资源
  verbs: ["*"]            # 所有操作
---
# 正确的ClusterRole（最小权限）
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

### RBAC审计命令

```bash
# 检查具有cluster-admin权限的主体
kubectl get clusterrolebinding -o wide | grep cluster-admin

# 检查所有绑定关系
kubectl get rolebinding,clusterrolebinding --all-namespaces

# 检查特定用户的权限
kubectl auth can-i list pods --as=system:serviceaccount:default:my-sa

# 检查特定Service Account的权限
kubectl describe rolebinding -n default sa-binding

# 审计谁可以创建Pod
kubectl auth can-i create pods --as=some-user

# 审计谁可以访问secrets
kubectl auth can-i get secrets --all-namespaces --as=user

# 审计谁具有特权Pod创建权限
kubectl auth can-i create pods --as=user -n default
```

## kubelet安全

### 匿名访问风险

```bash
# kubelet默认在10250端口监听，可能开放匿名访问
# 如果--anonymous-auth=true且未认证

# 列出Pod信息
curl -sk https://node-ip:10250/pods

# 在Pod内执行命令
curl -sk https://node-ip:10250/run/namespace/pod/container \
  -d "cmd=id"

# 从健康检查端点获取信息
curl http://node-ip:10255/healthz
curl http://node-ip:10255/spec/

# 配置强制认证
# kubelet配置
# --anonymous-auth=false
# --authentication-token-webhook=true
# --authorization-mode=Webhook
```

### kubelet命令执行探测

```bash
#!/bin/bash
# 批量检测kubelet匿名访问
NODES=("10.0.0.1" "10.0.0.2" "10.0.0.3")
FORBIDDEN_NS=("kube-system" "default")

for node in "${NODES[@]}"; do
  echo "[*] Testing $node..."
  response=$(curl -sk --connect-timeout 3 https://$node:10250/pods)
  if [[ "$response" == *"kind"* ]]; then
    echo "[!] $node has unauthenticated kubelet!"
  fi
done
```

## Pod安全

### Pod Security Admission

Pod Security Standards（PSS）替代了废弃的PodSecurityPolicy：

```yaml
# 命名空间级别强制Pod安全（标签方式）
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted    # 强制restricted
    pod-security.kubernetes.io/audit: baseline        # 审计baseline违规
    pod-security.kubernetes.io/warn: baseline         # 警告baseline违规
```

```yaml
# Restricted级别Pod规范（最严格）
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
```

### OPA/Gatekeeper策略

使用OPA（Open Policy Agent）定义自定义安全策略：

```yaml
# Gatekeeper约束模板：禁止特权容器
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivilegedcontainer
        violation[{"msg": msg}] {
          input.review.object.spec.containers[_].securityContext.privileged
          msg := "Privileged container is not allowed"
        }
---
# 应用约束
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "production"
```

## 网络安全策略

### 默认允许全部流量

```bash
# 检查命名空间是否有网络策略
kubectl get networkpolicies --all-namespaces

# 默认情况下，所有Pod可互相通信
# 没有NetworkPolicy → 允许所有流量

# 当前NetworkPolicy统计
kubectl get netpol -A | wc -l
```

### 最小特权网络策略

```yaml
# 拒绝所有入站和出站流量（Deny All）
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# 仅允许特定入口流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-access
spec:
  podSelector:
    matchLabels:
      app: api-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
---
# 允许出站DNS查询
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-dns
spec:
  podSelector:
    matchLabels:
      app: api-server
  egress:
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - port: 53
      protocol: UDP
```

## 镜像与供应链安全

### 镜像扫描

```bash
# 使用Trivy扫描镜像
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myapp:latest

# 扫描K8s集群
trivy k8s --report summary cluster

# 扫描本地文件系统
trivy fs .

# CI/CD集成
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

### 镜像签名（Cosign）

```bash
# 生成密钥对
cosign generate-key-pair

# 对镜像签名
cosign sign --key cosign.key registry.example.com/myapp:latest

# 验证签名
cosign verify --key cosign.pub registry.example.com/myapp:latest

# 在K8s中强制签名验证（使用Connaisseur或Ratify）
```

### 准入控制器

```yaml
# 使用Kyverno策略验证镜像来源
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-signature
    match:
      resources:
        kinds:
        - Pod
    verifyImages:
    - image: "registry.example.com/*"
      key: |-
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
```

## 安全扫描与审计工具

| 工具 | 用途 | 特点 |
|------|------|------|
| kube-bench | CIS Benchmark | 检查K8s安全配置合规 |
| kube-hunter | 漏洞扫描 | 渗透测试视角的扫描 |
| Kubescape | 合规扫描 | NSA/CISA K8s加固指南 |
| Popeye | 集群健康检查 | 自动修复建议 |
| Falco | 运行时安全 | 异常行为检测 |
| Trivy | 镜像漏洞扫描 | 支持多输出格式 |

### kube-bench

```bash
# 运行CIS Benchmark检查
kube-bench run --targets=master
kube-bench run --targets=node
kube-bench run --targets=etcd

# 输出JSON格式
kube-bench run --json > results.json

# Docker运行
docker run --pid=host -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /usr/bin:/usr/bin:ro \
  aquasec/kube-bench:latest run
```

### Falco运行时监控

```yaml
# Falco规则示例：检测容器内的Shell执行
- rule: Terminal Shell in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container
    and shell_procs and not user_shell_container_exclusions
  output: >
    A shell was spawned in a container
    (user=%user.name container_id=%container.id
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

## 防御清单

- **RBAC最小权限**：禁止cluster-admin的Service Account
- **禁止匿名访问**：设置`--anonymous-auth=false`
- **启用准入控制**：配置PodSecurity、Kyverno/OPA Gatekeeper
- **etcd加密**：启用etcd TLS加密和认证
- **网络安全策略**：每个命名空间配置NetworkPolicy
- **服务账号限制**：禁止自动挂载Token，限最小权限
- **镜像安全**：扫描漏洞，使用签名验证
- **Secret加密**：启用KMS加密Provider
- **审计日志**：启用API Server审计日志
- **节点安全**：kubelet认证授权，限制kubelet命令执行
- **资源配额**：配置ResourceQuota限制资源消耗
- **运行时安全**：部署Falco检测异常行为

## 参考资源

- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [Falco](https://falco.org/)
- [Kubescape](https://github.com/kubescape/kubescape)
