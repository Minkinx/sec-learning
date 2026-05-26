# Linux安全机制

> Linux安全体系以用户权限隔离为基础，配合强制访问控制、内核安全模块和审计系统，形成多层次防护结构。

## UGO权限模型

Linux传统的UGO（User-Group-Others）权限模型控制文件访问：

```bash
$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1234 May 10 12:34 /etc/shadow
#   ^    ^    ^    ^
#   |    |    |    |
# 类型  权限  硬链接 所有者
```

| 符号 | 八进制 | 权限 |
|------|--------|------|
| r-- | 4 | 读取 |
| -w- | 2 | 写入 |
| --x | 1 | 执行 |
| rwx | 7 | 读+写+执行 |
| r-x | 5 | 读+执行 |
| rw- | 6 | 读+写 |

权限三元组：所有者（User）、所属组（Group）、其他用户（Others）

## SUID / SGID / Sticky Bit

### SUID（Set User ID）
- 使用二进制文件的所有者权限执行，而非运行者の权限
- 典型例子：`/usr/bin/passwd`（所有者root，SUID位设置）
- 安全风险：有SUID位的漏洞程序可导致本地权限提升

```bash
$ find / -perm -4000 -type f 2>/dev/null  # 查找所有SUID文件
```

### SGID（Set Group ID）
- 文件和目录：使用所属组权限执行
- 目录：新创建的文件自动继承目录的组

### Sticky Bit
- 主要用在 `/tmp` 目录
- 只有文件所有者、目录所有者或root才能删除文件
- 设置：`chmod +t /tmp`

## ACL（Access Control Lists）

UGO模型只支持所有者/所属组/其他三个级别的权限控制。ACL允许更精细的权限分配：

```bash
# 给特定用户授予权限
setfacl -m u:alice:rwx /project/data

# 给特定组授与权限
setfacl -m g:devops:rx /project/data

# 查看ACL
getfacl /project/data

# 删除特定用户ACL
setfacl -x u:alice /project/data

# 递归设置ACL（X仅对目录生效）
setfacl -R -m g:devops:rx /project/
```

ACL掩码（mask）限制命名的组ACL和用户ACL的最大权限。

## PAM（Pluggable Authentication Modules）

PAM提供可插拔的认证框架，管理员通过配置文件灵活组合认证模块：

```
# /etc/pam.d/sshd 示例
auth       required     pam_securetty.so      # 安全终端检查
auth       required     pam_unix.so           # Unix密码认证
auth       required     pam_ecryptfs.so       # 加密家目录
account    required     pam_unix.so           # 账户状态（过期/锁定）
account    required     pam_time.so           # 时间限制
password   required     pam_pwquality.so      # 密码质量
password   required     pam_unix.so           # 密码更新
session    required     pam_unix.so           # 会话管理
session    optional     pam_lastlog.so        # 登录记录
```

PAM控制字段：
| 控制 | 行为 |
|------|------|
| required | 必须通过，失败后继续执行其他模块 |
| requisite | 必须通过，失败立即返回 |
| sufficient | 通过则跳过剩余模块 |
| optional | 可选，结果仅在无其他模块时决定 |

## Namespace与Cgroup（容器隔离）

### Namespace
Linux内核通过8种Namespace实现资源隔离：

| Namespace | 隔离内容 | 用途 |
|-----------|---------|------|
| PID | 进程ID | 容器内PID独立 |
| Network | 网络栈 | 独立网卡/IP/路由 |
| Mount | 挂载点 | 独立文件系统视图 |
| User | 用户ID | 容器内root≠主机root |
| UTS | 主机名 | 独立hostname |
| IPC | 进程间通信 | 隔离共享内存/信号量 |
| Cgroup | cgroup视图 | 隔离cgroup层次 |
| Time | 系统时间 | 隔离系统时间（Linux 5.6+） |

### Cgroup（Control Groups）
- 限制和统计进程组的资源使用（CPU、内存、磁盘IO、网络带宽）
- Cgroup v2是当前默认版本（systemd 247+）
- 典型应用：Docker容器资源限制

## Capabilities

将root权限拆分为独立的capability，实现最小权限：

```bash
# 查看进程capability
$ getpcaps 1234

# 给二进制文件授予特定capability
$ setcap cap_net_raw+ep /usr/bin/ping

# 常用capability
CAP_NET_RAW     # 原始套接字（ping）
CAP_NET_BIND_SERVICE  # 绑定低端口（<1024）
CAP_SYS_ADMIN   # 系统管理（谨慎授予，接近root）
CAP_DAC_OVERRIDE # 绕过文件权限检查
```

Docker默认丢弃所有capability，按需添加。

## SELinux

SELinux是Linux内核的强制访问控制（MAC）系统，由NSA开发。

### 基本概念
- **Subject**：进程（安全上下文包含域/类型）
- **Object**：文件、套接字等资源（安全上下文包含类型）
- **Policy**：定义主体对客体的访问规则

### 安全上下文格式
```
user:role:type:level
  ↑     ↑    ↑    ↑
用户   角色  类型  敏感度级别

例：system_u:object_r:shadow_t:s0
```

### 工作模式
| 模式 | 行为 | 配置 |
|------|------|------|
| Enforcing | 强制执行策略，拒绝违规访问 | 默认 |
| Permissive | 不拒绝但记录审计日志 | 排错使用 |
| Disabled | 完全禁用SELinux | 不推荐 |

### 管理命令
```bash
getenforce                 # 查看当前模式
setenforce 1               # 临时启用Enforcing
sestatus                   # 查看SELinux状态
ls -Z /etc/shadow          # 查看文件上下文
ps -Z -p 1                 # 查看进程上下文
audit2allow -a             # 从审计日志生成允许规则
chcon -t httpd_sys_content_t /var/www/html/  # 更改文件上下文
```

## AppArmor

Ubuntu和SUSE默认的MAC机制，相比SELinux更易管理：
- 基于路径而不是inode
- 使用profile文件定义规则
- 支持complain（仅记录）和enforce（强制）模式

```bash
aa-status                  # 查看加载的profile
aa-enforce /usr/bin/proxy  # 启用强制模式
aa-complain /usr/bin/proxy # 启用记录模式
```

AppArmor与SELinux不能同时运行。

## auditd

Linux审计系统，记录系统调用的安全事件：

```bash
# audit.rules 示例
-w /etc/passwd -p wa -k passwd_changes     # 监控passwd文件写入
-w /etc/shadow -p wa -k shadow_changes     # 监控shadow文件写入
-w /etc/selinux/ -p wa -k selinux_changes  # 监控SELinux配置变更
-a exit,always -S execve                   # 记录所有程序执行
-a always,exit -F arch=b64 -S connect      # 记录网络连接

# 查看日志
ausearch -k passwd_changes                 # 搜索特定key的事件
aureport --summary                         # 审计报告摘要

# 日志位置
/var/log/audit/audit.log
```

## 参考

- Linux man pages: capabilities(7), namespaces(7), cgroups(7)
- SELinux Project Wiki (NSA)
- Docker Security Documentation
- CIS Benchmark for Linux
