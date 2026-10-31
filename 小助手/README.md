# AssUI_Elec 日志账号 / 密码扫描器 by 因式分解x

从校园网客户端 **AssUI_Elec** 的日志中提取 `UserName` / `Password`，并按客户端自定义的
Base64 规则自动解码。纯 PowerShell 实现，无需 Python 或第三方库。

## 文件

| 文件 | 说明 |
| --- | --- |
| `AssUI_CredScan.ps1` | 主程序（Windows PowerShell 5.1 / PowerShell 7 均可） |
| `扫描AssUI日志账号密码.bat` | 双击启动器，等价于扫描整个日志目录 |

## 用法

```powershell
# 1. 扫描整个日志目录（默认）
.\AssUI_CredScan.ps1

# 2. 只扫描某一天的日志
.\AssUI_CredScan.ps1 -Date 2026-10-23

# 3. 扫描指定文件
.\AssUI_CredScan.ps1 -Path "$env:APPDATA\AssUI_Elec\Log\2026-10-23.log"

# 4. 密码打码（截图 / 分享时用）
.\AssUI_CredScan.ps1 -Mask

# 5. 报告中附带逐条原始记录（含行号）
.\AssUI_CredScan.ps1 -Full
```

双击 `扫描AssUI日志账号密码.bat` 可免命令行直接扫描。

## 输出

- 控制台表格：账号 ↔ 密码、仅用户名账号
- `AssUI_凭据_*.txt`：完整报告（账号密码表、仅用户名表、按文件统计）
- `AssUI_凭据_*.csv`：Excel 可直接打开

## 解码规则

日志里的凭据不是标准 Base64，客户端做了替换：

| 日志中 | 实际含义 |
| --- | --- |
| `:` | `=`（填充符） |
| `,` | `/` |
| 省略的末尾 `=` | 自动补齐 |

例：`"UserName":"MTM2MjU5NDgxMzk:","Password":"d3psMzEyMzA2QA::"`
→ `13625948139` / `wzl312306@`

脚本同时兼容标准 Base64 与 URL-safe 变体（`-` `_`）。

## 实现要点

- **编码自适应**：日志为 GBK 编码，脚本先按严格 UTF-8 解码，失败自动回落 GB18030，
  中文（如姓名、场景名）不会乱码。
- **URL 编码行**：`fromassui?data=...%22UserName%22...` 这类整行百分号编码的记录会
  先做一次 URL 解码再匹配。
- **误判防护**：纯数字（手机号）不会被当成 Base64；中文显示名（如 `王梓霖`）不会被
  当成账号；解码结果必须是可读文本且能通过 UTF-8 校验。
- **时间戳**：从行首 `[yyyy-MM-dd HH:mm:ss.fff]` 提取，用于统计首次 / 末次出现时间。

## 说明

`2026-10-23.log` 当天是手机号 + WebAuth 方式登录，日志只记录了用户名
`13625948139`，**没有 Password 字段**，因此单日扫描无法得到密码；密码只出现在
09-08 ~ 10-22 的若干天日志中，扫描整个目录即可完整还原。
