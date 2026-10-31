# ============================================================
#  AssUI_Elec 日志账号 / 密码扫描器 by 因式分解x
#  用途：扫描 AssUI_Elec（校园网接入客户端）日志，提取
#        UserName / Password 字段，并按客户端自定义的
#        Base64 规则自动解码。
#  解码规则：字母表 A-Za-z0-9+, ，其中
#            ':' -> '='   （填充符）
#            ',' -> '/'   （替换斜杠）
#            '-' -> '+'   '_' -> '/'（兼容 URL-safe 变体）
#            末尾省略的 '=' 自动补齐
#  用法：
#     .\AssUI_CredScan.ps1                      # 扫描整个日志目录
#     .\AssUI_CredScan.ps1 -Date 2026-10-23     # 只扫描指定日期
#     .\AssUI_CredScan.ps1 -Path D:\x.log       # 指定文件
#     .\AssUI_CredScan.ps1 -Full                # 额外输出逐条原始记录
#     .\AssUI_CredScan.ps1 -Mask                # 密码打码，便于截图
# ============================================================

[CmdletBinding()]
param(
    [string]$Path,
    [string]$Date,
    [string]$OutDir = 'D:\信息',
    [string]$OutFile,
    [switch]$Mask,
    [switch]$Full,
    [switch]$NoReport,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

# ---------- 常量 ----------
$script:FieldRegex = [regex]'"(?<k>UserName|userName|TrueNames|Password|PassWord|Pwd)"\s*:\s*"(?<v>(?:[^"\\]|\\.)*)"'
$script:TimeRegex  = [regex]'^\[(?<t>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\]'
$script:UserKeys   = @('UserName', 'userName')
$script:PassKeys   = @('Password', 'PassWord', 'Pwd')

# ---------- 工具函数 ----------

# 读取日志：先按严格 UTF-8 解码，失败则按 GB18030(936) 解码
function Read-LogText {
    param([string]$FilePath)
    $bytes = [IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -eq 0) { return '' }
    try {
        $strict = New-Object System.Text.UTF8Encoding($false, $true)
        return $strict.GetString($bytes)
    } catch {
        return [Text.Encoding]::GetEncoding(936).GetString($bytes)
    }
}

# 还原 JSON 里的 \uXXXX 转义
function Expand-JsonUnicode {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $Text.IndexOf('\u') -lt 0) { return $Text }
    return [regex]::Replace($Text, '\\u([0-9a-fA-F]{4})', {
        param($m)
        [char][Convert]::ToInt32($m.Groups[1].Value, 16)
    })
}

# 判断解码结果是否像正常文本（可见 ASCII / 中文）
function Test-TextLike {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text.IndexOf([char]0xFFFD) -ge 0) { return $false }   # 含替换符，说明解码错了
    $bad = 0
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        if ($c -lt 0x20 -or $c -eq 0x7F) { $bad++; continue }
        if ($c -ge 0x4E00 -and $c -le 0x9FFF) { continue }
        if ($c -ge 0x3000 -and $c -le 0x303F) { continue }
        if ($c -ge 0xFF00 -and $c -le 0xFFEF) { continue }
        if ($c -gt 0x7E) { $bad++ }
    }
    if ($bad / $Text.Length -gt 0.2) { return $false }
    return ($Text -match '[\w\u4e00-\u9fff@#$%^&*!]')
}

# 账号形态：ASCII 账号/手机号/邮箱，用来排除中文显示名
function Test-AccountLike {
    param([string]$Text)
    return ($Text -match '^[A-Za-z0-9][A-Za-z0-9_.@\-]{2,}$')
}

# 按 AssUI 自定义 Base64 规则解码；失败返回 $null
function ConvertFrom-AssuiB64 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $s = $Value.Trim()
    # 纯数字一定不是 Base64（账号原文），避免把手机号误当编码
    if ($s -match '^\d+$') { return $null }

    $s = $s.Replace(':', '=').Replace(',', '/').Replace('-', '+').Replace('_', '/')
    $s = $s.TrimEnd('=')
    if ($s.Length -lt 6 -or $s -notmatch '^[A-Za-z0-9+/]+$') { return $null }

    $pad = (4 - ($s.Length % 4)) % 4
    if ($pad -eq 3) { return $null }          # 长度非法，不可能是 Base64
    $s = $s + ('=' * $pad)

    try { $bytes = [Convert]::FromBase64String($s) } catch { return $null }
    if ($bytes.Length -eq 0) { return $null }

    $txt = $null
    try {
        $txt = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes)
    } catch {
        # 非 UTF-8 时，仅当原文带自定义替换符才按 GBK 兜底，否则视为误判
        if ($Value -match '[,:]') {
            $txt = [Text.Encoding]::GetEncoding(936).GetString($bytes)
        } else {
            return $null
        }
    }
    $txt = $txt.Trim([char]0, ' ', "`t", "`r", "`n")
    if (-not (Test-TextLike $txt)) { return $null }
    return $txt
}

# 把字段原始值解析成 "明文 / Base64" 结果
function Resolve-FieldValue {
    param([string]$Raw)
    $plain = Expand-JsonUnicode $Raw
    if ([string]::IsNullOrWhiteSpace($plain)) {
        return [pscustomobject]@{ Ok = $false; Value = ''; Kind = 'empty' }
    }
    $decoded = ConvertFrom-AssuiB64 $plain
    # 只有当解码结果与原文不同、且原文不像普通账号时才认为是 Base64
    if ($decoded -and $decoded -ne $plain) {
        return [pscustomobject]@{ Ok = $true; Value = $decoded; Kind = 'base64' }
    }
    return [pscustomobject]@{ Ok = $true; Value = $plain; Kind = 'plain' }
}

# 显示宽度（中文按 2 列计）
function Get-DisplayWidth {
    param([string]$Text)
    $w = 0
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        if (($c -ge 0x1100 -and $c -le 0x115F) -or
            ($c -ge 0x2E80 -and $c -le 0xA4CF) -or
            ($c -ge 0xAC00 -and $c -le 0xD7A3) -or
            ($c -ge 0xF900 -and $c -le 0xFAFF) -or
            ($c -ge 0xFE30 -and $c -le 0xFE6F) -or
            ($c -ge 0xFF00 -and $c -le 0xFF60) -or
            ($c -ge 0xFFE0 -and $c -le 0xFFE6)) { $w += 2 } else { $w += 1 }
    }
    return $w
}

function Format-Cell {
    param([string]$Text, [int]$Width)
    $Text = [string]$Text
    $w = Get-DisplayWidth $Text
    if ($w -ge $Width) { return $Text }
    return $Text + (' ' * ($Width - $w))
}

function Hide-Secret {
    param([string]$Secret)
    if (-not $Mask) { return $Secret }
    if ($Secret.Length -le 2) { return '**' }
    return $Secret.Substring(0, 2) + ('*' * [Math]::Min(6, $Secret.Length - 2))
}

# ---------- 解析扫描目标 ----------
$logDir = Join-Path $env:APPDATA 'AssUI_Elec\Log'

if ($Date) {
    if ($Date -notmatch '^\d{4}-\d{2}-\d{2}$') { throw "日期格式应为 yyyy-MM-dd，例如 2026-10-23" }
    $Path = Join-Path $logDir ("{0}.log" -f $Date)
}
if ([string]::IsNullOrWhiteSpace($Path)) { $Path = $logDir }

if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $targets = @(Get-Item -LiteralPath $Path)
} elseif (Test-Path -LiteralPath $Path -PathType Container) {
    $targets = @(Get-ChildItem -LiteralPath $Path -Filter '*.log' -File | Sort-Object Name)
} else {
    throw "找不到日志路径：$Path"
}
if ($targets.Count -eq 0) { throw "目录下没有 *.log 文件：$Path" }

# ---------- 扫描 ----------
$pairRecords  = New-Object System.Collections.Generic.List[object]
$userRecords  = New-Object System.Collections.Generic.List[object]
$fileStats    = New-Object System.Collections.Generic.List[object]

foreach ($file in $targets) {
    $text  = Read-LogText $file.FullName
    $lines = $text -split "`r?`n"
    $lineNo = 0
    $filePairs = 0
    $filePassFields = 0
    $fileUsers = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($line in $lines) {
        $lineNo++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $work = $line
        $fm = $script:FieldRegex.Matches($work)
        if ($fm.Count -eq 0 -and $line.IndexOf('%22') -ge 0) {
            try {
                $work = [uri]::UnescapeDataString($line)
                $fm = $script:FieldRegex.Matches($work)
            } catch { }
        }
        if ($fm.Count -eq 0) { continue }

        $tm = $script:TimeRegex.Match($line)
        $ts = if ($tm.Success) { $tm.Groups['t'].Value } else { '' }

        $candidates = New-Object System.Collections.Generic.List[object]
        $passVal = $null
        foreach ($m in $fm) {
            $k = $m.Groups['k'].Value
            $v = $m.Groups['v'].Value
            if ($script:UserKeys -contains $k) {
                $rv = Resolve-FieldValue $v
                $rv | Add-Member -NotePropertyName Key -NotePropertyValue $k -Force
                $candidates.Add($rv)
            } elseif (-not $passVal -and ($script:PassKeys -contains $k)) {
                $passVal = Resolve-FieldValue $v
                if ($v -ne '') { $filePassFields++ }
            }
        }
        if ($candidates.Count -eq 0) { continue }

        # 优先选 ASCII 账号形态（排除“王梓霖”这类中文显示名）
        $userVal = $candidates | Where-Object { $_.Ok -and (Test-AccountLike $_.Value) } | Select-Object -First 1
        if (-not $userVal -and $passVal) {
            $userVal = $candidates | Where-Object { $_.Ok } | Select-Object -First 1
        }
        if (-not $userVal) { continue }
        [void]$fileUsers.Add($userVal.Value)

        if ($passVal -and $passVal.Ok -and $passVal.Value -ne '') {
            $filePairs++
            $pairRecords.Add([pscustomobject]@{
                Time     = $ts
                File     = $file.Name
                LineNo   = $lineNo
                User     = $userVal.Value
                Pass     = $passVal.Value
                UserKind = $userVal.Kind
                PassKind = $passVal.Kind
            })
        } else {
            $userRecords.Add([pscustomobject]@{
                Time   = $ts
                File   = $file.Name
                LineNo = $lineNo
                User   = $userVal.Value
                Key    = $userVal.Key
                Kind   = $userVal.Kind
            })
        }
    }

    $fileStats.Add([pscustomobject]@{
        File       = $file.Name
        Lines      = $lineNo
        SizeKB     = [Math]::Round($file.Length / 1KB, 1)
        PassFields = $filePassFields
        PairCount  = $filePairs
        Users      = $fileUsers.Count
    })
}

# ---------- 汇总去重 ----------
$pairSummary = @()
if ($pairRecords.Count -gt 0) {
    $pairSummary = @($pairRecords |
        Group-Object User, Pass |
        ForEach-Object {
            $times = $_.Group | Where-Object { $_.Time } | ForEach-Object { $_.Time } | Sort-Object
            [pscustomobject]@{
                User  = $_.Group[0].User
                Pass  = $_.Group[0].Pass
                Count = $_.Count
                First = if ($times) { $times[0] } else { '' }
                Last  = if ($times) { $times[-1] } else { '' }
                Files = (($_.Group | ForEach-Object { $_.File } | Sort-Object -Unique) -join ',')
            }
        } | Sort-Object @{ Expression = 'Last'; Descending = $true }, User)
}

$userSummary = @()
if ($userRecords.Count -gt 0) {
    $pairUsers = @($pairSummary | ForEach-Object { $_.User })
    $userSummary = @($userRecords |
        Where-Object { $pairUsers -notcontains $_.User } |
        Group-Object User |
        ForEach-Object {
            $times = $_.Group | Where-Object { $_.Time } | ForEach-Object { $_.Time } | Sort-Object
            [pscustomobject]@{
                User  = $_.Group[0].User
                Count = $_.Count
                First = if ($times) { $times[0] } else { '' }
                Last  = if ($times) { $times[-1] } else { '' }
                Files = (($_.Group | ForEach-Object { $_.File } | Sort-Object -Unique) -join ',')
            }
        } | Sort-Object User)
}

# ---------- 控制台输出 ----------
if (-not $Quiet) {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' AssUI_Elec 日志账号 / 密码扫描' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host (" 扫描路径 : {0}" -f $Path)
    Write-Host (" 文件数量 : {0}" -f $targets.Count)
    Write-Host ''

    if ($pairSummary.Count -gt 0) {
        Write-Host ("[账号 ↔ 密码] 共 {0} 组" -f $pairSummary.Count) -ForegroundColor Green
        $pairSummary |
            Select-Object @{ n = '账号'; e = { $_.User } },
                          @{ n = '密码'; e = { Hide-Secret $_.Pass } },
                          @{ n = '次数'; e = { $_.Count } },
                          @{ n = '首次'; e = { $_.First } },
                          @{ n = '末次'; e = { $_.Last } },
                          @{ n = '文件'; e = { $_.Files } } |
            Format-Table -AutoSize | Out-Host
    } else {
        Write-Host '[账号 ↔ 密码] 未发现密码字段。' -ForegroundColor Yellow
    }

    if ($userSummary.Count -gt 0) {
        Write-Host ("[仅用户名，无密码字段] 共 {0} 个" -f $userSummary.Count) -ForegroundColor Yellow
        $userSummary |
            Select-Object @{ n = '账号/名称'; e = { $_.User } },
                          @{ n = '次数'; e = { $_.Count } },
                          @{ n = '首次'; e = { $_.First } },
                          @{ n = '末次'; e = { $_.Last } } |
            Format-Table -AutoSize | Out-Host
    }
}

# ---------- 生成报告 ----------
$reportPath = $null
if (-not $NoReport) {
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    if ([string]::IsNullOrWhiteSpace($OutFile)) {
        $OutFile = Join-Path $OutDir ("AssUI_凭据_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    $reportPath = $OutFile

    $sb = New-Object System.Text.StringBuilder
    $nl = "`r`n"
    [void]$sb.AppendLine('AssUI_Elec 日志账号 / 密码扫描报告')
    [void]$sb.AppendLine(('=' * 72))
    [void]$sb.AppendLine(("扫描时间 : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine(("扫描路径 : {0}" -f $Path))
    [void]$sb.AppendLine(("文件数量 : {0}" -f $targets.Count))
    [void]$sb.AppendLine('字段来源 : ASM 下发 JSON 中的 UserName / Password')
    [void]$sb.AppendLine('解码规则 : 自定义 Base64（'' : '' 代替 ''=''，'','' 代替 ''/''，省略补齐）')
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('一、账号 ↔ 密码 对应表（按账号/密码去重）')
    [void]$sb.AppendLine(('-' * 72))
    if ($pairSummary.Count -eq 0) {
        [void]$sb.AppendLine('（本次扫描范围内未出现 Password 字段）')
    } else {
        [void]$sb.AppendLine((Format-Cell '账号' 20) + (Format-Cell '密码' 24) + (Format-Cell '次数' 6) + (Format-Cell '首次' 24) + (Format-Cell '末次' 24) + '文件')
        foreach ($p in $pairSummary) {
            [void]$sb.AppendLine((Format-Cell $p.User 20) + (Format-Cell (Hide-Secret $p.Pass) 24) + (Format-Cell $p.Count 6) + (Format-Cell $p.First 24) + (Format-Cell $p.Last 24) + $p.Files)
        }
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine(('二、仅有用户名、未发现密码字段的账号（共 {0} 个）' -f $userSummary.Count))
    [void]$sb.AppendLine(('-' * 72))
    [void]$sb.AppendLine('说明：这些账号出现在 WebAuth / 设备信息 / 登录状态等记录中，')
    [void]$sb.AppendLine('      日志本身没有该次登录的 Password 字段，无法还原密码。')
    if ($userSummary.Count -gt 0) {
        [void]$sb.AppendLine((Format-Cell '账号/名称' 22) + (Format-Cell '次数' 6) + (Format-Cell '首次' 24) + (Format-Cell '末次' 24) + '文件')
        foreach ($u in $userSummary) {
            [void]$sb.AppendLine((Format-Cell $u.User 22) + (Format-Cell $u.Count 6) + (Format-Cell $u.First 24) + (Format-Cell $u.Last 24) + $u.Files)
        }
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('三、按文件统计')
    [void]$sb.AppendLine(('-' * 72))
    [void]$sb.AppendLine((Format-Cell '文件' 22) + (Format-Cell '行数' 8) + (Format-Cell '大小KB' 9) + (Format-Cell '密码字段' 9) + (Format-Cell '成对记录' 9) + '账号数')
    foreach ($s in $fileStats) {
        [void]$sb.AppendLine((Format-Cell $s.File 22) + (Format-Cell $s.Lines 8) + (Format-Cell $s.SizeKB 9) + (Format-Cell $s.PassFields 9) + (Format-Cell $s.PairCount 9) + $s.Users)
    }

    if ($Full -and $pairRecords.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(('四、逐条原始记录（共 {0} 条）' -f $pairRecords.Count))
        [void]$sb.AppendLine(('-' * 72))
        foreach ($r in $pairRecords) {
            [void]$sb.AppendLine(("{0}  {1}:{2}  {3} / {4}  [账号:{5} 密码:{6}]" -f $r.Time, $r.File, $r.LineNo, $r.User, (Hide-Secret $r.Pass), $r.UserKind, $r.PassKind))
        }
    }

    [IO.File]::WriteAllText($reportPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    # 同时导出 CSV，方便 Excel 查看
    $csvPath = [IO.Path]::ChangeExtension($reportPath, '.csv')
    $csvRows = @()
    foreach ($p in $pairSummary) {
        $csvRows += [pscustomobject]@{
            类型 = '账号密码'; 账号 = $p.User; 密码 = $p.Pass; 次数 = $p.Count
            首次 = $p.First; 末次 = $p.Last; 文件 = $p.Files
        }
    }
    foreach ($u in $userSummary) {
        $csvRows += [pscustomobject]@{
            类型 = '仅用户名'; 账号 = $u.User; 密码 = ''; 次数 = $u.Count
            首次 = $u.First; 末次 = $u.Last; 文件 = $u.Files
        }
    }
    if ($csvRows.Count -gt 0) {
        # 手动拼 CSV，保证中文与 BOM 在 PowerShell 5.1 / 7 下都正确
        $csvLines = New-Object System.Collections.Generic.List[string]
        $csvLines.Add('类型,账号,密码,次数,首次,末次,文件')
        foreach ($r in $csvRows) {
            $cells = @($r.类型, $r.账号, $r.密码, [string]$r.次数, $r.首次, $r.末次, $r.文件) |
                ForEach-Object {
                    $c = [string]$_
                    if ($c -match '[",\r\n]') { $c = '"' + $c.Replace('"', '""') + '"' }
                    $c
                }
            $csvLines.Add(($cells -join ','))
        }
        [IO.File]::WriteAllText($csvPath, (($csvLines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
    }
}

if (-not $Quiet) {
    Write-Host ''
    if ($reportPath) {
        Write-Host ("报告已保存: {0}" -f $reportPath) -ForegroundColor Green
        Write-Host ("CSV  已保存: {0}" -f ([IO.Path]::ChangeExtension($reportPath, '.csv'))) -ForegroundColor Green
    }
    Write-Host ''
}