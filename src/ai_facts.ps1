# security-watch: local facts for one AI explanation. Read-only. Keep this file ASCII-only.
# __DATA__ is replaced with base64 (UTF-8) lines "N <process name>" / "P <file path>".
# The names and paths come from logs, so they are never spliced into the script text:
# only the base64 alphabet is, and every lookup uses -Name / -LiteralPath.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Out($s) { [Console]::Out.WriteLine($s) }
function Cut($s, $n) { $s = ([string]$s -replace '[\r\n]+', ' ').Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }

$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__'))
$names = @(); $paths = @()
foreach ($line in ($data -split "`n")) {
    if ($line.StartsWith('N ')) { $names += $line.Substring(2) }
    elseif ($line.StartsWith('P ')) { $paths += $line.Substring(2) }
}

function Describe($p) {
    $item = Get-Item -LiteralPath $p -Force
    if (-not $item -or $item.PSIsContainer) { return "  file: not found" }
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    $signer = ''
    if ($sig.SignerCertificate) { $signer = (($sig.SignerCertificate.Subject -split ', ')[0]) -replace '^CN=', '' }
    $v = $item.VersionInfo
    $lines = @("  signature: $($sig.Status)" + $(if ($signer) { " (signer: $signer)" } else { '' }))
    if ($v.CompanyName -or $v.FileDescription) { $lines += "  version info: company=$(Cut $v.CompanyName 80); description=$(Cut $v.FileDescription 80); product=$(Cut $v.ProductName 80)" }
    $lines += "  modified: " + $item.LastWriteTime.ToString('yyyy-MM-dd') + ", size: $($item.Length) bytes"
    return ($lines -join "`n")
}

$tcp = @(Get-NetTCPConnection -State Listen)
$udp = @(Get-NetUDPEndpoint)
foreach ($n in ($names | Select-Object -Unique)) {
    $procs = @(Get-Process -Name $n)
    if ($procs.Count -eq 0) { Out "process '$n': not running now"; continue }
    $ids = $procs | ForEach-Object { [int]$_.Id }
    $exes = @($procs | ForEach-Object { $_.Path } | Where-Object { $_ } | Sort-Object -Unique)
    Out "process '$n': $($procs.Count) running"
    if ($exes.Count -eq 0) { Out "  path: not readable (needs administrator)" }
    foreach ($exe in $exes) {
        Out "  path: $exe"
        Out (Describe $exe)
    }
    $ports = @($tcp | Where-Object { $ids -contains [int]$_.OwningProcess } | ForEach-Object { "tcp $($_.LocalAddress):$($_.LocalPort)" }) +
             @($udp | Where-Object { $ids -contains [int]$_.OwningProcess } | ForEach-Object { "udp $($_.LocalAddress):$($_.LocalPort)" })
    $ports = @($ports | Select-Object -Unique)
    if ($ports.Count -gt 0) { Out ("  listening: " + (($ports | Select-Object -First 12) -join ', ') + $(if ($ports.Count -gt 12) { " (+$($ports.Count - 12) more)" } else { '' })) }
}
foreach ($p in ($paths | Select-Object -Unique)) {
    Out "file: $p"
    Out (Describe $p)
}
