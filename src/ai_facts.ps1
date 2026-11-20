# security-watch: local facts for one AI explanation. Read-only. Keep this file ASCII-only.
# __DATA__ is replaced with base64 (UTF-8) lines "T <tcp|udp> <port>" / "N <process name>" /
# "P <file path>". The values come from logs, so they are never spliced into the script
# text: only the base64 alphabet is, ports are cast to [int], and every lookup uses
# -Name / -Id / -LiteralPath.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Out($s) { [Console]::Out.WriteLine($s) }
function Cut($s, $n) { $s = ([string]$s -replace '[\r\n]+', ' ').Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }

$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__'))
$names = @(); $paths = @(); $wantPorts = @()
foreach ($line in ($data -split "`n")) {
    if ($line.StartsWith('N ')) { $names += $line.Substring(2) }
    elseif ($line.StartsWith('P ')) { $paths += $line.Substring(2) }
    elseif ($line.StartsWith('T ')) {
        $f = $line.Substring(2) -split ' '
        if ($f.Count -eq 2 -and ($f[0] -eq 'tcp' -or $f[0] -eq 'udp')) { $wantPorts += , @($f[0], [int]$f[1]) }
    }
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
# Windows services by host process id (readable without administrator rights).
$svcByPid = @{}
foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 })) {
    $k = [int]$s.ProcessId
    if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.ArrayList }
    [void]$svcByPid[$k].Add($s)
}
function SvcTag($id) {
    if ($svcByPid.ContainsKey([int]$id)) { ' [' + (($svcByPid[[int]$id] | ForEach-Object { $_.Name }) -join ',') + ']' } else { '' }
}

# --- ports named in the item: who owns them, which services, which firewall rules ---
if ($wantPorts.Count -gt 0) {
    $filters = @(Get-NetFirewallPortFilter -All)
    foreach ($wp in $wantPorts) {
        $proto = $wp[0]; $port = [int]$wp[1]
        $eps = if ($proto -eq 'tcp') { @($tcp | Where-Object { $_.LocalPort -eq $port }) } else { @($udp | Where-Object { $_.LocalPort -eq $port }) }
        if ($eps.Count -eq 0) { Out "port $proto ${port}: not open now"; continue }
        Out ("port $proto ${port}: open on " + (($eps | ForEach-Object { [string]$_.LocalAddress } | Sort-Object -Unique) -join ', '))
        foreach ($id in ($eps | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique)) {
            $pr = Get-Process -Id $id
            $started = if ($pr.StartTime) { ", started " + $pr.StartTime.ToString('yyyy-MM-dd HH:mm') } else { '' }
            Out ("  owner: $($pr.ProcessName) (PID $id)$started" + $(if ($pr.Path) { ", path: $($pr.Path)" } else { '' }))
            if ($svcByPid.ContainsKey($id)) {
                foreach ($s in $svcByPid[$id]) {
                    Out "  service in this process: $($s.Name) = $(Cut $s.DisplayName 80); state $($s.State), start type $($s.StartMode); image: $(Cut $s.PathName 160)"
                }
            } else {
                Out "  service in this process: none"
            }
        }
        $rules = @($filters | Where-Object { $_.Protocol -eq $proto.ToUpper() -and (@($_.LocalPort) -contains [string]$port) } | Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' })
        if ($rules.Count -eq 0) { Out "  firewall: no enabled inbound rule for this port number (program-based rules not checked)" }
        foreach ($r in ($rules | Select-Object -First 5)) {
            $a = $r | Get-NetFirewallAddressFilter
            Out "  firewall: inbound $($r.Action) '$(Cut $r.DisplayName 80)' profiles=$($r.Profile) remote=$((@($a.RemoteAddress)) -join ',')"
        }
    }
    Out ("network profiles: " + ((Get-NetConnectionProfile | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" }) -join ', '))
}

# --- processes named in the item ---
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
    $listen = @($tcp | Where-Object { $ids -contains [int]$_.OwningProcess } | ForEach-Object { "tcp $($_.LocalAddress):$($_.LocalPort)$(SvcTag $_.OwningProcess)" }) +
              @($udp | Where-Object { $ids -contains [int]$_.OwningProcess } | ForEach-Object { "udp $($_.LocalAddress):$($_.LocalPort)$(SvcTag $_.OwningProcess)" })
    $listen = @($listen | Select-Object -Unique)
    if ($listen.Count -gt 0) { Out ("  listening: " + (($listen | Select-Object -First 12) -join ', ') + $(if ($listen.Count -gt 12) { " (+$($listen.Count - 12) more)" } else { '' })) }
}
foreach ($p in ($paths | Select-Object -Unique)) {
    Out "file: $p"
    Out (Describe $p)
}
