# security-watch live feed for this PC. Read-only. ASCII-only.
# Every __INTERVAL__ seconds: new RDP / logon / USB events ("EV ..."), antivirus and
# service-install events ("X" lines), the established inbound TCP connections ("CONNS"
# block), the programs holding outbound connections ("O" lines) and newly started
# processes ("P" lines). What counts as suspicious is decided by security-watch, not here.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Out($s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Ts($t) { ([DateTimeOffset]$t).ToUnixTimeSeconds() }
function Clean($s) { ("$s" -replace '[\t\r\n]+', ' ').Trim() }
# Tab-separated record: kind, unix time, then the fields.
function Rec($kind, $t, $fields) { Out (("{0}`t{1}`t" -f $kind, $t) + (($fields | ForEach-Object { Clean $_ }) -join "`t")) }
function Fields($e) { $d = @{}; ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }; $d }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logs = @{
    core = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
    lsm  = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    sec  = 'Security'
    def  = 'Microsoft-Windows-Windows Defender/Operational'
    sys  = 'System'
}
# Start after the newest existing record so old history is not replayed.
$lastId = @{}
foreach ($k in $logs.Keys) {
    $e = Get-WinEvent -LogName $logs[$k] -MaxEvents 1
    $lastId[$k] = if ($e) { $e.RecordId } else { 0 }
}
$ipre = '(\d{1,3}(\.\d{1,3}){3})'
$private = '^(10\.|127\.|0\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|::$|::1$|fe[89ab]|f[cd])'
$from = (Get-Date).AddMinutes(-1)

# USB devices present now; later arrivals are reported as USBNEW.
function UsbDevices {
    $m = @{}
    Get-CimInstance Win32_PnPEntity -Property PNPDeviceID, Name, PNPClass -Filter "PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'HID%'" | ForEach-Object {
        $vid = if ($_.PNPDeviceID -match 'VID_([0-9A-F]{4})') { $Matches[1] } else { '----' }
        $prodId = if ($_.PNPDeviceID -match 'PID_([0-9A-F]{4})') { $Matches[1] } else { '----' }
        $m[$_.PNPDeviceID] = '{0} {1} {2} {3}' -f $_.PNPClass, $vid, $prodId, ($_.Name -replace '\s+', '_')
    }
    $m
}
$usb = UsbDevices

# Signature state of an executable: S valid, U unsigned or untrusted, B hash mismatch
# (file altered after signing), ? unknown. Checked once per path. Verifying means hashing
# the whole file, so very large executables are only asked whether they carry a signature,
# and each tick has a time budget: past it the answer is $null and the caller asks again
# on a later tick.
$sigs = @{}
$spent = @{ ms = 0 }
function Sig($path) {
    if (-not $path) { return '?' }
    if ($sigs.ContainsKey($path)) { return $sigs[$path] }
    if ($spent.ms -gt 1500) { return $null }
    $w = [Diagnostics.Stopwatch]::StartNew()
    $r = '?'
    $f = Get-Item -LiteralPath $path -Force
    if ($f -and $f.Length -gt 64MB) {
        try { [void][Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($path); $r = 'S' } catch { $r = 'U' }
    } elseif ($f) {
        $s = Get-AuthenticodeSignature -LiteralPath $path
        if ($s) {
            switch ("$($s.Status)") { 'Valid' { $r = 'S' } 'HashMismatch' { $r = 'B' } 'NotSigned' { $r = 'U' } 'NotTrusted' { $r = 'U' } }
        }
    }
    $spent.ms += $w.ElapsedMilliseconds
    $sigs[$path] = $r
    $r
}
# Places programs do not normally live; only executables there get a signature check.
$odd = '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Downloads\\|\\Desktop\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\AppData\\Roaming\\[^\\]+$|^[A-Za-z]:\\ProgramData\\[^\\]+$'

# This feed and the programs security-watch itself starts are not reported.
$me = $PID
$owner = [int](Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
$known = @{}   # "pid|name" -> executable path
$pending = New-Object System.Collections.ArrayList   # new processes waiting for a signature check
$first = $true
$cols = 'ProcessId', 'ParentProcessId', 'Name', 'ExecutablePath', 'CommandLine'

while ($true) {
    $now = Get-Date
    $t = Ts $now
    $spent.ms = 0
    $cur = UsbDevices
    foreach ($k in $cur.Keys) { if (-not $usb.ContainsKey($k)) { Out ("EV {0} USBNEW {1}" -f $t, $cur[$k]) } }
    $usb = $cur
    Get-WinEvent -FilterHashtable @{ LogName = $logs.core; Id = 131, 140; StartTime = $from } |
        Where-Object { $_.RecordId -gt $lastId.core } | Sort-Object RecordId | ForEach-Object {
            $lastId.core = $_.RecordId
            if ($_.Message -match $ipre) {
                Out ("EV {0} {1} {2}" -f (Ts $_.TimeCreated), $(if ($_.Id -eq 131) { 'RDPCONN' } else { 'RDPFAIL' }), $Matches[1])
            }
        }
    Get-WinEvent -FilterHashtable @{ LogName = $logs.lsm; Id = 21, 25; StartTime = $from } |
        Where-Object { $_.RecordId -gt $lastId.lsm } | Sort-Object RecordId | ForEach-Object {
            $lastId.lsm = $_.RecordId
            $x = ([xml]$_.ToXml()).Event.UserData.EventXML
            if ($x.Address -and $x.Address -notin @('LOCAL', '::1', '127.0.0.1')) {
                Out ("EV {0} RDPLOGON {1} {2}" -f (Ts $_.TimeCreated), $x.User, $x.Address)
            }
        }
    if ($admin) {
        Get-WinEvent -FilterHashtable @{ LogName = $logs.sec; Id = 4625; StartTime = $from } -MaxEvents 500 |
            Where-Object { $_.RecordId -gt $lastId.sec } | Sort-Object RecordId | ForEach-Object {
                $lastId.sec = $_.RecordId
                $ip = $_.Properties[19].Value
                if ($ip -and $ip -ne '-') { Out ("EV {0} LOGONFAIL {1}" -f (Ts $_.TimeCreated), $ip) }
            }
    }
    # Antivirus: detections, protection switched off, configuration changes.
    Get-WinEvent -FilterHashtable @{ LogName = $logs.def; Id = 1006, 1015, 1116, 5001, 5007, 5010, 5012, 5013; StartTime = $from } |
        Where-Object { $_.RecordId -gt $lastId.def } | Sort-Object RecordId | ForEach-Object {
            $lastId.def = $_.RecordId
            $d = Fields $_
            $et = Ts $_.TimeCreated
            $id = [int]$_.Id
            if ($id -in 1006, 1015, 1116) { Rec 'X' $et @('DEFTHREAT', $id, $d['Threat Name'], $d['Path'], $d['Process Name']) }
            elseif ($id -in 5001, 5010, 5012) { Rec 'X' $et @('DEFOFF', $id) }
            elseif ($id -eq 5007) { Rec 'X' $et @('DEFCFG', $(if ($d['New Value']) { $d['New Value'] } else { 'removed: ' + $d['Old Value'] })) }
            elseif ($id -eq 5013) { Rec 'X' $et @('DEFTAMPER', $d['Value']) }
        }
    # Newly installed services and cleared event logs.
    Get-WinEvent -FilterHashtable @{ LogName = $logs.sys; Id = 104, 7045; StartTime = $from } |
        Where-Object { $_.RecordId -gt $lastId.sys } | Sort-Object RecordId | ForEach-Object {
            $lastId.sys = $_.RecordId
            if ($_.Id -eq 7045 -and $_.ProviderName -eq 'Service Control Manager') {
                $d = Fields $_
                Rec 'X' (Ts $_.TimeCreated) @('SVCNEW', $d['ServiceName'], $d['ImagePath'], $d['ServiceType'], $d['AccountName'])
            } elseif ($_.Id -eq 104 -and $_.ProviderName -eq 'Microsoft-Windows-Eventlog') {
                Rec 'X' (Ts $_.TimeCreated) @('LOGCLEAR', ([xml]$_.ToXml()).Event.UserData.LogFileCleared.Channel)
            }
        }
    $from = $now.AddSeconds(-30)

    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }

    # Processes started since the last tick (everything on the first one). The full WMI
    # query is slow, so later ticks ask only for the new process ids.
    $fresh = @($procs.Keys | Where-Object { -not $known.ContainsKey(('{0}|{1}' -f $_, $procs[$_])) })
    $rows = @()
    if ($first -or $fresh.Count -gt 40) {
        $rows = @(Get-CimInstance Win32_Process -Property $cols)
    } elseif ($fresh.Count -gt 0) {
        $rows = @(Get-CimInstance Win32_Process -Property $cols -Filter (($fresh | ForEach-Object { "ProcessId=$_" }) -join ' OR '))
    }
    $next = @{}
    foreach ($id in $procs.Keys) {
        $k = '{0}|{1}' -f $id, $procs[$id]
        if ($known.ContainsKey($k)) { $next[$k] = $known[$k] }
    }
    foreach ($r in $rows) {
        $id = [int]$r.ProcessId
        $k = '{0}|{1}' -f $id, ($r.Name -replace '\.exe$', '')
        if ($next.ContainsKey($k)) { continue }
        $path = "$($r.ExecutablePath)"
        $next[$k] = $path
        $pp = [int]$r.ParentProcessId
        if ($id -le 4 -or $id -eq $me -or $id -eq $owner -or $pp -eq $me -or $pp -eq $owner) { continue }
        $cmd = "$($r.CommandLine)" -replace '[\t\r\n]+', ' '
        if ($cmd.Length -gt 4000) { $cmd = $cmd.Substring(0, 4000) }
        $parent = if ($procs.ContainsKey($pp)) { $procs[$pp] } else { '?' }
        $rec = "{0}`t{1}`t{2}`t{3}" -f $id, $pp, $r.Name, $parent
        if ($path -match $odd) { [void]$pending.Add(@($rec, $path, $cmd)) }
        else { Out ("P`t{0}`t{1}`t-`t{2}`t{3}" -f $t, $rec, $path, $cmd) }
    }
    foreach ($w in @($pending)) {
        $sig = Sig $w[1]
        if ($null -eq $sig) { break }
        Out ("P`t{0}`t{1}`t{2}`t{3}`t{4}" -f $t, $w[0], $sig, $w[1], $w[2])
        $pending.Remove($w)
    }
    $known = $next
    $first = $false

    $listen = @{}
    # Inbound = local address:port matches a listener reachable from outside (wildcard or
    # that exact address). Port-only matching misread outbound connections whose ephemeral
    # source port happened to equal some loopback-only listener's port.
    $tcp = @(Get-NetTCPConnection)
    $tcp | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -notin @('127.0.0.1', '::1') } |
        ForEach-Object { $listen[('{0}|{1}' -f $_.LocalAddress, $_.LocalPort)] = 1 }
    $outbound = @{}
    Out ("CONNS " + $t)
    $tcp | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
        $p = $_.LocalPort
        $name = $procs[[int]$_.OwningProcess]
        if ($listen.ContainsKey("0.0.0.0|$p") -or $listen.ContainsKey("::|$p") -or $listen.ContainsKey(('{0}|{1}' -f $_.LocalAddress, $p))) {
            Out ("CONN tcp {0}:{1} {2}:{3} {4}" -f $_.LocalAddress, $p, $_.RemoteAddress, $_.RemotePort, $name)
        } elseif ($name -and $_.RemoteAddress -notmatch $private) {
            # outbound: one line per program and remote port, public peers only
            $k = '{0}|{1}' -f $name, $_.RemotePort
            if (-not $outbound.ContainsKey($k)) { $outbound[$k] = @($name, $_.RemoteAddress, $_.RemotePort, $known[('{0}|{1}' -f [int]$_.OwningProcess, $name)]) }
        }
    }
    Out "CONNS_END"
    foreach ($o in $outbound.Values) {
        $sig = Sig $o[3]
        if ($null -eq $sig) { $sig = '-' }   # not checked yet
        Rec 'O' $t @($o[0], $o[1], $o[2], $sig, $o[3])
    }
    Start-Sleep -Seconds __INTERVAL__
}
