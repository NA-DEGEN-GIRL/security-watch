# security-watch live feed for this PC. Read-only. ASCII-only.
# Every __INTERVAL__ seconds: new RDP / logon events ("EV ...") and the
# established inbound TCP connections ("CONNS" block).
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Out($s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Ts($t) { ([DateTimeOffset]$t).ToUnixTimeSeconds() }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logs = @{
    core = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
    lsm  = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    sec  = 'Security'
}
# Start after the newest existing record so old history is not replayed.
$lastId = @{}
foreach ($k in $logs.Keys) {
    $e = Get-WinEvent -LogName $logs[$k] -MaxEvents 1
    $lastId[$k] = if ($e) { $e.RecordId } else { 0 }
}
$ipre = '(\d{1,3}(\.\d{1,3}){3})'
$from = (Get-Date).AddMinutes(-1)

# USB devices present now; later arrivals are reported as USBNEW.
function UsbDevices {
    $m = @{}
    Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^(USB|USBSTOR|HID)\\' } | ForEach-Object {
        $vid = if ($_.InstanceId -match 'VID_([0-9A-F]{4})') { $Matches[1] } else { '----' }
        $prodId = if ($_.InstanceId -match 'PID_([0-9A-F]{4})') { $Matches[1] } else { '----' }
        $m[$_.InstanceId] = '{0} {1} {2} {3}' -f $_.Class, $vid, $prodId, ($_.FriendlyName -replace '\s+', '_')
    }
    $m
}
$usb = UsbDevices

while ($true) {
    $now = Get-Date
    $cur = UsbDevices
    foreach ($k in $cur.Keys) { if (-not $usb.ContainsKey($k)) { Out ("EV {0} USBNEW {1}" -f (Ts $now), $cur[$k]) } }
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
    $from = $now.AddSeconds(-30)

    $listen = @{}
    Get-NetTCPConnection -State Listen | ForEach-Object { $listen[[int]$_.LocalPort] = 1 }
    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
    Out ("CONNS " + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    Get-NetTCPConnection -State Established | Where-Object {
        $listen.ContainsKey([int]$_.LocalPort) -and $_.RemoteAddress -notin @('127.0.0.1', '::1')
    } | ForEach-Object {
        Out ("CONN tcp {0}:{1} {2}:{3} {4}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $procs[[int]$_.OwningProcess])
    }
    Out "CONNS_END"
    Start-Sleep -Seconds __INTERVAL__
}
