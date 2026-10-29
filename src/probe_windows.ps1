# security-watch local probe for Windows. Read-only.
# __SINCE__ is replaced with a unix epoch before running.
# Output: one record per line, "<KEY> <fields...>". Keep this file ASCII-only.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$since = [DateTimeOffset]::FromUnixTimeSeconds([int64]__SINCE__).LocalDateTime
function Out($s) { [Console]::Out.WriteLine($s) }

Out "META hostname $env:COMPUTERNAME"
Out ("META os " + (Get-CimInstance Win32_OperatingSystem).Caption)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Out ("META root " + $(if ($admin) { 'yes' } else { 'no' }))

# --- listening sockets (non-loopback) ---
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
    Out ("LISTEN tcp {0} {1} {2}" -f $_.LocalAddress, $_.LocalPort, $procs[[int]$_.OwningProcess])
}
Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
    Out ("LISTEN udp {0} {1} {2}" -f $_.LocalAddress, $_.LocalPort, $procs[[int]$_.OwningProcess])
}

# --- accounts ---
Get-LocalUser | ForEach-Object { Out ("USER {0} {1}" -f $_.Name, $(if ($_.Enabled) { 'enabled' } else { 'disabled' })) }
Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { Out ("ADMIN " + $_.Name) }

# --- persistence: Run keys, startup folders, scheduled tasks, auto-start services ---
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    $p = Get-ItemProperty -Path $k
    if (-not $p) { continue }
    $short = ($k -replace '\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', '\')
    # Skip Microsoft updaters' one-shot post-update cleanup (e.g. msedge_cleanup_{GUID}
    # -> ...\Microsoft\<Edge|Copilot|...>\Application\<ver>\Installer\setup.exe).
    $p.PSObject.Properties | Where-Object {
        $_.Name -notlike 'PS*' -and -not ($_.Name -like '*_cleanup_*' -and [string]$_.Value -match '\\Microsoft\\[^\\]+\\Application\\[\d.]+\\Installer\\setup\.exe')
    } | ForEach-Object {
        $v = [string]$_.Value
        if ($v.Length -gt 90) { $v = $v.Substring(0, 90) }
        Out ("AUTORUN {0}\{1} = {2}" -f $short, $_.Name, $v)
    }
}
foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($d) { Get-ChildItem -LiteralPath $d -File | ForEach-Object { Out ("AUTORUN startup\" + $_.Name) } }
}
# \SoftLanding\<SID>\ holds Windows Start/tips tasks that rotate GUID names; skip them
# only while every action is a COM handler (no exe/script), so a planted program still shows.
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' -and
    -not ($_.TaskPath -like '\SoftLanding\*' -and -not ($_.Actions | Where-Object { $_.Execute }))
} | ForEach-Object {
    Out ("TASK " + $_.TaskPath + $_.TaskName)
}
Get-CimInstance Win32_Service | Where-Object {
    $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(system32|SysWOW64|Microsoft\.NET|servicing)\\'
} | ForEach-Object { Out ("SERVICE " + $_.Name) }

# --- remote access: RDP, OpenSSH server ---
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
Out ("RDP {0} nla={1}" -f $(if ($ts.fDenyTSConnections -eq 0) { 'enabled' } else { 'disabled' }), $nla)
$ipre = '(\d{1,3}(\.\d{1,3}){3})'
$core = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
Get-WinEvent -FilterHashtable @{ LogName = $core; Id = 131, 140; StartTime = $since } |
    ForEach-Object { if ($_.Message -match $ipre) { '{0} {1}' -f $_.Id, $Matches[1] } } |
    Group-Object | ForEach-Object {
        $id, $ip = $_.Name -split ' '
        Out ("{0} {1} {2}" -f $(if ($id -eq '131') { 'RDPCONN' } else { 'RDPFAIL' }), $_.Count, $ip)
    }
$oldest = Get-WinEvent -LogName $core -MaxEvents 1 -Oldest
if ($oldest) { Out ("RDPLOGSTART " + ([DateTimeOffset]$oldest.TimeCreated).ToUnixTimeSeconds()) }
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21, 25; StartTime = $since } |
    ForEach-Object {
        $x = ([xml]$_.ToXml()).Event.UserData.EventXML
        if ($x.Address -and $x.Address -notin @('LOCAL', '::1', '127.0.0.1')) { '{0} {1}' -f $x.User, $x.Address }
    } | Group-Object | ForEach-Object {
        $u, $ip = $_.Name -split ' ', 2
        Out ("RDPLOGON {0} {1} {2}" -f $_.Count, $u, $ip)
    }
$sshd = Get-Service sshd
if ($sshd) { Out ("SSHD " + $sshd.Status) }

# --- failed Windows logons (needs administrator) ---
if ($admin) {
    $f = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 5000)
    Out ("LOGONFAILTOTAL " + $f.Count)
    $f | ForEach-Object { $_.Properties[19].Value } | Where-Object { $_ -and $_ -ne '-' } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 10 |
        ForEach-Object { Out ("LOGONFAIL {0} {1}" -f $_.Count, $_.Name) }
} else {
    Out "META securitylog no-admin"
}

# --- protection status ---
$mp = Get-MpComputerStatus
if ($mp) { Out ("DEFENDER realtime={0} antivirus={1} sigage={2}" -f $mp.RealTimeProtectionEnabled, $mp.AntivirusEnabled, $mp.AntivirusSignatureAge) }
Get-NetFirewallProfile | ForEach-Object { Out ("FIREWALL {0} {1}" -f $_.Name, $_.Enabled) }
Out "END"
