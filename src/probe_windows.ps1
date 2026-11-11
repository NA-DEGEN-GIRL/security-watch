# security-watch local probe for Windows. Read-only.
# __SINCE__ is replaced with a unix epoch before running.
# Output: one record per line, "<KEY> <fields...>". Keep this file ASCII-only.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$since = [DateTimeOffset]::FromUnixTimeSeconds([int64]__SINCE__).LocalDateTime
function Out($s) { [Console]::Out.WriteLine($s) }
function Cut($s, $n) { $s = ([string]$s -replace '[\r\n]+', ' ').Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }

Out "META hostname $env:COMPUTERNAME"
Out ("META os " + (Get-CimInstance Win32_OperatingSystem).Caption)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Out ("META root " + $(if ($admin) { 'yes' } else { 'no' }))

# --- listening sockets (non-loopback) ---
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notlike '127.*' -and $_.LocalAddress -ne '::1' } | ForEach-Object {
    Out ("LISTEN tcp {0} {1} {2}" -f $_.LocalAddress, $_.LocalPort, $procs[[int]$_.OwningProcess])
}
Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notlike '127.*' -and $_.LocalAddress -ne '::1' } | ForEach-Object {
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
    # Same for OneDrive: RunOnce "cmd /q /c del|rmdir" of its own old version folder.
    $p.PSObject.Properties | Where-Object {
        $_.Name -notlike 'PS*' -and -not ($_.Name -like '*_cleanup_*' -and [string]$_.Value -match '\\Microsoft\\[^\\]+\\Application\\[\d.]+\\Installer\\setup\.exe') -and
        -not ($k -like '*\RunOnce' -and [string]$_.Value -match '^[A-Z]:\\Windows\\system32\\cmd\.exe /q /c (del /q|rmdir /s /q) "[^"&|<>]*\\Microsoft\\OneDrive\\[^"&|<>]*"$')
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

# --- less common start points that get hijacked; fixed names are always printed so a change shows ---
function Val($key, $name) {
    $v = (@((Get-ItemProperty -Path $key -Name $name).$name) | Where-Object { $_ }) -join ','
    if ($v) { Cut $v 200 } else { '-' }
}
$nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$nt32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion'
$cc = 'HKLM:\SYSTEM\CurrentControlSet\Control'
Out ("PERSIST winlogon\Shell = " + (Val "$nt\Winlogon" 'Shell'))
Out ("PERSIST winlogon\Userinit = " + (Val "$nt\Winlogon" 'Userinit'))
Out ("PERSIST winlogon\Shell(user) = " + (Val 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell'))
Out ("PERSIST AppInit_DLLs = " + (Val "$nt\Windows" 'AppInit_DLLs'))
Out ("PERSIST AppInit_DLLs(32) = " + (Val "$nt32\Windows" 'AppInit_DLLs'))
Out ("PERSIST lsa\AuthenticationPackages = " + (Val "$cc\Lsa" 'Authentication Packages'))
Out ("PERSIST lsa\NotificationPackages = " + (Val "$cc\Lsa" 'Notification Packages'))
Out ("PERSIST lsa\SecurityPackages = " + (Val "$cc\Lsa" 'Security Packages'))
Out ("PERSIST lsa\SecurityPackages(os) = " + (Val "$cc\Lsa\OSConfig" 'Security Packages'))
Out ("PERSIST BootExecute = " + (Val "$cc\Session Manager" 'BootExecute'))
Out ("PERSIST logonscript(user) = " + (Val 'HKCU:\Environment' 'UserInitMprLogonScript'))
foreach ($b in @($nt, $nt32)) {
    $tag = $(if ($b -eq $nt32) { '(32)' } else { '' })
    Get-ChildItem -Path "$b\Image File Execution Options" | ForEach-Object {
        $d = $_.GetValue('Debugger')
        if ($d) { Out ("PERSIST ifeo{0}\{1} = {2}" -f $tag, $_.PSChildName, (Cut $d 200)) }
    }
}
Get-ChildItem -Path "$nt\SilentProcessExit" | ForEach-Object {
    $d = $_.GetValue('MonitorProcess')
    if ($d) { Out ("PERSIST exitmonitor\{0} = {1}" -f $_.PSChildName, (Cut $d 200)) }
}
foreach ($e in @(
        @('appcert', "$cc\Session Manager\AppCertDlls"),
        @('policyrun', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
        @('policyrun(user)', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'))) {
    $p = Get-ItemProperty -Path $e[1]
    if ($p) {
        $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Out ("PERSIST {0}\{1} = {2}" -f $e[0], $_.Name, (Cut $_.Value 200))
        }
    }
}

# --- redirection of names and web traffic: hosts file, system proxy ---
# (Docker Desktop and Tailscale keep their own hosts entries up to date; those are left out)
$hl = @(Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" |
    ForEach-Object { (($_ -replace '#.*', '') -replace '\s+', ' ').Trim() } |
    Where-Object { $_ -and $_ -notmatch 'docker\.internal$' -and $_ -notmatch '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+ \S+\.ts\.net\.?( |$)' } |
    Sort-Object -Unique)
$hl | Select-Object -First 60 | ForEach-Object { Out ("HOSTS " + (Cut $_ 120)) }
if ($hl.Count -gt 60) { Out ("HOSTS (+{0} more)" -f ($hl.Count - 60)) }
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Out ("PROXY enable={0} server={1} pac={2}" -f [int]$is.ProxyEnable, $(if ($is.ProxyServer) { Cut $is.ProxyServer 120 } else { '-' }), $(if ($is.AutoConfigURL) { Cut $is.AutoConfigURL 120 } else { '-' }))

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
if ($mp) { Out ("DEFENDER realtime={0} antivirus={1} sigage={2} tamper={3}" -f $mp.RealTimeProtectionEnabled, $mp.AntivirusEnabled, $mp.AntivirusSignatureAge, $mp.IsTamperProtected) }
# what Defender found since $since (the live feed reports these as they happen)
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1006, 1015, 1116; StartTime = $since } | ForEach-Object {
    $d = @{}
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ($d['Threat Name']) { '{0} | {1}' -f $d['Threat Name'], ($d['Path'] -split '; ')[0] }
} | Group-Object { ($_ -split ' \| ', 2)[0] } | ForEach-Object {
    Out ("THREAT {0} {1}" -f $_.Count, (Cut $_.Group[0] 220))
}
Get-NetFirewallProfile | ForEach-Object { Out ("FIREWALL {0} {1}" -f $_.Name, $_.Enabled) }
Out "END"
