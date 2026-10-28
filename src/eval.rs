//! Turns a probe snapshot (and its baseline diff) into human-readable findings.

use crate::baseline::Change;
use crate::config::{Kind, Target};
use crate::probe::{is_private_ip, Snapshot};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Alert,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Ok => "정상",
            Level::Info => "정보",
            Level::Warn => "주의",
            Level::Alert => "위험",
        }
    }
}

pub struct Finding {
    pub level: Level,
    pub text: String,
    pub details: Vec<String>,
}

fn f(level: Level, text: impl Into<String>, details: Vec<String>) -> Finding {
    Finding { level, text: text.into(), details }
}

/// `public`/`private` split of `(count, ip, extra)` rows, most frequent first.
fn split_by_ip(rows: Vec<(u64, String, String)>) -> (Vec<(u64, String, String)>, Vec<(u64, String, String)>) {
    let (mut public, mut private): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| !is_private_ip(&r.1));
    public.sort_by(|a, b| b.0.cmp(&a.0));
    private.sort_by(|a, b| b.0.cmp(&a.0));
    (public, private)
}

fn top(rows: &[(u64, String, String)], n: usize) -> Vec<String> {
    let mut v: Vec<String> = rows
        .iter()
        .take(n)
        .map(|(c, ip, extra)| if extra.is_empty() { format!("{ip}  ×{c}") } else { format!("{extra} @ {ip}  ×{c}") })
        .collect();
    if rows.len() > n {
        v.push(format!("… 외 {}개", rows.len() - n));
    }
    v
}

pub fn evaluate(t: &Target, s: &Snapshot, since: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    match t.kind {
        Kind::Local => eval_windows(s, since, &mut out),
        Kind::Remote { lan_only } => eval_linux(s, lan_only, &mut out),
    }
    if !s.complete {
        out.push(f(Level::Warn, "검사 결과를 일부만 받았습니다 (스크립트가 끝까지 실행되지 않음)", vec![]));
    }
    out
}

fn eval_linux(s: &Snapshot, lan_only: bool, out: &mut Vec<Finding>) {
    if s.meta("journal") == Some("limited") {
        out.push(f(Level::Warn, "로그 읽기 권한이 없어 SSH/방화벽 로그를 확인하지 못했습니다", vec![
            "검사 계정을 adm 또는 systemd-journal 그룹에 추가하면 확인할 수 있습니다".into(),
        ]));
    }

    // SSH brute force / probing
    if let Some(r) = s.first("SSHFAIL") {
        let (total, public, uniq) = (r.num(0), r.num(1), r.num(2));
        let tops: Vec<(u64, String, String)> =
            s.all("SSHFAILTOP").map(|r| (r.num(0), r.fields().get(1).unwrap_or(&"").to_string(), String::new())).collect();
        let (pub_rows, _) = split_by_ip(tops);
        let users: Vec<String> = s.all("SSHFAILUSER").map(|r| r.fields().get(1).unwrap_or(&"").to_string()).collect();
        let mut details = top(&pub_rows, 5);
        if !users.is_empty() {
            details.push(format!("시도한 계정 이름: {}", users.join(", ")));
        }
        if public > 0 && lan_only {
            details.push("공유기 안쪽 서버인데 인터넷에서 SSH 시도가 들어왔습니다. 공유기 포트포워딩/DMZ를 확인하세요".into());
            out.push(f(Level::Alert, format!("공인 IP에서 SSH 접속 시도 {public}건 ({uniq}개 IP)"), details));
        } else if public > 0 {
            out.push(f(Level::Info, format!("인터넷 SSH 무차별 대입 시도 {public}건 ({uniq}개 IP), 성공 기록은 아래 참고"), details));
        } else if total > 0 {
            out.push(f(Level::Info, format!("SSH 로그인 실패 {total}건 (모두 내부망)"), vec![]));
        }
    }

    // Successful SSH logins
    let accepts: Vec<(u64, String, String)> = s
        .all("ACCEPT")
        .map(|r| {
            let x = r.fields();
            (r.num(0), x.get(3).unwrap_or(&"").to_string(), format!("{} ({})", x.get(1).unwrap_or(&""), x.get(2).unwrap_or(&"")))
        })
        .collect();
    let password: Vec<String> = accepts
        .iter()
        .filter(|a| a.2.contains("(password)") || a.2.contains("(keyboard-interactive"))
        .map(|a| format!("{} @ {}  ×{}", a.2, a.1, a.0))
        .collect();
    let (pub_ok, priv_ok) = split_by_ip(accepts);
    if !pub_ok.is_empty() {
        let lvl = if lan_only { Level::Alert } else { Level::Warn };
        out.push(f(lvl, "공인 IP에서 SSH 로그인 성공, 본인 접속인지 확인하세요", top(&pub_ok, 5)));
    }
    if !password.is_empty() {
        out.push(f(Level::Warn, "비밀번호 방식 SSH 로그인이 있습니다 (키 인증만 쓰는 것을 권장)", password));
    }
    if !priv_ok.is_empty() {
        let n: u64 = priv_ok.iter().map(|r| r.0).sum();
        out.push(f(Level::Info, format!("내부망 SSH 로그인 {n}건"), top(&priv_ok, 3)));
    }

    if let Some(r) = s.first("SUDOFAIL") {
        if r.num(0) > 0 {
            out.push(f(Level::Warn, format!("sudo 비밀번호 실패 {}건", r.num(0)), vec![]));
        }
    }
    if let Some(r) = s.first("FWBLOCK") {
        if r.num(1) > 0 {
            out.push(f(Level::Info, format!("방화벽이 공인 IP 패킷 {}건을 차단 ({}개 IP)", r.num(1), r.num(2)), vec![
                "인터넷에서 이 서버까지 패킷이 도달했다는 뜻입니다 (포트포워딩된 포트)".into(),
            ]));
        }
    }
    if let Some(r) = s.first("FIREWALL") {
        if r.rest.ends_with("inactive") {
            let lvl = if lan_only { Level::Info } else { Level::Warn };
            out.push(f(lvl, "호스트 방화벽(ufw)이 꺼져 있습니다", vec![]));
        }
    }

    let uid0: Vec<String> = s.all("UID0").map(|r| r.rest.clone()).filter(|n| n != "root").collect();
    if !uid0.is_empty() {
        out.push(f(Level::Alert, "root 외에 UID 0(관리자 권한) 계정이 있습니다", uid0));
    }
    if let Some(r) = s.first("PRELOAD") {
        out.push(f(Level::Alert, "/etc/ld.so.preload 가 설정돼 있습니다 (루트킷이 자주 쓰는 수법)", vec![r.rest.clone()]));
    }
    let tmpexe: Vec<String> = s.all("TMPEXE").map(|r| r.rest.clone()).collect();
    if !tmpexe.is_empty() {
        out.push(f(Level::Alert, "임시 폴더(/tmp, /dev/shm)에서 실행 중인 프로그램이 있습니다", tmpexe));
    }
    let tmpfile: Vec<String> = s.all("TMPFILE").map(|r| r.rest.clone()).collect();
    if !tmpfile.is_empty() {
        out.push(f(Level::Warn, "임시 폴더에 새 실행 파일이 생겼습니다", tmpfile));
    }
    if s.first("REBOOT").is_some() {
        out.push(f(Level::Info, "보안 업데이트 적용을 위해 재부팅이 필요합니다", vec![]));
    }
}

fn eval_windows(s: &Snapshot, since: u64, out: &mut Vec<Finding>) {
    let since_overwritten = |key: &str| -> bool {
        let start = s.first("RDPLOGSTART").map(|r| r.num(0)).unwrap_or(0);
        start > since + 60 && s.first(key).is_some()
    };
    let rows = |key: &str| -> Vec<(u64, String, String)> {
        s.all(key).map(|r| (r.num(0), r.fields().get(1).unwrap_or(&"").to_string(), String::new())).collect()
    };

    if let Some(r) = s.first("RDP") {
        if r.rest.starts_with("enabled") {
            if r.rest.contains("nla=0") {
                out.push(f(Level::Warn, "원격 데스크톱(RDP)이 켜져 있고 NLA(사전 인증)가 꺼져 있습니다", vec![]));
            } else {
                out.push(f(Level::Info, "원격 데스크톱(RDP) 켜짐 (NLA 사용)", vec![]));
            }
        }
    }
    let (conn_pub, conn_priv) = split_by_ip(rows("RDPCONN"));
    if !conn_pub.is_empty() {
        let n: u64 = conn_pub.iter().map(|r| r.0).sum();
        let mut d = top(&conn_pub, 5);
        d.push("RDP가 인터넷에 노출돼 있습니다. 공유기 포트포워딩에서 RDP(3389) 규칙을 확인하세요".into());
        out.push(f(Level::Alert, format!("공인 IP에서 RDP 접속 {n}건 ({}개 IP)", conn_pub.len()), d));
    }
    if !conn_priv.is_empty() {
        let n: u64 = conn_priv.iter().map(|r| r.0).sum();
        out.push(f(Level::Info, format!("내부망 RDP 접속 {n}건"), top(&conn_priv, 3)));
    }
    let (fail_pub, _) = split_by_ip(rows("RDPFAIL"));
    if !fail_pub.is_empty() {
        let n: u64 = fail_pub.iter().map(|r| r.0).sum();
        out.push(f(Level::Alert, format!("공인 IP의 RDP 로그인 실패 {n}건 (비밀번호 대입 공격)"), top(&fail_pub, 5)));
    }
    if since_overwritten("RDPCONN") {
        out.push(f(Level::Warn, "RDP 로그가 검사 기간 중에 덮어써졌습니다 (짧은 시간에 접속이 많았다는 뜻)", vec![]));
    }
    let logons: Vec<(u64, String, String)> = s
        .all("RDPLOGON")
        .map(|r| {
            let x = r.fields();
            (r.num(0), x.get(2).unwrap_or(&"").to_string(), x.get(1).unwrap_or(&"").to_string())
        })
        .collect();
    let (logon_pub, logon_priv) = split_by_ip(logons);
    if !logon_pub.is_empty() {
        out.push(f(Level::Warn, "외부 IP에서 RDP 로그인 성공, 본인 접속인지 확인하세요", top(&logon_pub, 5)));
    }
    if !logon_priv.is_empty() {
        out.push(f(Level::Info, "내부망 RDP 로그인", top(&logon_priv, 3)));
    }

    if let Some(r) = s.first("LOGONFAILTOTAL") {
        if r.num(0) > 0 {
            let (p, q) = split_by_ip(rows("LOGONFAIL"));
            let lvl = if p.is_empty() { Level::Warn } else { Level::Alert };
            let mut d = top(&p, 5);
            d.extend(top(&q, 3));
            out.push(f(lvl, format!("Windows 로그인 실패 {}건", r.num(0)), d));
        }
    } else if s.meta("securitylog") == Some("no-admin") {
        out.push(f(Level::Info, "Windows 로그인 실패 기록은 '관리자 권한으로 실행'해야 확인됩니다", vec![]));
    }
    if let Some(r) = s.first("SSHD") {
        if r.rest == "Running" {
            out.push(f(Level::Info, "OpenSSH 서버(sshd)가 실행 중입니다", vec![]));
        }
    }
    if let Some(r) = s.first("DEFENDER") {
        if r.rest.contains("realtime=False") || r.rest.contains("antivirus=False") {
            out.push(f(Level::Warn, "Microsoft Defender 실시간 보호가 꺼져 있습니다", vec![r.rest.clone()]));
        }
    }
    let fw_off: Vec<String> =
        s.all("FIREWALL").filter(|r| r.rest.ends_with("False")).map(|r| r.fields()[0].to_string()).collect();
    if !fw_off.is_empty() {
        out.push(f(Level::Warn, format!("Windows 방화벽이 꺼진 프로필: {}", fw_off.join(", ")), vec![]));
    }
}

fn category(cat: &str) -> (&'static str, Level) {
    match cat {
        "LISTEN" => ("열린 포트", Level::Warn),
        "SHELLUSER" => ("로그인 가능한 계정", Level::Alert),
        "USER" => ("로컬 계정", Level::Alert),
        "UID0" => ("UID 0 계정", Level::Alert),
        "ADMIN" => ("관리자 그룹 구성원", Level::Alert),
        "AUTHKEY" => ("SSH 허용 키(authorized_keys)", Level::Alert),
        "MTIME" => ("중요 설정 파일 수정", Level::Warn),
        "UNIT" => ("systemd 서비스/타이머", Level::Warn),
        "CRON" | "CRONFILE" => ("cron 예약 작업", Level::Warn),
        "AUTORUN" => ("자동 실행 항목(Run 키/시작프로그램)", Level::Warn),
        "TASK" => ("예약 작업(작업 스케줄러)", Level::Warn),
        "SERVICE" => ("자동 시작 서비스", Level::Warn),
        "RDP" => ("원격 데스크톱 설정", Level::Warn),
        "SSHD" => ("OpenSSH 서버 상태", Level::Warn),
        "FIREWALL" => ("방화벽 설정", Level::Warn),
        _ => ("기타", Level::Info),
    }
}

/// One finding per category of baseline changes.
pub fn changes_to_findings(changes: &[Change]) -> Vec<Finding> {
    let mut cats: Vec<&str> = changes.iter().map(|c| c.category.as_str()).collect();
    cats.dedup();
    cats.sort();
    cats.dedup();
    let mut out = Vec::new();
    for cat in cats {
        let (label, add_level) = category(cat);
        let mut level = Level::Info;
        let mut d = Vec::new();
        for c in changes.iter().filter(|c| c.category == cat) {
            // User-level systemd units change during normal deploys; report them softly.
            let item_level = if cat == "UNIT" && c.key.starts_with("user:") { Level::Info } else { add_level };
            match (&c.old, &c.new) {
                (None, Some(_)) => {
                    level = level.max(item_level);
                    d.push(format!("+ 새로 생김: {}", c.key));
                }
                (Some(o), Some(n)) => {
                    level = level.max(item_level.min(Level::Warn));
                    if cat == "MTIME" {
                        d.push(format!("~ 수정됨: {}", c.key));
                    } else {
                        d.push(format!("~ 바뀜: {}  ({o} → {n})", c.key));
                    }
                }
                (Some(_), None) => d.push(format!("- 없어짐: {}", c.key)),
                (None, None) => {}
            }
        }
        out.push(f(level, format!("기준선 대비 변경: {label}"), d));
    }
    out
}
