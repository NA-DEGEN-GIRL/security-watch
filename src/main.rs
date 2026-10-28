//! security-watch: double-click security check for this PC and your SSH servers.
//! Looks for intrusion traces (exposed RDP/SSH, logins from public IPs, new keys,
//! accounts, ports, autoruns...) and writes a report. Read-only on every host.

mod baseline;
mod config;
mod eval;
mod probe;
mod runner;
mod win;

use config::{Kind, Target};
use eval::{Finding, Level};
use probe::Snapshot;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY: u64 = 86_400;
const MAX_WINDOW: u64 = 7 * DAY;

struct HostResult {
    target: Target,
    since: u64,
    first_window: bool,
    hostname: Option<String>,
    findings: Vec<Finding>,
    current: Option<baseline::Items>,
    has_baseline: bool,
    changed: bool,
    ok: bool,
}

/// Console + report-file writer. Colors only go to the console.
struct Out {
    color: bool,
    report: String,
}

impl Out {
    fn line(&mut self, color: &str, text: &str) {
        if self.color && !color.is_empty() {
            println!("{color}{text}\x1b[0m");
        } else {
            println!("{text}");
        }
        self.report.push_str(text);
        self.report.push_str("\r\n");
    }
}

fn level_color(l: Level) -> &'static str {
    match l {
        Level::Alert => "\x1b[1;91m",
        Level::Warn => "\x1b[1;93m",
        Level::Info => "\x1b[96m",
        Level::Ok => "\x1b[92m",
    }
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn human_duration(secs: u64) -> String {
    let (d, h, m) = (secs / DAY, secs % DAY / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}분"),
        (0, _) => format!("{h}시간 {m}분"),
        (_, 0) => format!("{d}일"),
        _ => format!("{d}일 {h}시간"),
    }
}

fn check(target: Target, root: &Path, now: u64) -> HostResult {
    let state = root.join("state");
    let last = baseline::load_last_run(&state.join(format!("{}.lastrun", target.state_name())));
    let first_window = last.is_none();
    let since = last.map(|t| t.max(now.saturating_sub(MAX_WINDOW))).unwrap_or(now - DAY);

    let output = match target.kind {
        Kind::Local => runner::probe_local(since),
        Kind::Remote { .. } => runner::probe_remote(&target.name, since),
    };
    let mut r = HostResult {
        target,
        since,
        first_window,
        hostname: None,
        findings: Vec::new(),
        current: None,
        has_baseline: false,
        changed: false,
        ok: false,
    };
    let out = match output {
        Ok(o) if !o.stdout.trim().is_empty() => o,
        Ok(o) => {
            let err = o.stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("응답 없음").trim().to_string();
            r.findings.push(Finding { level: Level::Alert, text: "검사 실패: 접속하거나 실행하지 못했습니다".into(), details: vec![err] });
            return r;
        }
        Err(e) => {
            r.findings.push(Finding { level: Level::Alert, text: "검사 실패".into(), details: vec![e] });
            return r;
        }
    };
    let _ = out.success;

    let snap = Snapshot::parse(&out.stdout);
    r.hostname = snap.meta("hostname").map(str::to_string);
    r.findings = eval::evaluate(&r.target, &snap, since);
    r.ok = snap.complete;

    let items = baseline::items(&snap);
    let base_path = state.join(format!("{}.baseline", r.target.state_name()));
    match baseline::load(&base_path) {
        Some(base) => {
            r.has_baseline = true;
            let changes = baseline::diff(&base, &items);
            r.changed = !changes.is_empty();
            r.findings.extend(eval::changes_to_findings(&changes));
        }
        None if snap.complete => {
            let _ = std::fs::create_dir_all(&state);
            if baseline::save(&base_path, &items).is_ok() {
                r.findings.push(Finding {
                    level: Level::Info,
                    text: format!("첫 실행이라 기준선을 저장했습니다 (항목 {}개). 다음부터 이 상태와 비교합니다", items.len()),
                    details: vec![],
                });
            }
        }
        None => {}
    }
    if snap.complete {
        baseline::save_last_run(&state.join(format!("{}.lastrun", r.target.state_name())), now);
    }
    r.current = Some(items);
    r
}

fn main() {
    let color = win::init_console();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let root = config::resolve_root(&exe_dir);
    let (targets, created) = config::load(&root);
    let mut o = Out { color, report: String::new() };
    let started = win::now_display();

    o.line("\x1b[1m", &format!("══════ security-watch · {started} ══════"));
    if created {
        o.line("\x1b[93m", &format!("설정 파일을 새로 만들었습니다: {}", root.join(config::CONFIG_FILE).display()));
        o.line("", "  원격 서버를 검사하려면 이 파일에 'host <ssh별칭>' 줄을 추가하세요.");
    }
    if targets.is_empty() {
        o.line("\x1b[93m", "검사할 대상이 없습니다. 설정 파일을 확인하세요.");
        pause();
        return;
    }
    let names: Vec<String> = targets.iter().map(Target::title).collect();
    println!("점검 중: {} (보통 10~40초) ...", names.join(", "));

    let now = now_epoch();
    let (tx, rx) = mpsc::channel();
    for (i, t) in targets.iter().cloned().enumerate() {
        let tx = tx.clone();
        let root = root.clone();
        thread::spawn(move || {
            let _ = tx.send((i, check(t, &root, now)));
        });
    }
    drop(tx);
    let mut results: Vec<(usize, HostResult)> = rx.iter().collect();
    results.sort_by_key(|(i, _)| *i);

    let count = |l: Level| results.iter().flat_map(|(_, r)| &r.findings).filter(|f| f.level == l).count();
    let worst = results.iter().flat_map(|(_, r)| &r.findings).map(|f| f.level).max().unwrap_or(Level::Ok);
    let verdict = match worst {
        Level::Alert => "확인이 필요한 위험 항목이 있습니다",
        Level::Warn => "주의할 항목이 있습니다",
        _ => "이상 징후가 발견되지 않았습니다",
    };
    o.line(level_color(worst), &format!(
        "결과: {verdict}  (위험 {} · 주의 {} · 정보 {})",
        count(Level::Alert),
        count(Level::Warn),
        count(Level::Info)
    ));

    for (_, r) in &mut results {
        r.findings.sort_by(|a, b| b.level.cmp(&a.level));
        let host_worst = r.findings.iter().map(|f| f.level).max().unwrap_or(Level::Ok);
        let shown_worst = if host_worst <= Level::Info { Level::Ok } else { host_worst };
        o.line("", "");
        let name = match &r.hostname {
            Some(h) if *h != r.target.title() => format!("{} ({h})", r.target.title()),
            _ => r.target.title(),
        };
        o.line(level_color(shown_worst), &format!("■ {name}  [{}]", shown_worst.label()));
        let window = human_duration(now.saturating_sub(r.since));
        let scope = if r.first_window { format!("첫 실행: 최근 {window}") } else { format!("마지막 실행 이후 {window}") };
        o.line("\x1b[90m", &format!("  검사 범위: {scope}"));
        if !r.findings.iter().any(|f| f.level >= Level::Warn) {
            o.line(level_color(Level::Ok), "  [정상] 주의할 이상 징후 없음");
        }
        for f in &r.findings {
            o.line(level_color(f.level), &format!("  [{}] {}", f.level.label(), f.text));
            for d in &f.details {
                o.line("", &format!("         · {d}"));
            }
        }
    }

    let reports = root.join("reports");
    let _ = std::fs::create_dir_all(&reports);
    let report_path = reports.join(format!("report-{}.txt", win::now_file_stamp()));

    let changed: Vec<&HostResult> = results.iter().map(|(_, r)| r).filter(|r| r.changed && r.ok).collect();
    o.line("", "");
    if !changed.is_empty() {
        let list: Vec<String> = changed.iter().map(|r| r.target.title()).collect();
        print!("기준선과 달라진 항목이 있습니다 ({}). 확인한 변경을 새 기준선으로 저장할까요? [y/N] ", list.join(", "));
        let _ = io::stdout().flush();
        let mut answer = String::new();
        let _ = io::stdin().lock().read_line(&mut answer);
        if answer.trim().eq_ignore_ascii_case("y") {
            for r in &changed {
                if let Some(items) = &r.current {
                    let p = root.join("state").join(format!("{}.baseline", r.target.state_name()));
                    let _ = baseline::save(&p, items);
                }
            }
            o.line("\x1b[92m", "새 기준선을 저장했습니다.");
        } else {
            o.line("", "기준선은 그대로 둡니다. 다음 실행에서도 같은 변경이 다시 표시됩니다.");
        }
    }

    match std::fs::write(&report_path, o.report.as_bytes()) {
        Ok(_) => println!("\n리포트 저장: {}", report_path.display()),
        Err(e) => println!("\n리포트 저장 실패: {e}"),
    }
    pause();
}

fn pause() {
    print!("\nEnter 키를 누르면 종료합니다...");
    let _ = io::stdout().flush();
    let _ = io::stdin().lock().read_line(&mut String::new());
}
