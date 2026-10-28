//! `--once`: the original console report (one scan, text report file, optional baseline accept).

use crate::baseline;
use crate::config::{self, Target};
use crate::eval::Level;
use crate::scan::{self, ScanResult, DAY};
use crate::win;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

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

pub fn human_duration(secs: u64) -> String {
    let (d, h, m) = (secs / DAY, secs % DAY / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}분"),
        (0, _) => format!("{h}시간 {m}분"),
        (_, 0) => format!("{d}일"),
        _ => format!("{d}일 {h}시간"),
    }
}

pub fn run_once(root: &Path, interactive: bool) {
    let color = win::init_console();
    let (targets, created) = config::load(root);
    let mut o = Out { color, report: String::new() };
    let pause = |interactive: bool| {
        if interactive {
            print!("\nEnter 키를 누르면 종료합니다...");
            let _ = io::stdout().flush();
            let _ = io::stdin().lock().read_line(&mut String::new());
        }
    };

    o.line("\x1b[1m", &format!("══════ security-watch · {} ══════", win::now_display()));
    if created {
        o.line("\x1b[93m", &format!("설정 파일을 새로 만들었습니다: {}", root.join(config::CONFIG_FILE).display()));
    }
    if targets.is_empty() {
        o.line("\x1b[93m", "검사할 대상이 없습니다. 설정 파일을 확인하세요.");
        pause(interactive);
        return;
    }
    let names: Vec<String> = targets.iter().map(Target::title).collect();
    println!("점검 중: {} ...", names.join(", "));

    let now = crate::now_epoch();
    let (tx, rx) = mpsc::channel();
    for (i, t) in targets.iter().cloned().enumerate() {
        let (tx, root) = (tx.clone(), root.to_path_buf());
        thread::spawn(move || {
            let r = scan::check(&t, &root, now, None);
            let _ = tx.send((i, t, r));
        });
    }
    drop(tx);
    let mut results: Vec<(usize, Target, ScanResult)> = rx.iter().collect();
    results.sort_by_key(|(i, ..)| *i);

    let all = || results.iter().flat_map(|(_, _, r)| r.findings.iter().chain(&r.changes));
    let count = |l: Level| all().filter(|f| f.level == l).count();
    let worst = all().map(|f| f.level).max().unwrap_or(Level::Ok);
    let verdict = match worst {
        Level::Alert => "확인이 필요한 위험 항목이 있습니다",
        Level::Warn => "주의할 항목이 있습니다",
        _ => "이상 징후가 발견되지 않았습니다",
    };
    o.line(level_color(worst), &format!("결과: {verdict}  (위험 {} · 주의 {} · 정보 {})", count(Level::Alert), count(Level::Warn), count(Level::Info)));

    for (_, t, r) in &results {
        let mut fs: Vec<_> = r.findings.iter().chain(&r.changes).collect();
        fs.sort_by(|a, b| b.level.cmp(&a.level));
        let worst = fs.iter().map(|f| f.level).max().unwrap_or(Level::Ok);
        let shown = if worst <= Level::Info { Level::Ok } else { worst };
        o.line("", "");
        let name = match &r.hostname {
            Some(h) if *h != t.title() => format!("{} ({h})", t.title()),
            _ => t.title(),
        };
        o.line(level_color(shown), &format!("■ {name}  [{}]", shown.label()));
        let window = human_duration(now.saturating_sub(r.since));
        let scope = if r.first_window { format!("첫 실행: 최근 {window}") } else { format!("마지막 실행 이후 {window}") };
        o.line("\x1b[90m", &format!("  검사 범위: {scope}"));
        if !fs.iter().any(|f| f.level >= Level::Warn) {
            o.line(level_color(Level::Ok), "  [정상] 주의할 이상 징후 없음");
        }
        for f in fs {
            o.line(level_color(f.level), &format!("  [{}] {}", f.level.label(), f.text));
            for d in &f.details {
                o.line("", &format!("         · {d}"));
            }
        }
    }

    let changed: Vec<&(usize, Target, ScanResult)> = results.iter().filter(|(_, _, r)| r.has_changes() && r.complete).collect();
    o.line("", "");
    if !changed.is_empty() && interactive {
        let list: Vec<String> = changed.iter().map(|(_, t, _)| t.title()).collect();
        print!("기준선과 달라진 항목이 있습니다 ({}). 확인한 변경을 새 기준선으로 저장할까요? [y/N] ", list.join(", "));
        let _ = io::stdout().flush();
        let mut answer = String::new();
        let _ = io::stdin().lock().read_line(&mut answer);
        if answer.trim().eq_ignore_ascii_case("y") {
            for (_, t, r) in &changed {
                if let Some(items) = &r.items {
                    let _ = baseline::save(&scan::baseline_path(root, t), items);
                }
            }
            o.line("\x1b[92m", "새 기준선을 저장했습니다.");
        } else {
            o.line("", "기준선은 그대로 둡니다. 다음 실행에서도 같은 변경이 다시 표시됩니다.");
        }
    }

    let reports = root.join("reports");
    let _ = std::fs::create_dir_all(&reports);
    let path = reports.join(format!("report-{}.txt", win::now_file_stamp()));
    match std::fs::write(&path, o.report.as_bytes()) {
        Ok(_) => println!("\n리포트 저장: {}", path.display()),
        Err(e) => println!("\n리포트 저장 실패: {e}"),
    }
    pause(interactive);
}
