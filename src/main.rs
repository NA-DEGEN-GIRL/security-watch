//! security-watch: security monitor for this PC and your SSH servers.
//! Double-click: live dashboard window. `--once`: one text report and exit.
//! Read-only on every host.
#![windows_subsystem = "windows"]

mod ai;
mod app;
mod baseline;
mod config;
mod eval;
mod gui;
mod json;
mod live;
mod notify;
mod probe;
mod report;
mod rules;
mod runner;
mod scan;
mod ui;
mod usb;
mod win;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let root = config::resolve_root(&exe_dir);
    win::tie_children_to_process();

    // Developer aid: `--replay <windows|linux> <capture file>` prints what a saved
    // capture of a live script would raise (for tuning the rules against false alarms).
    if let Some(i) = args.iter().position(|a| a == "--replay") {
        win::ensure_console();
        let text = args.get(i + 2).and_then(|p| std::fs::read(p).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        for line in live::replay(args.get(i + 1).map(String::as_str) == Some("windows"), &text) {
            println!("{line}");
        }
        return;
    }
    // `--ai-prompt <text> [detail...]`: prints what "AI 설명" would send for a finding
    // on this PC (local facts collected, names masked), without sending anything.
    if let Some(i) = args.iter().position(|a| a == "--ai-prompt") {
        win::ensure_console();
        win::init_console();
        let opts = config::options(&root);
        let s = ai::Subject {
            source: "점검 결과",
            local: true,
            lan_only: true,
            level: eval::Level::Warn,
            text: args.get(i + 1).cloned().unwrap_or_default(),
            details: args.iter().skip(i + 2).cloned().collect(),
            private_names: std::env::var("COMPUTERNAME").map(|n| vec![(n, "<이PC>".to_string())]).unwrap_or_default(),
            title: "이 PC".into(),
        };
        println!("{}", ai::preview(&s, opts.ai_mask));
        return;
    }
    if has("--once") {
        let interactive = win::ensure_console();
        report::run_once(&root, interactive);
        return;
    }
    ui::run(root, has("--demo"));
}
