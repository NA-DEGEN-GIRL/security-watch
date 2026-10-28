//! One full (heavy) check of a target: run the probe, evaluate, diff the baseline.

use crate::baseline;
use crate::config::{Kind, Target};
use crate::eval::{self, Finding, Level};
use crate::probe::Snapshot;
use crate::runner;
use std::path::Path;

pub const DAY: u64 = 86_400;
const MAX_WINDOW: u64 = 7 * DAY;

pub struct ScanResult {
    pub since: u64,
    pub first_window: bool,
    pub hostname: Option<String>,
    /// Findings from logs and current state.
    pub findings: Vec<Finding>,
    /// Findings describing differences from the accepted baseline.
    pub changes: Vec<Finding>,
    pub items: Option<baseline::Items>,
    pub complete: bool,
}

impl ScanResult {
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }
}

pub fn baseline_path(root: &Path, t: &Target) -> std::path::PathBuf {
    root.join("state").join(format!("{}.baseline", t.state_name()))
}

fn lastrun_path(root: &Path, t: &Target) -> std::path::PathBuf {
    root.join("state").join(format!("{}.lastrun", t.state_name()))
}

fn watch_since_path(root: &Path) -> std::path::PathBuf {
    root.join("state").join("watch_since")
}

/// "Reference point": log findings never look earlier than this (e.g. the moment
/// the exposure was fixed), so already-handled past attacks stop showing up.
pub fn load_watch_since(root: &Path) -> u64 {
    baseline::load_last_run(&watch_since_path(root)).unwrap_or(0)
}

pub fn save_watch_since(root: &Path, epoch: u64) {
    let _ = std::fs::create_dir_all(root.join("state"));
    baseline::save_last_run(&watch_since_path(root), epoch);
}

/// `fixed_since`: dashboard mode checks a rolling window and leaves the
/// "since last run" bookkeeping of the one-shot report untouched.
pub fn check(target: &Target, root: &Path, now: u64, fixed_since: Option<u64>) -> ScanResult {
    let last = if fixed_since.is_none() { baseline::load_last_run(&lastrun_path(root, target)) } else { None };
    let first_window = fixed_since.is_none() && last.is_none();
    let since = fixed_since
        .unwrap_or_else(|| last.map(|t| t.max(now.saturating_sub(MAX_WINDOW))).unwrap_or(now - DAY))
        .max(load_watch_since(root).min(now));

    let mut r = ScanResult { since, first_window, hostname: None, findings: Vec::new(), changes: Vec::new(), items: None, complete: false };
    let output = match target.kind {
        Kind::Local => runner::probe_local(since),
        Kind::Remote { .. } => runner::probe_remote(&target.name, since),
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

    let snap = Snapshot::parse(&out.stdout);
    r.hostname = snap.meta("hostname").map(str::to_string);
    r.findings = eval::evaluate(target, &snap, since);
    r.complete = snap.complete;

    let items = baseline::items(&snap);
    let base_path = baseline_path(root, target);
    match baseline::load(&base_path) {
        Some(base) => r.changes = eval::changes_to_findings(&baseline::diff(&base, &items)),
        None if snap.complete => {
            let _ = std::fs::create_dir_all(root.join("state"));
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
    if snap.complete && fixed_since.is_none() {
        let _ = std::fs::create_dir_all(root.join("state"));
        baseline::save_last_run(&lastrun_path(root, target), now);
    }
    r.items = Some(items);
    r
}
