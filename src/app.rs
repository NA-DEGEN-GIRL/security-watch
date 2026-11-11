//! Shared dashboard state: per-host scan results, live counters/connections, event feed.

use crate::baseline;
use crate::config::Target;
use crate::eval::{Finding, Level};
use crate::scan::{self, ScanResult};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const MAX_EVENTS: usize = 3000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Clone)]
pub struct Conn {
    pub local: String,
    pub peer: String,
    pub proc_name: String,
    pub public: bool,
}

/// A keyboard-type USB device as seen by the BadUSB guard.
#[derive(Clone)]
pub struct UsbDevice {
    pub label: String,
    /// Plugged in while the program was running.
    pub new: bool,
    /// Key presses since it was plugged in (only counted for new devices).
    pub keys: u64,
    pub secs: u64,
}

pub struct Event {
    pub id: u64,
    pub ts: u64,
    pub last_ts: u64,
    pub count: u64,
    pub host: String,
    pub level: Level,
    pub text: String,
    pub public: bool,
    key: String,
}

pub struct HostState {
    pub target: Target,
    pub hostname: Option<String>,
    pub live: LiveState,
    pub live_error: String,
    pub scanning: bool,
    pub last_scan: u64,
    pub scan_ok: bool,
    pub findings: Vec<Finding>,
    pub changes: Vec<Finding>,
    pub items: Option<baseline::Items>,
    pub counters: BTreeMap<&'static str, u64>,
    pub conns: Vec<Conn>,
    pub conns_ts: u64,
}

impl HostState {
    pub fn counter(&self, keys: &[&str]) -> u64 {
        keys.iter().map(|k| self.counters.get(k).copied().unwrap_or(0)).sum()
    }
}

pub struct Inner {
    pub hosts: Vec<HostState>,
    pub events: VecDeque<Event>,
    next_id: u64,
    pub scan_minutes: u64,
    pub force_scan: bool,
    /// Reference point for log-based findings (0 = none).
    pub watch_since: u64,
    pub usb: Vec<UsbDevice>,
    /// Dangerous events waiting to be shown as a notification.
    pub alarms: Vec<String>,
    pub alarm_on: bool,
}

pub struct App {
    pub inner: Mutex<Inner>,
    pub root: PathBuf,
    /// Lowercase texts from `ignore` config lines.
    pub ignore: Vec<String>,
    pub children: Mutex<Vec<Child>>,
    pub stopping: AtomicBool,
}

impl App {
    pub fn new(root: PathBuf, targets: Vec<Target>) -> App {
        let hosts = targets
            .into_iter()
            .map(|target| HostState {
                target,
                hostname: None,
                live: LiveState::Connecting,
                live_error: String::new(),
                scanning: false,
                last_scan: 0,
                scan_ok: false,
                findings: Vec::new(),
                changes: Vec::new(),
                items: None,
                counters: BTreeMap::new(),
                conns: Vec::new(),
                conns_ts: 0,
            })
            .collect();
        App {
            inner: Mutex::new(Inner {
                hosts,
                events: VecDeque::new(),
                next_id: 1,
                scan_minutes: 5,
                force_scan: false,
                watch_since: scan::load_watch_since(&root),
                usb: Vec::new(),
                alarms: Vec::new(),
                alarm_on: true,
            }),
            root,
            ignore: Vec::new(),
            children: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    pub fn track_child(&self, child: Child) -> u32 {
        let id = child.id();
        self.children.lock().unwrap_or_else(|e| e.into_inner()).push(child);
        id
    }

    pub fn forget_child(&self, pid: u32) {
        let mut v = self.children.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = v.iter().position(|c| c.id() == pid) {
            let mut c = v.remove(pos);
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        for c in self.children.lock().unwrap_or_else(|e| e.into_inner()).iter_mut() {
            let _ = c.kill();
        }
    }

    // ----- actions triggered from the window -----

    pub fn request_scan(&self) {
        self.lock().force_scan = true;
    }

    pub fn set_scan_minutes(&self, minutes: u64) {
        self.lock().scan_minutes = minutes.clamp(1, 1440);
    }

    pub fn set_alarm(&self, on: bool) {
        let mut g = self.lock();
        g.alarm_on = on;
        g.alarms.clear();
    }

    /// Hide log history older than now from findings and rescan.
    pub fn set_watch_since_now(&self) {
        let now = crate::now_epoch();
        scan::save_watch_since(&self.root, now);
        let mut g = self.lock();
        g.watch_since = now;
        g.force_scan = true;
        g.push_event("", Level::Info, String::new(), "기준 시점을 지금으로 바꿨습니다. 이전 로그 기록은 점검 결과에서 제외됩니다".into(), false, now, 0);
    }

    /// Save the host's current state as the new baseline.
    pub fn accept_baseline(&self, name: &str) -> Result<(), String> {
        let now = crate::now_epoch();
        let mut g = self.lock();
        let h = g.host_mut(name).ok_or("대상을 찾을 수 없습니다")?;
        let items = h.items.as_ref().ok_or("저장할 검사 결과가 없습니다")?;
        baseline::save(&scan::baseline_path(&self.root, &h.target), items).map_err(|e| format!("저장 실패: {e}"))?;
        h.changes.clear();
        let title = h.target.title();
        g.push_event(name, Level::Info, String::new(), format!("{title}: 현재 상태를 새 기준선으로 승인했습니다"), false, now, 0);
        Ok(())
    }
}

impl Inner {
    pub fn host_mut(&mut self, name: &str) -> Option<&mut HostState> {
        self.hosts.iter_mut().find(|h| h.target.name == name)
    }

    pub fn bump(&mut self, host: &str, counter: &'static str) {
        if let Some(h) = self.host_mut(host) {
            *h.counters.entry(counter).or_insert(0) += 1;
        }
    }

    /// Adds an event, or folds it into a recent one with the same key
    /// (repeated logins/attempts from the same source become one "×N" row).
    pub fn push_event(&mut self, host: &str, level: Level, key: String, text: String, public: bool, ts: u64, fold_secs: u64) {
        if fold_secs > 0 {
            if let Some(e) = self
                .events
                .iter_mut()
                .rev()
                .take(500)
                .find(|e| e.host == host && e.key == key && ts.saturating_sub(e.last_ts) <= fold_secs)
            {
                e.count += 1;
                e.last_ts = e.last_ts.max(ts);
                let raised = (level > e.level && level == Level::Alert).then(|| e.text.clone());
                e.level = e.level.max(level);
                if let Some(text) = raised {
                    self.alarm(host, &text, ts);
                }
                return;
            }
        }
        if level == Level::Alert {
            self.alarm(host, &text, ts);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.events.push_back(Event { id, ts, last_ts: ts, count: 1, host: host.to_string(), level, text, public, key });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    /// Queues a notification for something dangerous happening now (old log lines stay quiet).
    fn alarm(&mut self, host: &str, text: &str, ts: u64) {
        if !self.alarm_on || self.alarms.len() >= 50 || crate::now_epoch().saturating_sub(ts) > 300 {
            return;
        }
        let title = self.hosts.iter().find(|h| h.target.name == host).map(|h| h.target.title());
        self.alarms.push(match title {
            Some(t) => format!("[{t}] {text}"),
            None => text.to_string(),
        });
    }

    pub fn apply_scan(&mut self, name: &str, r: ScanResult, now: u64) {
        // Dangerous findings that were not there after the previous scan raise the alarm
        // (compared without digits, so a growing count is not "new").
        fn alerts(h: &HostState) -> Vec<(String, String)> {
            h.findings
                .iter()
                .chain(&h.changes)
                .filter(|f| f.level == Level::Alert && !f.text.starts_with("검사 실패"))
                .map(|f| (f.text.chars().filter(|c| !c.is_ascii_digit()).collect(), f.text.clone()))
                .collect()
        }
        let mut fresh = Vec::new();
        if let Some(h) = self.host_mut(name) {
            let before: HashSet<String> = alerts(h).into_iter().map(|a| a.0).collect();
            h.scanning = false;
            h.last_scan = now;
            h.scan_ok = r.complete;
            if r.hostname.is_some() {
                h.hostname = r.hostname;
            }
            h.findings = r.findings;
            h.changes = r.changes;
            if r.items.is_some() {
                h.items = r.items;
            }
            fresh = alerts(h).into_iter().filter(|a| !before.contains(&a.0)).map(|a| a.1).collect();
        }
        for text in fresh {
            self.alarm(name, &text, now);
        }
    }

    /// Worst of scan findings and live events in the last hour (Info counts as OK).
    pub fn host_level(&self, h: &HostState, now: u64) -> Level {
        let recent = now.saturating_sub(3600);
        let live = self.events.iter().filter(|e| e.host == h.target.name && e.last_ts >= recent).map(|e| e.level).max().unwrap_or(Level::Ok);
        let scan = h.findings.iter().chain(&h.changes).map(|f| f.level).max().unwrap_or(Level::Ok);
        match live.max(scan) {
            Level::Info => Level::Ok,
            l => l,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Kind;

    #[test]
    fn repeated_events_are_folded() {
        let t = Target { name: "h".into(), kind: Kind::Local };
        let app = App::new(PathBuf::from("."), vec![t]);
        let mut g = app.lock();
        g.push_event("h", Level::Info, "k".into(), "login".into(), false, 100, 600);
        g.push_event("h", Level::Warn, "k".into(), "login".into(), false, 200, 600);
        g.push_event("h", Level::Info, "k".into(), "login".into(), false, 2000, 600);
        assert_eq!(g.events.len(), 2);
        assert_eq!(g.events[0].count, 2);
        assert_eq!(g.events[0].level, Level::Warn);
    }

    #[test]
    fn only_fresh_alerts_raise_the_alarm() {
        let t = Target { name: "h".into(), kind: Kind::Local };
        let app = App::new(PathBuf::from("."), vec![t]);
        let now = crate::now_epoch();
        let mut g = app.lock();
        g.push_event("h", Level::Alert, "old".into(), "old log line".into(), false, now - 4000, 600);
        g.push_event("h", Level::Warn, "k".into(), "warn".into(), false, now, 600);
        assert!(g.alarms.is_empty());
        g.push_event("h", Level::Alert, "k".into(), "warn".into(), false, now, 600); // escalates
        g.push_event("h", Level::Alert, "k".into(), "warn".into(), false, now, 600); // folded
        g.push_event("h", Level::Alert, "k2".into(), "bad".into(), false, now, 600);
        assert_eq!(g.alarms, vec!["[이 PC] warn".to_string(), "[이 PC] bad".to_string()]);
        g.alarm_on = false;
        g.push_event("h", Level::Alert, "k3".into(), "muted".into(), false, now, 600);
        assert_eq!(g.alarms.len(), 2);
    }
}
