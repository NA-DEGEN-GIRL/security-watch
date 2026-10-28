//! Dashboard mode: native window, live feeds, periodic full scans.

use crate::app::{App, Conn, LiveState};
use crate::config::{self, Kind, Target};
use crate::eval::{Finding, Level};
use crate::gui::{self, Gui};
use crate::{live, scan, win};
use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn scanner(app: Arc<App>) {
    loop {
        if app.is_stopping() {
            return;
        }
        let now = crate::now_epoch();
        let due: Vec<Target> = {
            let mut g = app.lock();
            let force = std::mem::take(&mut g.force_scan);
            let period = g.scan_minutes * 60;
            g.hosts
                .iter_mut()
                .filter(|h| !h.scanning && (force || h.last_scan == 0 || now >= h.last_scan + period))
                .map(|h| {
                    h.scanning = true;
                    h.target.clone()
                })
                .collect()
        };
        for t in due {
            let app = Arc::clone(&app);
            thread::spawn(move || {
                let now = crate::now_epoch();
                let r = scan::check(&t, &app.root, now, Some(now - scan::DAY));
                app.lock().apply_scan(&t.name, r, now);
            });
        }
        thread::sleep(Duration::from_secs(1));
    }
}

pub fn run(root: PathBuf, demo: bool) {
    if !win::single_instance("Local\\security-watch-dashboard", gui::TITLE) {
        return; // the running window was brought to the front
    }
    let app = if demo {
        Arc::new(demo_app())
    } else {
        let (targets, _) = config::load(&root);
        let app = Arc::new(App::new(root, targets.clone()));
        for t in targets {
            live::start(&app, t);
        }
        let a = Arc::clone(&app);
        thread::spawn(move || scanner(a));
        app
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(gui::TITLE)
            .with_inner_size([1440.0, 940.0])
            .with_min_inner_size([960.0, 600.0])
            .with_icon(Arc::new(gui::icon(64))),
        ..Default::default()
    };
    let gui_app = Arc::clone(&app);
    if let Err(e) = eframe::run_native(gui::TITLE, options, Box::new(move |cc| Ok(Box::new(Gui::new(cc, gui_app))))) {
        win::message_box(gui::TITLE, &format!("창을 열지 못했습니다: {e}"));
    }
    app.shutdown();
}

/// Fake hosts and events for screenshots (`--demo`): documentation IPs only.
fn demo_app() -> App {
    let t = |name: &str, kind| Target { name: name.into(), kind };
    let app = App::new(
        PathBuf::from("."),
        vec![t("local", Kind::Local), t("web-01", Kind::Remote { lan_only: true }), t("nas-01", Kind::Remote { lan_only: true })],
    );
    let now = crate::now_epoch();
    let f = |level, text: &str, details: &[&str]| Finding { level, text: text.into(), details: details.iter().map(|s| s.to_string()).collect() };
    let mut g = app.lock();
    g.watch_since = now - 7200;
    for (i, h) in g.hosts.iter_mut().enumerate() {
        h.live = LiveState::Connected;
        h.last_scan = now - 90 + i as u64 * 10;
        h.scan_ok = true;
    }
    {
        let h = &mut g.hosts[0];
        h.hostname = Some("DESKTOP-DEMO".into());
        h.findings = vec![
            f(Level::Alert, "공인 IP에서 RDP 접속 214건 (9개 IP)", &["203.0.113.24  ×131", "198.51.100.7  ×41", "203.0.113.88  ×17", "… 외 6개", "RDP가 인터넷에 노출돼 있습니다. 공유기 포트포워딩에서 RDP(3389) 규칙을 확인하세요"]),
            f(Level::Alert, "공인 IP의 RDP 로그인 실패 52건 (비밀번호 대입 공격)", &["198.51.100.7  ×30", "203.0.113.24  ×22"]),
            f(Level::Info, "원격 데스크톱(RDP) 켜짐 (NLA 사용)", &[]),
        ];
        h.counters.insert("rdp_pub", 214);
        h.counters.insert("rdp_fail_pub", 52);
        h.counters.insert("login", 3);
    }
    {
        let h = &mut g.hosts[1];
        h.hostname = Some("web-01".into());
        h.findings = vec![f(Level::Info, "내부망 SSH 로그인 42건", &["admin (publickey) @ 192.168.1.20  ×42"])];
        h.changes = vec![f(Level::Warn, "기준선 대비 변경: 열린 포트", &["+ 새로 생김: tcp 0.0.0.0:8080 (python3)"])];
        h.counters.insert("login", 42);
        h.conns = vec![Conn { local: "192.168.1.10:22".into(), peer: "192.168.1.20:51522".into(), proc_name: "sshd".into(), public: false }];
    }
    {
        let h = &mut g.hosts[2];
        h.hostname = Some("nas-01".into());
        h.findings = vec![f(Level::Info, "내부망 SSH 로그인 5건", &["backup (publickey) @ 192.168.1.20  ×5"])];
        h.counters.insert("login", 5);
        h.conns = vec![Conn { local: "192.168.1.11:22".into(), peer: "192.168.1.20:50110".into(), proc_name: "sshd".into(), public: false }];
    }
    let mut ev = |host: &str, level, key: &str, text: &str, public, ago: u64, n: u64| {
        for k in 0..n {
            g.push_event(host, level, key.into(), text.into(), public, now - ago - (n - 1 - k) * 2, 600);
        }
    };
    ev("web-01", Level::Warn, "f", "SSH 인증 실패 ← 192.168.1.35 (계정: test)", false, 600, 2);
    ev("nas-01", Level::Info, "fw", "방화벽 차단 ← 198.51.100.200 (UDP/1900)", true, 300, 3);
    ev("web-01", Level::Info, "l", "SSH 로그인 admin ← 192.168.1.20 [publickey]", false, 12, 42);
    ev("local", Level::Alert, "rf", "RDP 로그인 실패 ← 198.51.100.7", true, 55, 30);
    ev("local", Level::Alert, "rc", "공인 IP의 RDP 접속 ← 203.0.113.24 (RDP가 인터넷에 노출됨)", true, 40, 131);
    drop(g);
    app
}
