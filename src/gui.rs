//! Native dashboard window (egui). Reads the shared `App` state every frame and
//! turns button clicks into `App` actions.

use crate::ai::{self, Ai, KeySource, Subject, View};
use crate::app::{App, HostState, Inner, LiveState};
use crate::config::Kind;
use crate::eval::{Finding, Level};
use crate::win;
use eframe::egui::{self, Align, Color32, CornerRadius, FontFamily, Layout, Margin, RichText, Sense, Stroke};
use std::sync::Arc;
use std::time::Duration;

pub const TITLE: &str = "security-watch";

enum Confirm {
    WatchSince,
    Accept(String),
}

enum Action {
    Select(String),
    Scan,
    Minutes(u64),
    Alarm(bool),
    Ask(Confirm),
    Explain(Subject),
}

pub struct Gui {
    app: Arc<App>,
    ai: Arc<Ai>,
    selected: Option<String>,
    show_all_events: bool,
    confirm: Option<Confirm>,
    message: Option<String>,
    offset: i64,
    /// Row shown in the "AI 설명" window.
    ai_open: Option<Subject>,
    key_input: String,
    key_message: Option<String>,
    editing_key: bool,
    show_sent: bool,
}

/// Names the AI request must not carry: server aliases and host names.
fn private_names(g: &Inner) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for h in &g.hosts {
        let local = matches!(h.target.kind, Kind::Local);
        if !local {
            v.push((h.target.name.clone(), "<서버>".to_string()));
        }
        if let Some(hn) = &h.hostname {
            v.push((hn.clone(), if local { "<이PC>" } else { "<서버>" }.to_string()));
        }
    }
    v
}

fn subject(g: &Inner, h: &HostState, source: &'static str, level: Level, text: &str, details: &[String]) -> Subject {
    Subject {
        source,
        local: matches!(h.target.kind, Kind::Local),
        lan_only: matches!(h.target.kind, Kind::Remote { lan_only: true }),
        level,
        text: text.to_string(),
        details: details.to_vec(),
        private_names: private_names(g),
        title: h.target.title(),
    }
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n).collect::<String>() + "…" }
}

struct Palette {
    ok: Color32,
    info: Color32,
    warn: Color32,
    alert: Color32,
    panel: Color32,
    tile: Color32,
    line: Color32,
    muted: Color32,
}

fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            ok: Color32::from_rgb(63, 185, 80),
            info: Color32::from_rgb(88, 166, 255),
            warn: Color32::from_rgb(210, 153, 34),
            alert: Color32::from_rgb(248, 81, 73),
            panel: Color32::from_rgb(21, 27, 35),
            tile: Color32::from_rgb(27, 34, 44),
            line: Color32::from_rgb(42, 51, 64),
            muted: Color32::from_rgb(139, 151, 166),
        }
    } else {
        Palette {
            ok: Color32::from_rgb(26, 127, 55),
            info: Color32::from_rgb(9, 105, 218),
            warn: Color32::from_rgb(154, 103, 0),
            alert: Color32::from_rgb(207, 34, 46),
            panel: Color32::from_rgb(255, 255, 255),
            tile: Color32::from_rgb(240, 243, 247),
            line: Color32::from_rgb(216, 222, 230),
            muted: Color32::from_rgb(93, 104, 117),
        }
    }
}

impl Palette {
    fn level(&self, l: Level) -> Color32 {
        match l {
            Level::Ok => self.ok,
            Level::Info => self.info,
            Level::Warn => self.warn,
            Level::Alert => self.alert,
        }
    }
}

fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

fn badge(ui: &mut egui::Ui, p: &Palette, l: Level, text: &str) {
    egui::Frame::new()
        .fill(tint(p.level(l), 40))
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::symmetric(8, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(p.level(l)).strong().size(12.5));
        });
}

fn ago(ts: u64, now: u64) -> String {
    let s = now.saturating_sub(ts);
    match s {
        0..=59 => format!("{s}초 전"),
        60..=3599 => format!("{}분 전", s / 60),
        _ => format!("{}시간 전", s / 3600),
    }
}

fn until(ts: u64, now: u64) -> String {
    let s = ts.saturating_sub(now);
    if s < 60 { format!("{s}초 후") } else { format!("{}분 {}초 후", s / 60, s % 60) }
}

impl Gui {
    pub fn new(cc: &eframe::CreationContext<'_>, app: Arc<App>, ai: Arc<Ai>) -> Gui {
        setup_fonts(&cc.egui_ctx);
        cc.egui_ctx.options_mut(|o| o.theme_preference = egui::ThemePreference::System);
        Gui {
            app,
            ai,
            selected: None,
            show_all_events: false,
            confirm: None,
            message: None,
            offset: win::local_offset(),
            ai_open: None,
            key_input: String::new(),
            key_message: None,
            editing_key: false,
            show_sent: false,
        }
    }

    /// A row's AI state for the inline line: None = no button.
    fn ai_row(&self, s: &Subject) -> Option<Option<ai::Answer>> {
        self.ai.settings.enabled.then(|| self.ai.answer(&s.key()))
    }

    fn open_explain(&mut self, s: Subject, ctx: &egui::Context) {
        self.show_sent = false;
        self.key_message = None;
        let key = s.key();
        if self.ai.key_source() != KeySource::Missing && matches!(self.ai.view(&key), View::None) {
            self.ai.prepare(s.clone(), ctx.clone());
        }
        self.ai_open = Some(s);
    }

    fn top_bar(&self, ui: &mut egui::Ui, g: &Inner, p: &Palette, now: u64, actions: &mut Vec<Action>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("security-watch").strong().size(17.0));
            let worst = g.hosts.iter().map(|h| g.host_level(h, now)).max().unwrap_or(Level::Ok);
            let text = match worst {
                Level::Alert => "위험 항목 있음",
                Level::Warn => "주의 항목 있음",
                _ => "전체 정상",
            };
            badge(ui, p, worst, text);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mut alarm = g.alarm_on;
                if ui.checkbox(&mut alarm, "알림").on_hover_text("위험 이벤트가 생기면 트레이 알림과 소리로 알려 줍니다").changed() {
                    actions.push(Action::Alarm(alarm));
                }
                ui.separator();
                let scanning = g.hosts.iter().any(|h| h.scanning);
                if ui.add_enabled(!scanning, egui::Button::new(RichText::new("지금 전체 검사").strong())).clicked() {
                    actions.push(Action::Scan);
                }
                let mut minutes = g.scan_minutes;
                egui::ComboBox::from_id_salt("every")
                    .selected_text(format!("{minutes}분마다"))
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for m in [1, 5, 15, 30, 60] {
                            ui.selectable_value(&mut minutes, m, format!("{m}분마다"));
                        }
                    });
                if minutes != g.scan_minutes {
                    actions.push(Action::Minutes(minutes));
                }
                ui.label(RichText::new("전체 검사").color(p.muted));
                ui.separator();
                if ui
                    .button("기준 시점을 지금으로")
                    .on_hover_text("이 시각 이전의 로그 기록(이미 조치한 과거 공격 등)은 점검 결과에서 제외합니다")
                    .clicked()
                {
                    actions.push(Action::Ask(Confirm::WatchSince));
                }
                let since = if g.watch_since > 0 {
                    format!("기준 시점 {} 이후", win::fmt_clock(g.watch_since, now, self.offset))
                } else {
                    "기준 시점 없음 (최근 24시간)".to_string()
                };
                ui.label(RichText::new(since).color(p.muted));
                ui.separator();
                let last = g.hosts.iter().map(|h| h.last_scan).max().unwrap_or(0);
                let next = g.hosts.iter().filter(|h| h.last_scan > 0).map(|h| h.last_scan).min().map(|t| t + g.scan_minutes * 60);
                let meta = if scanning {
                    "전체 검사 중...".to_string()
                } else if last > 0 {
                    format!("마지막 전체 검사 {} · 다음 {}", ago(last, now), next.map(|n| until(n, now)).unwrap_or_default())
                } else {
                    "첫 검사 준비 중".to_string()
                };
                if scanning {
                    ui.spinner();
                }
                ui.label(RichText::new(meta).color(p.muted));
            });
        });
    }

    fn host_card(&self, ui: &mut egui::Ui, g: &Inner, h: &HostState, p: &Palette, now: u64, actions: &mut Vec<Action>) {
        let level = g.host_level(h, now);
        let selected = self.selected.as_deref() == Some(h.target.name.as_str());
        let stroke = if selected { Stroke::new(2.0, p.info) } else { Stroke::new(1.0, p.line) };
        let resp = egui::Frame::new()
            .fill(p.panel)
            .stroke(stroke)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                // status strip
                let r = ui.max_rect();
                ui.painter().hline(r.x_range(), r.top() - 12.0, Stroke::new(3.0, p.level(level)));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(h.target.title()).strong().size(16.0));
                    if let Some(hn) = h.hostname.as_deref().filter(|n| *n != h.target.title()) {
                        ui.label(RichText::new(hn).color(p.muted));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let shown = if level <= Level::Info { Level::Ok } else { level };
                        badge(ui, p, shown, shown.label());
                    });
                });
                let (dot, text) = match h.live {
                    LiveState::Connected => (p.ok, "실시간 수신 중"),
                    LiveState::Connecting => (p.warn, "연결 중..."),
                    LiveState::Disconnected => (p.alert, "실시간 연결 끊김"),
                };
                let kind = match h.target.kind {
                    Kind::Local => " · 이 PC",
                    Kind::Remote { lan_only: true } => " · 내부망 서버",
                    Kind::Remote { lan_only: false } => " · 공개 서버",
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(dot).size(11.0));
                    ui.label(RichText::new(format!("{text}{kind}")).color(p.muted).size(12.5));
                });
                if h.live == LiveState::Disconnected && !h.live_error.is_empty() {
                    ui.label(RichText::new(&h.live_error).color(p.alert).size(12.0));
                }
                ui.add_space(6.0);
                let ext = h.counter(&["ssh_fail_pub", "rdp_pub", "rdp_fail_pub", "conn_pub", "login_pub"]);
                let fails = h.counter(&["ssh_fail", "rdp_fail", "logon_fail", "sudo_fail"]);
                let logins = h.counter(&["login", "login_pub"]);
                let pub_conns = h.conns.iter().filter(|c| c.public).count();
                ui.columns(4, |c| {
                    stat(&mut c[0], p, ext.to_string(), "외부 접근", ext > 0);
                    stat(&mut c[1], p, fails.to_string(), "인증 실패", fails > 0);
                    stat(&mut c[2], p, logins.to_string(), "로그인", false);
                    let conns = if pub_conns > 0 { format!("{} (외부 {pub_conns})", h.conns.len()) } else { h.conns.len().to_string() };
                    stat(&mut c[3], p, conns, "현재 연결", pub_conns > 0);
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if h.scanning {
                        ui.spinner();
                        ui.label(RichText::new("검사 중").color(p.muted).size(12.0));
                    } else if h.last_scan > 0 {
                        ui.label(RichText::new(format!("전체 검사 {}", ago(h.last_scan, now))).color(p.muted).size(12.0));
                    } else {
                        ui.label(RichText::new("검사 대기").color(p.muted).size(12.0));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new("이번 실행 중 집계").color(p.muted).size(12.0));
                    });
                });
            })
            .response
            .interact(Sense::click())
            .on_hover_text("클릭하면 이 대상만 보기");
        if resp.clicked() {
            actions.push(Action::Select(h.target.name.clone()));
        }
    }

    fn findings_panel(&self, ui: &mut egui::Ui, g: &Inner, p: &Palette, now: u64, actions: &mut Vec<Action>) {
        panel(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("점검 결과").strong().size(15.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let scope = if g.watch_since > 0 && now.saturating_sub(g.watch_since) < 86_400 { "기준 시점 이후" } else { "최근 24시간" };
                    let hint = if self.selected.is_some() { "선택한 대상만 표시 중".to_string() } else { format!("{scope} 로그 + 기준선 비교") };
                    ui.label(RichText::new(hint).color(p.muted).size(12.5));
                });
            });
            ui.add_space(4.0);
            egui::ScrollArea::vertical().id_salt("findings").max_height(440.0).auto_shrink([false, true]).show(ui, |ui| {
                for (i, h) in g.hosts.iter().filter(|h| self.selected.as_ref().is_none_or(|s| *s == h.target.name)).enumerate() {
                    if i > 0 {
                        ui.separator();
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(h.target.title()).strong());
                        if let Some(hn) = h.hostname.as_deref().filter(|n| *n != h.target.title()) {
                            ui.label(RichText::new(hn).color(p.muted));
                        }
                        if h.last_scan > 0 {
                            ui.label(RichText::new(format!("· 검사 {}", win::fmt_clock(h.last_scan, now, self.offset))).color(p.muted).size(12.5));
                        }
                        if !h.changes.is_empty() {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button("변경 사항 승인").on_hover_text("지금 상태를 정상으로 인정하고 이후 비교 기준으로 저장").clicked() {
                                    actions.push(Action::Ask(Confirm::Accept(h.target.name.clone())));
                                }
                            });
                        }
                    });
                    if h.last_scan == 0 {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new("첫 전체 검사 중...").color(p.muted));
                        });
                        continue;
                    }
                    let mut all: Vec<&Finding> = h.findings.iter().chain(&h.changes).collect();
                    all.sort_by(|a, b| b.level.cmp(&a.level));
                    if !all.iter().any(|f| f.level >= Level::Warn) {
                        finding_row(ui, p, Level::Ok, "주의할 이상 징후 없음", &[], None);
                    }
                    for f in all {
                        let s = subject(g, h, "점검 결과", f.level, &f.text, &f.details);
                        if finding_row(ui, p, f.level, &f.text, &f.details, self.ai_row(&s)) {
                            actions.push(Action::Explain(s));
                        }
                    }
                }
            });
        });
    }

    fn events_panel(&mut self, ui: &mut egui::Ui, g: &Inner, p: &Palette, now: u64, actions: &mut Vec<Action>) {
        panel(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("실시간 이벤트").strong().size(15.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.selectable_value(&mut self.show_all_events, true, "전체");
                    ui.selectable_value(&mut self.show_all_events, false, "중요만");
                });
            });
            ui.add_space(4.0);
            let mut list: Vec<_> = g
                .events
                .iter()
                .filter(|e| self.selected.as_ref().is_none_or(|s| *s == e.host))
                .filter(|e| self.show_all_events || e.level >= Level::Warn || e.public)
                .collect();
            list.sort_by(|a, b| b.last_ts.cmp(&a.last_ts).then(b.id.cmp(&a.id)));
            egui::ScrollArea::vertical().id_salt("events").max_height(440.0).auto_shrink([false, true]).show(ui, |ui| {
                if list.is_empty() {
                    let t = if self.show_all_events { "아직 이벤트가 없습니다." } else { "중요 이벤트가 없습니다. \"전체\"를 누르면 일반 로그인 등도 보입니다." };
                    ui.label(RichText::new(t).color(p.muted));
                }
                for e in list.into_iter().take(300) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(win::fmt_clock(e.last_ts, now, self.offset)).color(p.muted).monospace().size(12.0));
                        badge(ui, p, e.level, e.level.label());
                        let hs = g.hosts.iter().find(|h| h.target.name == e.host);
                        let host = hs.map(|h| h.target.title()).unwrap_or_else(|| TITLE.to_string());
                        ui.label(RichText::new(host).color(p.muted).size(12.0));
                        ui.label(&e.text);
                        if e.count > 1 {
                            ui.label(RichText::new(format!("×{} · {}부터", e.count, win::fmt_clock(e.ts, now, self.offset))).color(p.muted).size(12.0));
                        }
                        if let Some(h) = hs.filter(|_| e.level >= Level::Warn) {
                            let s = subject(g, h, "실시간 이벤트", e.level, &e.text, &[]);
                            if let Some(state) = self.ai_row(&s) {
                                let clicked = match state {
                                    Some(a) => ui
                                        .add(egui::Button::new(RichText::new(format!("AI: {}", a.verdict.label())).color(p.level(a.verdict.level())).size(12.0)).small())
                                        .on_hover_text(&a.summary)
                                        .clicked(),
                                    None => ui.small_button("AI 설명").on_hover_text("이 이벤트가 걱정할 일인지 AI에게 물어봅니다").clicked(),
                                };
                                if clicked {
                                    actions.push(Action::Explain(s));
                                }
                            }
                        }
                    });
                }
            });
        });
    }

    fn conns_panel(&self, ui: &mut egui::Ui, g: &Inner, p: &Palette) {
        panel(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("지금 들어와 있는 연결").strong().size(15.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new("열려 있는 포트로 들어온 연결 · 5초마다 갱신 · 빨간색은 공인(외부) IP").color(p.muted).size(12.5));
                });
            });
            let mut rows: Vec<_> = g
                .hosts
                .iter()
                .filter(|h| self.selected.as_ref().is_none_or(|s| *s == h.target.name))
                .flat_map(|h| h.conns.iter().map(move |c| (h, c)))
                .collect();
            rows.sort_by_key(|(_, c)| !c.public);
            if rows.is_empty() {
                ui.label(RichText::new("지금 들어와 있는 연결이 없습니다.").color(p.muted));
                return;
            }
            egui::ScrollArea::vertical().id_salt("conns").max_height(260.0).auto_shrink([false, true]).show(ui, |ui| {
                egui::Grid::new("conns_grid").striped(true).num_columns(4).min_col_width(140.0).show(ui, |ui| {
                    for head in ["대상", "상대 주소", "받은 포트", "프로세스"] {
                        ui.label(RichText::new(head).color(p.muted).strong().size(12.5));
                    }
                    ui.end_row();
                    for (h, c) in rows {
                        ui.label(h.target.title());
                        let peer = if c.public { format!("{} (외부)", c.peer) } else { c.peer.clone() };
                        ui.label(RichText::new(peer).monospace().color(if c.public { p.alert } else { ui.visuals().text_color() }));
                        ui.label(RichText::new(&c.local).monospace());
                        if c.proc_name == "?" {
                            ui.label(RichText::new("권한 필요").color(p.muted));
                        } else {
                            ui.label(&c.proc_name);
                        }
                        ui.end_row();
                    }
                });
            });
        });
    }

    fn usb_panel(&self, ui: &mut egui::Ui, g: &Inner, p: &Palette) {
        panel(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("USB 키보드형 장치 (BadUSB 감시)").strong().size(15.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new("새로 꽂은 장치의 Windows 키·단축키·초고속 입력을 감지 · 입력한 글자는 기록하지 않음").color(p.muted).size(12.5));
                });
            });
            let devs: Vec<_> = g.usb.iter().collect();
            if devs.is_empty() {
                ui.label(RichText::new("연결된 USB 키보드형 장치가 없습니다.").color(p.muted));
                return;
            }
            egui::Grid::new("usb_grid").striped(true).num_columns(3).min_col_width(160.0).show(ui, |ui| {
                for head in ["장치", "상태", "입력한 키 수"] {
                    ui.label(RichText::new(head).color(p.muted).strong().size(12.5));
                }
                ui.end_row();
                for d in devs {
                    ui.label(&d.label);
                    if d.new {
                        ui.label(RichText::new(format!("이번 실행 중 연결됨 · {}", ago(crate::now_epoch().saturating_sub(d.secs), crate::now_epoch()))).color(p.warn));
                        ui.label(d.keys.to_string());
                    } else {
                        ui.label(RichText::new("시작할 때부터 연결됨 (신뢰)").color(p.muted));
                        ui.label(RichText::new("-").color(p.muted));
                    }
                    ui.end_row();
                }
            });
        });
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let (title, body) = match c {
            Confirm::WatchSince => (
                "기준 시점을 지금으로".to_string(),
                "지금 시각을 기준 시점으로 정할까요?\n이전 로그 기록(이미 조치한 과거 공격 등)은 점검 결과에서 빠지고, 바로 전체 검사를 다시 합니다.\n(기준선 비교와 실시간 이벤트는 그대로입니다)".to_string(),
            ),
            Confirm::Accept(name) => (
                "변경 사항 승인".to_string(),
                format!("{name}: 기준선과 달라진 항목을 모두 확인했고, 지금 상태를 새 기준선으로 저장할까요?"),
            ),
        };
        let mut decision = None;
        egui::Modal::new(egui::Id::unique("security-watch-confirm")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.label(RichText::new(title).strong().size(16.0));
            ui.add_space(6.0);
            ui.label(body);
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("확인").strong()).clicked() {
                    decision = Some(true);
                }
                if ui.button("취소").clicked() {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                match self.confirm.take() {
                    Some(Confirm::WatchSince) => self.app.set_watch_since_now(),
                    Some(Confirm::Accept(name)) => {
                        if let Err(e) = self.app.accept_baseline(&name) {
                            self.message = Some(e);
                        }
                    }
                    None => {}
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

fn panel(ui: &mut egui::Ui, p: &Palette, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new().fill(p.panel).stroke(Stroke::new(1.0, p.line)).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
}

fn stat(ui: &mut egui::Ui, p: &Palette, value: String, label: &str, hot: bool) {
    egui::Frame::new().fill(p.tile).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(9, 6)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let v = RichText::new(value).strong().size(18.0);
        ui.label(if hot { v.color(p.alert) } else { v });
        ui.label(RichText::new(label).color(p.muted).size(11.5));
    });
}

/// `ai`: None = no AI button; Some(answer) = button, plus the cached answer if any.
/// Returns true when the AI button (or the answer line) was clicked.
fn finding_row(ui: &mut egui::Ui, p: &Palette, level: Level, text: &str, details: &[String], ai: Option<Option<ai::Answer>>) -> bool {
    let mut clicked = false;
    ui.horizontal_top(|ui| {
        badge(ui, p, level, level.label());
        ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(text);
                if matches!(ai, Some(None)) && ui.small_button("AI 설명").on_hover_text("이 항목이 걱정할 일인지 AI에게 물어봅니다").clicked() {
                    clicked = true;
                }
            });
            for d in details {
                ui.label(RichText::new(format!("• {d}")).color(p.muted).size(12.5));
            }
            if let Some(Some(a)) = &ai {
                let line = RichText::new(format!("AI 의견: {} · {}", a.verdict.label(), short(&a.summary, 80))).color(p.level(a.verdict.level())).size(12.5);
                if ui.add(egui::Label::new(line).sense(Sense::click())).on_hover_text("클릭하면 AI 설명 전체 보기").clicked() {
                    clicked = true;
                }
            }
        });
    });
    ui.add_space(4.0);
    clicked
}

fn ago_text(ts: u64) -> String {
    ago(ts, crate::now_epoch())
}

impl Gui {
    fn key_form(&mut self, ui: &mut egui::Ui, p: &Palette, s: &Subject) {
        ui.label(RichText::new("Anthropic API 키").strong());
        ui.label(
            "console.anthropic.com → API Keys에서 만든 키(sk-ant-…)를 붙여 넣으세요. \
             이 Windows 계정에서만 풀 수 있도록 암호화(DPAPI)해서 .private\\state\\ai.key에 저장합니다. \
             환경 변수 ANTHROPIC_API_KEY가 있으면 그 키를 먼저 씁니다.",
        );
        ui.add(egui::TextEdit::singleline(&mut self.key_input).password(true).hint_text("sk-ant-...").desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            if ui.button(RichText::new("저장").strong()).clicked() {
                match self.ai.save_key(&self.key_input) {
                    Ok(()) => {
                        self.key_input.clear();
                        self.key_message = None;
                        self.editing_key = false;
                        if matches!(self.ai.view(&s.key()), View::None | View::Failed(_)) {
                            self.ai.prepare(s.clone(), ui.ctx().clone());
                        }
                    }
                    Err(e) => self.key_message = Some(e),
                }
            }
            if self.ai.key_source() == KeySource::File && ui.button("저장된 키 삭제").clicked() {
                self.ai.delete_key();
                self.key_message = Some("저장된 키를 삭제했습니다".into());
            }
            if self.editing_key && ui.button("취소").clicked() {
                self.editing_key = false;
                self.key_input.clear();
            }
        });
        if let Some(m) = &self.key_message {
            ui.label(RichText::new(m).color(p.alert));
        }
    }

    fn answer_view(&self, ui: &mut egui::Ui, p: &Palette, a: &ai::Answer) {
        ui.horizontal_wrapped(|ui| {
            badge(ui, p, a.verdict.level(), a.verdict.label());
            ui.label(RichText::new(&a.summary).strong());
        });
        ui.add_space(4.0);
        ui.label(&a.explanation);
        if !a.steps.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new("직접 확인하는 방법").strong());
            for (i, step) in a.steps.iter().enumerate() {
                ui.label(format!("{}. {step}", i + 1));
            }
        }
        ui.add_space(6.0);
        let cost = a.cost_usd().map(|c| format!(" · 약 ${c:.4}")).unwrap_or_default();
        ui.label(RichText::new(format!("{} · {} · 입력 {} / 출력 {} 토큰{cost}", a.model, ago_text(a.ts), a.input_tokens, a.output_tokens)).color(p.muted).size(12.0));
    }

    fn ai_window(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(s) = self.ai_open.clone() else { return };
        let key = s.key();
        let mut open = true;
        let mut close = false;
        egui::Window::new("AI 설명")
            .id(egui::Id::unique("security-watch-ai"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(600.0)
            .default_pos(ctx.content_rect().center() - egui::vec2(300.0, 260.0))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().max_height(620.0).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        badge(ui, p, s.level, s.level.label());
                        ui.label(RichText::new(format!("{} · {}", s.title, s.source)).color(p.muted).size(12.5));
                    });
                    ui.label(RichText::new(&s.text).strong());
                    for d in s.details.iter().take(8) {
                        ui.label(RichText::new(format!("• {d}")).color(p.muted).size(12.5));
                    }
                    if s.details.len() > 8 {
                        ui.label(RichText::new(format!("… 외 {}줄", s.details.len() - 8)).color(p.muted).size(12.5));
                    }
                    ui.separator();

                    if self.ai.key_source() == KeySource::Missing || self.editing_key {
                        self.key_form(ui, p, &s);
                        return;
                    }
                    let model = self.ai.settings.model.clone();
                    match self.ai.view(&key) {
                        View::None => {
                            if ui.button("AI에게 묻기 준비").clicked() {
                                self.ai.prepare(s.clone(), ctx.clone());
                            }
                        }
                        View::Preparing => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("이 PC에서 관련 정보(실행 위치·서명·포트)를 확인하는 중…");
                            });
                        }
                        View::Ready(prompt) => {
                            let masked = if self.ai.settings.mask { " IP 주소·PC 이름·서버 이름·사용자 이름은 가려서 보냅니다." } else { " (ai-mask off: 가리지 않고 그대로 보냅니다)" };
                            ui.label(format!("아래 내용을 Claude({model})에게 보냅니다.{masked}"));
                            egui::ScrollArea::vertical().id_salt("ai-prompt").max_height(240.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut prompt.as_str()).code_editor().desired_width(f32::INFINITY));
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.button(RichText::new("보내고 묻기").strong()).clicked() {
                                    self.ai.ask(&key, ctx.clone());
                                }
                                if ui.button("취소").clicked() {
                                    close = true;
                                }
                                if model == ai::DEFAULT_MODEL {
                                    ui.label(RichText::new("보통 한 번에 $0.001 미만").color(p.muted).size(12.0));
                                }
                            });
                        }
                        View::Asking => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(format!("Claude({model})에게 묻는 중…"));
                            });
                        }
                        View::Failed(e) => {
                            ui.label(RichText::new(e).color(p.alert));
                            ui.horizontal(|ui| {
                                if ui.button("다시 시도").clicked() {
                                    self.ai.prepare(s.clone(), ctx.clone());
                                }
                                if ui.button("API 키 바꾸기").clicked() {
                                    self.editing_key = true;
                                }
                            });
                        }
                        View::Done(a) => {
                            self.answer_view(ui, p, &a);
                            let sent = self.ai.sent(&key);
                            ui.horizontal(|ui| {
                                if ui.button("다시 묻기").clicked() {
                                    self.show_sent = false;
                                    self.ai.prepare(s.clone(), ctx.clone());
                                }
                                if sent.is_some() {
                                    ui.toggle_value(&mut self.show_sent, "보낸 내용 보기");
                                }
                            });
                            if let Some(sent) = sent.filter(|_| self.show_sent) {
                                egui::ScrollArea::vertical().id_salt("ai-sent").max_height(200.0).show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(&mut sent.as_str()).code_editor().desired_width(f32::INFINITY));
                                });
                            }
                        }
                    }
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("AI 의견은 참고용입니다. 로그 내용 일부는 공격자가 꾸밀 수 있으니, 승인이나 조치는 직접 확인한 뒤 하세요.")
                                .color(p.muted)
                                .size(12.0),
                        );
                        let src = match self.ai.key_source() {
                            KeySource::Env => "키: 환경 변수",
                            KeySource::File => "키: 암호화 저장",
                            KeySource::Missing => "키 없음",
                        };
                        ui.label(RichText::new(src).color(p.muted).size(12.0));
                        if ui.small_button("API 키 관리").clicked() {
                            self.editing_key = true;
                        }
                    });
                });
            });
        if !open || close {
            self.ai.dismiss(&key);
            self.ai_open = None;
            self.editing_key = false;
            self.key_input.clear();
        }
    }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // egui's bundled fonts have no Hangul; Malgun Gothic ships with Windows.
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\malgun.ttf") {
        fonts.font_data.insert("malgun".into(), Arc::new(egui::FontData::from_owned(bytes)));
        if let Some(f) = fonts.families.get_mut(&FontFamily::Proportional) {
            f.insert(0, "malgun".into());
        }
        if let Some(f) = fonts.families.get_mut(&FontFamily::Monospace) {
            f.push("malgun".into());
        }
    }
    ctx.set_fonts(fonts);
    ctx.all_styles_mut(|s| {
        use egui::{FontId, TextStyle};
        s.text_styles.insert(TextStyle::Body, FontId::proportional(14.0));
        s.text_styles.insert(TextStyle::Button, FontId::proportional(14.0));
        s.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
        s.text_styles.insert(TextStyle::Monospace, FontId::monospace(13.0));
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
    });
}

impl eframe::App for Gui {
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        ctx.request_repaint_after(Duration::from_secs(1));
        let now = crate::now_epoch();
        let p = palette(root_ui.visuals().dark_mode);
        let app = Arc::clone(&self.app);
        let mut actions = Vec::new();
        {
            let g = app.lock();
            egui::Panel::top("top").frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(18, 10))).show(root_ui, |ui| {
                self.top_bar(ui, &g, &p, now, &mut actions);
            });
            egui::CentralPanel::default().show(root_ui, |ui| {
                egui::ScrollArea::vertical().id_salt("page").auto_shrink([false, false]).show(ui, |ui| {
                    ui.add_space(6.0);
                    if let Some(m) = &self.message {
                        ui.label(RichText::new(m).color(p.alert).strong());
                    }
                    let n = g.hosts.len().max(1);
                    ui.columns(n, |cols| {
                        for (i, h) in g.hosts.iter().enumerate() {
                            self.host_card(&mut cols[i], &g, h, &p, now, &mut actions);
                        }
                    });
                    ui.add_space(12.0);
                    ui.columns(2, |cols| {
                        self.findings_panel(&mut cols[0], &g, &p, now, &mut actions);
                        self.events_panel(&mut cols[1], &g, &p, now, &mut actions);
                    });
                    ui.add_space(12.0);
                    self.conns_panel(ui, &g, &p);
                    ui.add_space(12.0);
                    if g.hosts.iter().any(|h| matches!(h.target.kind, Kind::Local)) {
                        self.usb_panel(ui, &g, &p);
                        ui.add_space(12.0);
                    }
                });
            });
        }
        for a in actions {
            match a {
                Action::Select(n) => self.selected = if self.selected.as_deref() == Some(n.as_str()) { None } else { Some(n) },
                Action::Scan => app.request_scan(),
                Action::Minutes(m) => app.set_scan_minutes(m),
                Action::Alarm(on) => app.set_alarm(on),
                Action::Ask(c) => self.confirm = Some(c),
                Action::Explain(s) => self.open_explain(s, &ctx),
            }
        }
        self.ai_window(&ctx, &p);
        self.confirm_dialog(&ctx);
    }
}

include!("icon_shape.rs");

/// Window icon (taskbar/title bar), drawn by the same code as the exe icon.
pub fn icon(size: u32) -> egui::IconData {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    const SS: u32 = 4;
    for row in 0..size {
        for col in 0..size {
            let (mut acc, mut a) = ([0.0f64; 3], 0.0f64);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (col as f64 + (sx as f64 + 0.5) / SS as f64) / size as f64;
                    let y = (row as f64 + (sy as f64 + 0.5) / SS as f64) / size as f64;
                    let s = shade(x, y);
                    for i in 0..3 {
                        acc[i] += s[i] * s[3];
                    }
                    a += s[3];
                }
            }
            let ch = |i: usize| if a > 0.0 { (acc[i] / a).round() as u8 } else { 0 };
            rgba.extend_from_slice(&[ch(0), ch(1), ch(2), (a / (SS * SS) as f64 * 255.0).round() as u8]);
        }
    }
    egui::IconData { rgba, width: size, height: size }
}
