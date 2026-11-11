//! Alarm for dangerous events: a tray icon whose balloon (a toast on Windows 10/11)
//! says what happened, plus a sound and a flashing taskbar button, so it is noticed
//! while the dashboard sits in the background. Clicking the icon or the balloon
//! brings the dashboard to the front.

use crate::app::App;
use crate::gui::TITLE;
use crate::win;
use std::ffi::c_void;
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;

type Hwnd = *mut c_void;

#[repr(C)]
struct WndClassExW {
    size: u32,
    style: u32,
    wndproc: unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize,
    cls_extra: i32,
    wnd_extra: i32,
    instance: *mut c_void,
    icon: *mut c_void,
    cursor: *mut c_void,
    background: *mut c_void,
    menu_name: *const u16,
    class_name: *const u16,
    icon_small: *mut c_void,
}

#[repr(C)]
struct Msg {
    hwnd: Hwnd,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt: [i32; 2],
    private: u32,
}

/// NOTIFYICONDATAW
#[repr(C)]
struct NotifyIconData {
    size: u32,
    hwnd: Hwnd,
    id: u32,
    flags: u32,
    callback_message: u32,
    icon: *mut c_void,
    tip: [u16; 128],
    state: u32,
    state_mask: u32,
    info: [u16; 256],
    version: u32,
    info_title: [u16; 64],
    info_flags: u32,
    guid: [u8; 16],
    balloon_icon: *mut c_void,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterClassExW(wc: *const WndClassExW) -> u16;
    fn CreateWindowExW(ex: u32, class: *const u16, name: *const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: Hwnd, menu: *mut c_void, inst: *mut c_void, param: *mut c_void) -> Hwnd;
    fn DefWindowProcW(h: Hwnd, msg: u32, w: usize, l: isize) -> isize;
    fn GetMessageW(msg: *mut Msg, h: Hwnd, min: u32, max: u32) -> i32;
    fn DispatchMessageW(msg: *const Msg) -> isize;
    fn SetTimer(h: Hwnd, id: usize, millis: u32, callback: *mut c_void) -> usize;
    fn LoadIconW(inst: *mut c_void, name: *const u16) -> *mut c_void;
    fn RegisterWindowMessageW(name: *const u16) -> u32;
    fn MessageBeep(kind: u32) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn Shell_NotifyIconW(message: u32, data: *const NotifyIconData) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

const WM_TIMER: u32 = 0x0113;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_LBUTTONDBLCLK: u32 = 0x0203;
const WM_TRAY: u32 = 0x8000 + 1; // WM_APP + 1
const NIN_BALLOONUSERCLICK: u32 = 0x0405;
const NIM_ADD: u32 = 0;
const NIM_MODIFY: u32 = 1;
const NIM_DELETE: u32 = 2;
const NIF_MESSAGE: u32 = 1;
const NIF_ICON: u32 = 2;
const NIF_TIP: u32 = 4;
const NIF_INFO: u32 = 0x10;
const NIIF_ERROR: u32 = 3;
const NIIF_NOSOUND: u32 = 0x10;
const MB_ICONHAND: u32 = 0x10;
const IDI_SHIELD: usize = 32518;
/// Alarms arriving within this many seconds of a balloon wait and are shown together.
const GAP_SECS: u64 = 20;

static APP: OnceLock<Arc<App>> = OnceLock::new();
static HWND: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
static LAST_SHOWN: AtomicU64 = AtomicU64::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Copies `s` into a fixed UTF-16 field, cut at a character boundary, NUL-terminated.
fn put(dst: &mut [u16], s: &str) {
    let mut i = 0;
    for c in s.chars() {
        let mut b = [0u16; 2];
        let u = c.encode_utf16(&mut b);
        if i + u.len() >= dst.len() {
            break;
        }
        dst[i..i + u.len()].copy_from_slice(u);
        i += u.len();
    }
    dst[i] = 0;
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max - 1).chain(Some('…')).collect()
}

fn data(hwnd: Hwnd) -> NotifyIconData {
    let mut d: NotifyIconData = unsafe { std::mem::zeroed() };
    d.size = std::mem::size_of::<NotifyIconData>() as u32;
    d.hwnd = hwnd;
    d.id = 1;
    d
}

fn add_icon(hwnd: Hwnd) {
    let mut d = data(hwnd);
    d.flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    d.callback_message = WM_TRAY;
    put(&mut d.tip, TITLE);
    unsafe {
        // The exe's own icon (resource 1, embedded by build.rs), else the stock shield.
        d.icon = LoadIconW(GetModuleHandleW(std::ptr::null()), 1 as *const u16);
        if d.icon.is_null() {
            d.icon = LoadIconW(std::ptr::null_mut(), IDI_SHIELD as *const u16);
        }
        Shell_NotifyIconW(NIM_ADD, &d);
    }
}

/// Balloon title and body for the queued alarms.
fn message(alarms: &[String]) -> (String, String) {
    let title = match alarms.len() {
        1 => "security-watch 위험 감지".to_string(),
        n => format!("security-watch 위험 감지 ({n}건)"),
    };
    (title, alarms.iter().take(3).map(|a| clip(a, 80)).collect::<Vec<_>>().join("\n"))
}

fn tick(hwnd: Hwnd) {
    let Some(app) = APP.get() else { return };
    let now = crate::now_epoch();
    if now < LAST_SHOWN.load(Ordering::Relaxed) + GAP_SECS {
        return;
    }
    let alarms = std::mem::take(&mut app.lock().alarms);
    if alarms.is_empty() {
        return;
    }
    LAST_SHOWN.store(now, Ordering::Relaxed);
    let (title, body) = message(&alarms);
    let mut d = data(hwnd);
    d.flags = NIF_INFO;
    d.info_flags = NIIF_ERROR | NIIF_NOSOUND;
    put(&mut d.info_title, &title);
    put(&mut d.info, &body);
    unsafe {
        Shell_NotifyIconW(NIM_MODIFY, &d);
        // Sound and taskbar flash also get through when toasts are muted (do not disturb).
        MessageBeep(MB_ICONHAND);
    }
    win::flash(TITLE);
}

unsafe extern "system" fn wndproc(h: Hwnd, msg: u32, w: usize, l: isize) -> isize {
    match msg {
        WM_TIMER => {
            tick(h);
            0
        }
        WM_TRAY => {
            if matches!(l as u32 & 0xFFFF, WM_LBUTTONUP | WM_LBUTTONDBLCLK | NIN_BALLOONUSERCLICK) {
                win::bring_to_front(TITLE);
            }
            0
        }
        // Explorer restarted: the tray is empty again.
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            add_icon(h);
            0
        }
        _ => unsafe { DefWindowProcW(h, msg, w, l) },
    }
}

pub fn start(app: Arc<App>) {
    if APP.set(app).is_err() {
        return;
    }
    thread::spawn(|| unsafe {
        // A hidden top-level window (not message-only: those miss the TaskbarCreated broadcast).
        let class = wide("SecurityWatchTray");
        let wc = WndClassExW {
            size: std::mem::size_of::<WndClassExW>() as u32,
            style: 0,
            wndproc,
            cls_extra: 0,
            wnd_extra: 0,
            instance: GetModuleHandleW(std::ptr::null()),
            icon: std::ptr::null_mut(),
            cursor: std::ptr::null_mut(),
            background: std::ptr::null_mut(),
            menu_name: std::ptr::null(),
            class_name: class.as_ptr(),
            icon_small: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), wc.instance, std::ptr::null_mut());
        if hwnd.is_null() {
            return;
        }
        HWND.store(hwnd as isize, Ordering::Relaxed);
        TASKBAR_CREATED.store(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()), Ordering::Relaxed);
        add_icon(hwnd);
        SetTimer(hwnd, 1, 1000, std::ptr::null_mut());
        let mut msg = std::mem::zeroed::<Msg>();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    });
}

/// Takes the icon out of the tray (otherwise it lingers until the mouse passes over it).
pub fn remove() {
    let hwnd = HWND.swap(0, Ordering::Relaxed);
    if hwnd != 0 {
        unsafe {
            Shell_NotifyIconW(NIM_DELETE, &data(hwnd as Hwnd));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_icon_data_matches_the_win32_layout() {
        assert_eq!(std::mem::size_of::<NotifyIconData>(), 976);
    }

    #[test]
    fn fills_fixed_fields_and_summarises() {
        let mut f = [0xFFFFu16; 4];
        put(&mut f, "가나다라마");
        assert_eq!(f, ['가' as u16, '나' as u16, '다' as u16, 0]);
        let (title, body) = message(&["a".repeat(200), "b".into(), "c".into(), "d".into()]);
        assert!(title.contains("4건"));
        assert_eq!(body.lines().count(), 3);
        assert_eq!(body.lines().next().unwrap().chars().count(), 80);
    }
}
