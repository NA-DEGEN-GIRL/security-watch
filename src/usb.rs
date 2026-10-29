//! BadUSB guard: watches keyboard-type devices with the Raw Input API, which tells
//! which physical device each keystroke came from. A device plugged in while we run
//! that presses the Windows key, sends Ctrl/Alt shortcuts or types at machine speed
//! raises an alert, and (within a minute of arrival) locks the PC before an injected
//! command can run. Only key *classes* and timing are looked at; typed characters
//! are never recorded.

use crate::app::{App, UsbDevice};
use crate::eval::Level;
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;

type Hwnd = *mut c_void;

#[repr(C)]
struct RawInputDevice {
    usage_page: u16,
    usage: u16,
    flags: u32,
    target: Hwnd,
}

#[repr(C)]
struct RawInputHeader {
    kind: u32,
    size: u32,
    device: *mut c_void,
    wparam: usize,
}

#[repr(C)]
struct RawKeyboard {
    make_code: u16,
    flags: u16,
    reserved: u16,
    vkey: u16,
    message: u32,
    extra: u32,
}

#[repr(C)]
struct RawInputKeyboard {
    header: RawInputHeader,
    keyboard: RawKeyboard,
}

#[repr(C)]
struct RawInputDeviceList {
    device: *mut c_void,
    kind: u32,
}

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

#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterClassExW(wc: *const WndClassExW) -> u16;
    fn CreateWindowExW(ex: u32, class: *const u16, name: *const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: Hwnd, menu: *mut c_void, inst: *mut c_void, param: *mut c_void) -> Hwnd;
    fn DefWindowProcW(h: Hwnd, msg: u32, w: usize, l: isize) -> isize;
    fn GetMessageW(msg: *mut Msg, h: Hwnd, min: u32, max: u32) -> i32;
    fn DispatchMessageW(msg: *const Msg) -> isize;
    fn RegisterRawInputDevices(devices: *const RawInputDevice, count: u32, size: u32) -> i32;
    fn GetRawInputData(input: *mut c_void, command: u32, data: *mut c_void, size: *mut u32, header_size: u32) -> u32;
    fn GetRawInputDeviceInfoW(device: *mut c_void, command: u32, data: *mut c_void, size: *mut u32) -> u32;
    fn GetRawInputDeviceList(list: *mut RawInputDeviceList, count: *mut u32, size: u32) -> u32;
    fn LockWorkStation() -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

const WM_INPUT_DEVICE_CHANGE: u32 = 0x00FE;
const WM_INPUT: u32 = 0x00FF;
const RID_INPUT: u32 = 0x1000_0003;
const RIDI_DEVICENAME: u32 = 0x2000_0007;
const RIM_TYPEKEYBOARD: u32 = 1;
const RIDEV_INPUTSINK: u32 = 0x0000_0100;
const RIDEV_DEVNOTIFY: u32 = 0x0000_2000;
const RI_KEY_BREAK: u16 = 1;
const GIDC_ARRIVAL: usize = 1;
const GIDC_REMOVAL: usize = 2;
const HWND_MESSAGE: isize = -3;

const YUBICO_VID: &str = "1050";
/// Injected attacks fire right after plug-in; only then do we lock the PC.
const LOCK_WINDOW_SECS: u64 = 60;
/// Faster than people type in bursts (keys per second).
const BURST_KEYS_PER_SEC: usize = 20;

struct Dev {
    vid: String,
    pid: String,
    /// Plugged in while we were running (not one of the keyboards present at start).
    new: bool,
    arrived: Instant,
    keys: u64,
    recent: VecDeque<Instant>,
    ctrl: bool,
    alt: bool,
    reported_typing: bool,
}

struct Guard {
    app: Arc<App>,
    lock_on_attack: bool,
    devs: HashMap<usize, Dev>,
}

static GUARD: OnceLock<Mutex<Guard>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn device_name(handle: *mut c_void) -> String {
    unsafe {
        let mut len = 0u32;
        GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, std::ptr::null_mut(), &mut len);
        if len == 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize];
        GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, buf.as_mut_ptr() as *mut c_void, &mut len);
        String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string()
    }
}

/// "\\?\HID#VID_1050&PID_0407&MI_00#..." -> ("1050", "0407")
pub fn vid_pid(name: &str) -> (String, String) {
    let up = name.to_ascii_uppercase();
    let grab = |key: &str| up.find(key).map(|i| up[i + key.len()..].chars().take(4).collect::<String>()).unwrap_or_default();
    (grab("VID_"), grab("PID_"))
}

fn label(vid: &str, pid: &str) -> String {
    match vid {
        "" => "가상/내장 키보드".to_string(),
        YUBICO_VID => format!("Yubico YubiKey (VID {vid} PID {pid})"),
        _ => format!("USB 키보드형 장치 (VID {vid} PID {pid})"),
    }
}

fn publish(g: &Guard) {
    let mut list: Vec<UsbDevice> = g
        .devs
        .values()
        .filter(|d| !d.vid.is_empty())
        .map(|d| UsbDevice { label: label(&d.vid, &d.pid), new: d.new, keys: d.keys, secs: d.arrived.elapsed().as_secs() })
        .collect();
    list.sort_by(|a, b| b.new.cmp(&a.new).then(a.label.cmp(&b.label)));
    g.app.lock().usb = list;
}

fn event(g: &Guard, level: Level, key: String, text: String) {
    let now = crate::now_epoch();
    g.app.lock().push_event("local", level, key, text, false, now, 600);
}

fn on_device_change(g: &mut Guard, kind: usize, handle: *mut c_void) {
    let id = handle as usize;
    if kind == GIDC_ARRIVAL {
        let name = device_name(handle);
        let (vid, pid) = vid_pid(&name);
        if !g.devs.contains_key(&id) {
            if !vid.is_empty() {
                let (level, extra) = if vid == YUBICO_VID {
                    (Level::Info, " · 터치할 때 OTP 문자열을 입력하는 것은 정상입니다")
                } else {
                    (Level::Warn, " · 직접 꽂은 키보드가 아니라면 바로 뽑으세요")
                };
                event(g, level, format!("usbkbd:{vid}:{pid}"), format!("새 키보드형 장치 연결: {}{extra}", label(&vid, &pid)));
            }
            g.devs.insert(id, Dev { vid, pid, new: true, arrived: Instant::now(), keys: 0, recent: VecDeque::new(), ctrl: false, alt: false, reported_typing: false });
        }
    } else if kind == GIDC_REMOVAL {
        g.devs.remove(&id);
    }
    publish(g);
}

fn on_key(g: &mut Guard, handle: *mut c_void, vkey: u16, up: bool) {
    // Software-generated input (SendInput) has no device; it is not a USB device.
    if handle.is_null() {
        return;
    }
    let id = handle as usize;
    if !g.devs.contains_key(&id) {
        let name = device_name(handle);
        let (vid, pid) = vid_pid(&name);
        g.devs.insert(id, Dev { vid, pid, new: false, arrived: Instant::now(), keys: 0, recent: VecDeque::new(), ctrl: false, alt: false, reported_typing: false });
    }
    let lock = g.lock_on_attack;
    let d = g.devs.get_mut(&id).expect("inserted above");
    match vkey {
        0x11 | 0xA2 | 0xA3 => d.ctrl = !up,
        0x12 | 0xA4 | 0xA5 => d.alt = !up,
        _ => {}
    }
    if up || !d.new || d.vid.is_empty() {
        return; // only key-downs from devices plugged in during this run
    }
    let now = Instant::now();
    d.keys += 1;
    d.recent.push_back(now);
    while d.recent.front().is_some_and(|t| now.duration_since(*t).as_millis() > 1000) {
        d.recent.pop_front();
    }
    let young = d.arrived.elapsed().as_secs() < LOCK_WINDOW_SECS;
    let gui = vkey == 0x5B || vkey == 0x5C;
    let shortcut = (d.ctrl || d.alt) && !matches!(vkey, 0x10..=0x12 | 0xA0..=0xA5);
    let burst = d.recent.len() >= BURST_KEYS_PER_SEC && d.vid != YUBICO_VID;
    let what = label(&d.vid, &d.pid);
    let (vid, pid) = (d.vid.clone(), d.pid.clone());
    let first_typing = !d.reported_typing;
    d.reported_typing = true;

    if gui || shortcut || burst {
        let why = if gui {
            "Windows 키를 눌렀습니다 (Win+R로 명령을 실행하는 BadUSB 수법)"
        } else if shortcut {
            "Ctrl/Alt 단축키를 보냈습니다"
        } else {
            "사람이 칠 수 없는 속도로 자동 입력 중입니다"
        };
        let locked = young && lock && unsafe { LockWorkStation() } != 0;
        let tail = if locked { " → PC를 잠갔습니다. 장치를 뽑은 뒤 다시 로그인하세요" } else { "" };
        event(g, Level::Alert, format!("usbattack:{vid}:{pid}"), format!("BadUSB 의심: 새로 꽂힌 {what}가 {why}{tail}"));
    } else if first_typing {
        let text = if vid == YUBICO_VID {
            format!("{what}가 문자를 입력했습니다 (터치 OTP라면 정상)")
        } else {
            format!("새로 꽂힌 {what}가 키 입력을 시작했습니다")
        };
        event(g, Level::Info, format!("usbtype:{vid}:{pid}"), text);
    }
    publish(g);
}

unsafe extern "system" fn wndproc(h: Hwnd, msg: u32, w: usize, l: isize) -> isize {
    let Some(lock) = GUARD.get() else { return unsafe { DefWindowProcW(h, msg, w, l) } };
    match msg {
        WM_INPUT => {
            let mut raw = std::mem::MaybeUninit::<RawInputKeyboard>::zeroed();
            let mut size = std::mem::size_of::<RawInputKeyboard>() as u32;
            let got = unsafe {
                GetRawInputData(l as *mut c_void, RID_INPUT, raw.as_mut_ptr() as *mut c_void, &mut size, std::mem::size_of::<RawInputHeader>() as u32)
            };
            if got != u32::MAX && got as usize >= std::mem::size_of::<RawInputHeader>() {
                let raw = unsafe { raw.assume_init() };
                if raw.header.kind == RIM_TYPEKEYBOARD {
                    let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
                    on_key(&mut g, raw.header.device, raw.keyboard.vkey, raw.keyboard.flags & RI_KEY_BREAK != 0);
                }
            }
            unsafe { DefWindowProcW(h, msg, w, l) }
        }
        WM_INPUT_DEVICE_CHANGE => {
            let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
            on_device_change(&mut g, w, l as *mut c_void);
            0
        }
        _ => unsafe { DefWindowProcW(h, msg, w, l) },
    }
}

/// Keyboards attached before we started are trusted as-is.
fn existing_keyboards() -> HashMap<usize, Dev> {
    let mut out = HashMap::new();
    unsafe {
        let size = std::mem::size_of::<RawInputDeviceList>() as u32;
        let mut count = 0u32;
        GetRawInputDeviceList(std::ptr::null_mut(), &mut count, size);
        let mut list: Vec<RawInputDeviceList> = (0..count).map(|_| RawInputDeviceList { device: std::ptr::null_mut(), kind: 0 }).collect();
        let n = GetRawInputDeviceList(list.as_mut_ptr(), &mut count, size);
        if n == u32::MAX {
            return out;
        }
        for d in list.iter().take(n as usize).filter(|d| d.kind == RIM_TYPEKEYBOARD) {
            let name = device_name(d.device);
            let (vid, pid) = vid_pid(&name);
            out.insert(d.device as usize, Dev { vid, pid, new: false, arrived: Instant::now(), keys: 0, recent: VecDeque::new(), ctrl: false, alt: false, reported_typing: false });
        }
    }
    out
}

pub fn start(app: Arc<App>, lock_on_attack: bool) {
    thread::spawn(move || unsafe {
        let devs = existing_keyboards();
        let guard = Guard { app, lock_on_attack, devs };
        publish(&guard);
        let _ = GUARD.set(Mutex::new(guard));

        let class = wide("SecurityWatchRawInput");
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
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, HWND_MESSAGE as Hwnd, std::ptr::null_mut(), wc.instance, std::ptr::null_mut());
        if hwnd.is_null() {
            return;
        }
        // Generic desktop keyboards (usage page 1, usage 6), even when we are not focused.
        let rid = RawInputDevice { usage_page: 1, usage: 6, flags: RIDEV_INPUTSINK | RIDEV_DEVNOTIFY, target: hwnd };
        if RegisterRawInputDevices(&rid, 1, std::mem::size_of::<RawInputDevice>() as u32) == 0 {
            return;
        }
        let mut msg = std::mem::zeroed::<Msg>();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_vid_pid_from_device_path() {
        let (v, p) = super::vid_pid(r"\\?\HID#VID_1050&PID_0407&MI_00#7&1a2b&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}");
        assert_eq!((v.as_str(), p.as_str()), ("1050", "0407"));
        assert_eq!(super::vid_pid(r"\\?\Root#RDP_KBD#0000#{884b}").0, "");
    }
}
