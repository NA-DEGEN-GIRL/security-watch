//! Minimal Win32 bindings (kernel32 only) so the tool needs no external crates.

use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLocalTime(st: *mut SystemTime);
    fn GetStdHandle(n: u32) -> *mut c_void;
    fn GetConsoleMode(h: *mut c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(h: *mut c_void, mode: u32) -> i32;
    fn SetConsoleOutputCP(cp: u32) -> i32;
    fn SetConsoleCP(cp: u32) -> i32;
}

const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
const CP_UTF8: u32 = 65001;

/// UTF-8 output (Korean text) and ANSI colors. Returns whether colors are usable.
pub fn init_console() -> bool {
    unsafe {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

fn local_time() -> SystemTime {
    let mut st = SystemTime::default();
    unsafe { GetLocalTime(&mut st) };
    st
}

/// "2026-10-29 00:30:12"
pub fn now_display() -> String {
    let t = local_time();
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second)
}

/// "20261029-003012"
pub fn now_file_stamp() -> String {
    let t = local_time();
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second)
}
