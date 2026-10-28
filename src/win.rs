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
    fn AttachConsole(pid: u32) -> i32;
    fn AllocConsole() -> i32;
    fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(job: *mut c_void, class: i32, info: *mut c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
}

#[repr(C)]
#[derive(Default)]
struct BasicLimit {
    per_process_user_time: i64,
    per_job_user_time: i64,
    limit_flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimit {
    basic: BasicLimit,
    io: [u64; 6],
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}

const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x0800;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
/// Spawn flag for processes that must outlive us (the Edge window).
pub const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// Puts this process in a kill-on-close job: every ssh/PowerShell child started
/// afterwards dies with us, even if we crash or are killed from Task Manager.
pub fn tie_children_to_process() {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return;
        }
        let mut info = ExtendedLimit::default();
        info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        let ok = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            &mut info as *mut ExtendedLimit as *mut c_void,
            std::mem::size_of::<ExtendedLimit>() as u32,
        );
        if ok != 0 {
            AssignProcessToJobObject(job, GetCurrentProcess());
        }
        // The job handle stays open for the life of the process on purpose.
    }
}

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
}

const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;

/// The exe is a GUI-subsystem app (no console flash on double-click). For the
/// `--once` text report, reuse redirected handles, else the parent console, else a
/// new console. Returns true when prompts (y/N, Enter) can be answered.
pub fn ensure_console() -> bool {
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h.is_null() && h as isize != -1 {
            return true; // redirected (pipe/file) by the caller
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
            return false; // the parent shell owns the keyboard; do not prompt
        }
        AllocConsole() != 0
    }
}

pub fn message_box(caption: &str, text: &str) {
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (t, c) = (w(text), w(caption));
    unsafe {
        MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), 0x10);
    }
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
