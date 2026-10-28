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

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

/// Puts this process in a kill-on-close job: every ssh/PowerShell child started
/// afterwards dies with us, even if we crash or are killed from Task Manager.
pub fn tie_children_to_process() {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return;
        }
        let mut info = ExtendedLimit::default();
        info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
    fn FindWindowW(class: *const u16, title: *const u16) -> *mut c_void;
    fn ShowWindow(hwnd: *mut c_void, cmd: i32) -> i32;
    fn SetForegroundWindow(hwnd: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(attrs: *mut c_void, initial_owner: i32, name: *const u16) -> *mut c_void;
    fn GetLastError() -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// True if this is the only running dashboard. Otherwise brings the existing
/// window (found by `title`) to the front and returns false.
pub fn single_instance(mutex_name: &str, title: &str) -> bool {
    const ERROR_ALREADY_EXISTS: u32 = 183;
    unsafe {
        let m = CreateMutexW(std::ptr::null_mut(), 0, wide(mutex_name).as_ptr());
        if !m.is_null() && GetLastError() != ERROR_ALREADY_EXISTS {
            return true; // keep the handle open for the life of the process
        }
        let hwnd = FindWindowW(std::ptr::null(), wide(title).as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, 9); // SW_RESTORE
            SetForegroundWindow(hwnd);
        }
        false
    }
}

// ----- local time formatting for unix timestamps -----

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Seconds to add to a unix time to get local wall-clock time.
pub fn local_offset() -> i64 {
    let t = local_time();
    let local = days_from_civil(t.year as i64, t.month as i64, t.day as i64) * 86_400
        + t.hour as i64 * 3600
        + t.minute as i64 * 60
        + t.second as i64;
    let utc = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    ((local - utc) as f64 / 900.0).round() as i64 * 900 // time zones are multiples of 15 min
}

/// "13:05:09" for today, "10/28 23:39" otherwise (local time).
pub fn fmt_clock(ts: u64, now: u64, offset: i64) -> String {
    let (l, n) = (ts as i64 + offset, now as i64 + offset);
    let (day, sec) = (l.div_euclid(86_400), l.rem_euclid(86_400));
    let (h, mi, s) = (sec / 3600, sec % 3600 / 60, sec % 60);
    if day == n.div_euclid(86_400) {
        format!("{h:02}:{mi:02}:{s:02}")
    } else {
        let (_, m, d) = civil_from_days(day);
        format!("{m}/{d} {h:02}:{mi:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip_and_format() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(days_from_civil(2026, 10, 29)), (2026, 10, 29));
        // 2026-10-28 14:39:00 UTC shown in KST (+9h) on a different day
        let ts = days_from_civil(2026, 10, 28) as u64 * 86_400 + 14 * 3600 + 39 * 60;
        assert_eq!(fmt_clock(ts, ts + 86_400 * 2, 9 * 3600), "10/28 23:39");
        assert_eq!(fmt_clock(ts, ts, 9 * 3600), "23:39:00");
    }
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
