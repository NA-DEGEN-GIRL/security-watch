//! Embeds the app icon into the exe (so a pinned/shortcut exe shows it) without
//! crates: the icon is rasterized here, written as .ico, and compiled with the
//! Windows SDK `rc.exe`. If the SDK is missing the build continues without an icon.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = out.join("app.ico");
    fs::write(&ico, make_ico(&[16, 24, 32, 48, 64, 256])).unwrap();

    let Some(rc) = find_rc() else {
        println!("cargo:warning=rc.exe (Windows SDK) not found; building without an exe icon");
        return;
    };
    let rc_file = out.join("app.rc");
    fs::write(&rc_file, format!("1 ICON \"{}\"\n", ico.display().to_string().replace('\\', "\\\\"))).unwrap();
    let res = out.join("app.res");
    let ok = Command::new(rc).arg("/nologo").arg("/fo").arg(&res).arg(&rc_file).status().map(|s| s.success()).unwrap_or(false);
    if ok {
        println!("cargo:rustc-link-arg-bins={}", res.display());
    } else {
        println!("cargo:warning=rc.exe failed; building without an exe icon");
    }
}

fn find_rc() -> Option<PathBuf> {
    let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = fs::read_dir(kits).ok()?.flatten().map(|e| e.path()).filter(|p| p.join("x64").join("rc.exe").is_file()).collect();
    versions.sort();
    versions.pop().map(|v| v.join("x64").join("rc.exe"))
}

/// Coverage-blended RGBA of the shield icon at unit coordinates (x, y in 0..1).
fn shade(x: f64, y: f64) -> [f64; 4] {
    let mut c = [0.0, 0.0, 0.0, 0.0];
    let mut paint = |rgb: [f64; 3], inside: bool| {
        if inside {
            c = [rgb[0], rgb[1], rgb[2], 1.0];
        }
    };
    // Rounded dark tile.
    let r = 0.22;
    let (dx, dy) = ((x - 0.5).abs() - (0.5 - r), (y - 0.5).abs() - (0.5 - r));
    let tile = dx.max(0.0).hypot(dy.max(0.0)) <= r;
    paint([13.0, 17.0, 23.0], tile);
    // Shield: pointed top, straight sides, rounded bottom.
    let half = if y < 0.125 || y > 0.86 {
        -1.0
    } else if y < 0.24 {
        0.32 * (y - 0.125) / 0.115
    } else if y < 0.48 {
        0.32
    } else {
        let t = (y - 0.48) / 0.38;
        0.32 * (1.0 - t * t).max(0.0).sqrt()
    };
    paint([47.0, 129.0, 247.0], (x - 0.5).abs() <= half);
    // Check mark.
    let seg = |ax: f64, ay: f64, bx: f64, by: f64| {
        let (vx, vy) = (bx - ax, by - ay);
        let t = (((x - ax) * vx + (y - ay) * vy) / (vx * vx + vy * vy)).clamp(0.0, 1.0);
        (x - ax - t * vx).hypot(y - ay - t * vy)
    };
    let d = seg(0.35, 0.50, 0.46, 0.61).min(seg(0.46, 0.61, 0.67, 0.40));
    paint([255.0, 255.0, 255.0], d <= 0.045);
    c
}

fn render(size: u32) -> Vec<u8> {
    const SS: u32 = 4; // 4x4 supersampling for smooth edges
    let mut px = Vec::with_capacity((size * size * 4) as usize);
    for row in (0..size).rev() {
        // BMP rows are bottom-up
        for col in 0..size {
            let mut acc = [0.0; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (col as f64 + (sx as f64 + 0.5) / SS as f64) / size as f64;
                    let y = (row as f64 + (sy as f64 + 0.5) / SS as f64) / size as f64;
                    let s = shade(x, y);
                    for i in 0..3 {
                        acc[i] += s[i] * s[3];
                    }
                    acc[3] += s[3];
                }
            }
            let n = (SS * SS) as f64;
            let a = acc[3] / n;
            let ch = |i: usize| if acc[3] > 0.0 { (acc[i] / acc[3]).round() as u8 } else { 0 };
            px.extend_from_slice(&[ch(2), ch(1), ch(0), (a * 255.0).round() as u8]); // BGRA
        }
    }
    px
}

fn make_ico(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&s| {
            let mask_row = s.div_ceil(32) * 4;
            let mut b = Vec::new();
            for v in [40u32, s, s * 2] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&32u16.to_le_bytes());
            for v in [0u32, s * s * 4 + mask_row * s, 0, 0, 0, 0] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&render(s));
            b.extend(std::iter::repeat_n(0u8, (mask_row * s) as usize));
            b
        })
        .collect();
    let mut ico = Vec::new();
    for v in [0u16, 1, sizes.len() as u16] {
        ico.extend_from_slice(&v.to_le_bytes());
    }
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (s, img) in sizes.iter().zip(&images) {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        ico.extend_from_slice(&[dim, dim, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(img.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        ico.extend_from_slice(&img);
    }
    ico
}
