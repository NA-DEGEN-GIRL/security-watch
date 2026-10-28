//! Embeds the app icon into the exe (so a pinned/shortcut exe shows it) without
//! crates: the icon is rasterized here, written as .ico, and compiled with the
//! Windows SDK `rc.exe`. If the SDK is missing the build continues without an icon.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/icon_shape.rs");
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

include!("src/icon_shape.rs");

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
