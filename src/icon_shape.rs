// Shared by build.rs (exe icon) and the app (window icon). Pure function, no deps.

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
