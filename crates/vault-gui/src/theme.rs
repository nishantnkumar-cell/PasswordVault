//! The app's look: a light, neutral palette with one blue accent, and the
//! small drawn pieces (letter tiles, code countdown) egui has no widget for.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, Pos2, RichText, Sense, Shape, Stroke,
    TextStyle, Ui, Vec2,
};

pub const INK: Color32 = Color32::from_rgb(0x15, 0x17, 0x1C);
pub const TEXT: Color32 = Color32::from_rgb(0x2E, 0x33, 0x3D);
pub const MUTED: Color32 = Color32::from_rgb(0x4F, 0x56, 0x65);
pub const GROUND: Color32 = Color32::from_rgb(0xF6, 0xF7, 0xF9);
pub const SIDEBAR: Color32 = Color32::from_rgb(0xEE, 0xF0, 0xF3);
pub const SURFACE: Color32 = Color32::WHITE;
pub const BORDER: Color32 = Color32::from_rgb(0xDD, 0xE1, 0xE7);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0xC9, 0xCE, 0xD6);
pub const HOVER: Color32 = Color32::from_rgb(0xF0, 0xF2, 0xF5);
pub const ACCENT: Color32 = Color32::from_rgb(0x2C, 0x55, 0xD4);
pub const ACCENT_DARK: Color32 = Color32::from_rgb(0x1D, 0x3F, 0xA8);
pub const ACCENT_WEAK: Color32 = Color32::from_rgb(0xE8, 0xEE, 0xFC);
pub const OK: Color32 = Color32::from_rgb(0x1F, 0x7A, 0x4D);
pub const WARN: Color32 = Color32::from_rgb(0xA8, 0x4E, 0x06);
pub const ERROR: Color32 = Color32::from_rgb(0xB4, 0x23, 0x18);

const RADIUS: u8 = 8;

/// Install the palette, spacing and type sizes.
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.style_mut_of(egui::Theme::Light, |s| {
        s.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(22.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(14.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(14.0, FontFamily::Monospace),
            ),
        ]
        .into();
        let sp = &mut s.spacing;
        sp.item_spacing = Vec2::new(8.0, 8.0);
        sp.button_padding = Vec2::new(12.0, 6.0);
        sp.interact_size.y = 30.0;
        sp.window_margin = Margin::same(16);

        let v = &mut s.visuals;
        v.panel_fill = GROUND;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, BORDER_STRONG);
        v.window_corner_radius = CornerRadius::same(14);
        v.extreme_bg_color = SURFACE;
        v.text_edit_bg_color = Some(SURFACE);
        v.faint_bg_color = GROUND;
        v.code_bg_color = GROUND;
        v.hyperlink_color = ACCENT;
        v.error_fg_color = ERROR;
        v.warn_fg_color = WARN;
        v.selection.bg_fill = ACCENT_WEAK;
        v.selection.stroke = Stroke::new(1.0, ACCENT_DARK);

        let w = &mut v.widgets;
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        for (state, fill, stroke) in [
            (&mut w.inactive, SURFACE, BORDER_STRONG),
            (&mut w.hovered, HOVER, BORDER_STRONG),
            (&mut w.active, SIDEBAR, ACCENT),
            (&mut w.open, HOVER, BORDER_STRONG),
        ] {
            state.weak_bg_fill = fill;
            state.bg_fill = fill;
            state.bg_stroke = Stroke::new(1.0, stroke);
            state.fg_stroke = Stroke::new(1.0, INK);
            state.corner_radius = CornerRadius::same(RADIUS);
            state.expansion = 0.0;
        }
    });
}

/// A white card with a hairline border.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(18, 14))
}

/// The filled blue button for a screen's main action.
pub fn primary(ui: &mut Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).color(Color32::WHITE).strong())
            .fill(ACCENT)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(0.0, 34.0)),
    )
}

/// A small uppercase heading over a group.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .small()
            .strong()
            .color(MUTED),
    );
}

/// A rounded tile with the first letter of `title`, tinted from the title so
/// each item keeps its colour.
pub fn monogram(ui: &mut Ui, title: &str, size: f32) {
    const TINTS: [(Color32, Color32); 6] = [
        (INK, Color32::WHITE),
        (
            Color32::from_rgb(0xDC, 0xE7, 0xDF),
            Color32::from_rgb(0x1F, 0x5A, 0x3B),
        ),
        (
            Color32::from_rgb(0xF4, 0xE3, 0xD3),
            Color32::from_rgb(0x8A, 0x3F, 0x05),
        ),
        (
            Color32::from_rgb(0xE3, 0xE1, 0xF5),
            Color32::from_rgb(0x3F, 0x37, 0x90),
        ),
        (
            Color32::from_rgb(0xDD, 0xEB, 0xF3),
            Color32::from_rgb(0x1D, 0x4F, 0x6E),
        ),
        (ACCENT_WEAK, ACCENT_DARK),
    ];
    let n = title
        .bytes()
        .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize));
    let (bg, fg) = TINTS[n % TINTS.len()];
    let letter = title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "·".into());
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same((size / 4.0) as u8), bg);
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        letter,
        FontId::proportional(size * 0.42),
        fg,
    );
}

/// A ring that empties as a one-time code nears its end.
pub fn countdown(ui: &mut Ui, left: f32, period: f32) {
    let size = 28.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - 3.0;
    let p = ui.painter();
    p.circle_stroke(c, r, Stroke::new(4.0, BORDER));
    let frac = (left / period.max(1.0)).clamp(0.0, 1.0);
    let steps = (48.0 * frac).ceil() as usize;
    if steps > 0 {
        let start = -std::f32::consts::FRAC_PI_2;
        let sweep = std::f32::consts::TAU * frac;
        let pts: Vec<Pos2> = (0..=steps)
            .map(|i| {
                let a = start + sweep * i as f32 / steps as f32;
                c + Vec2::new(a.cos(), a.sin()) * r
            })
            .collect();
        let color = if left <= 5.0 { WARN } else { ACCENT };
        p.add(Shape::line(pts, Stroke::new(4.0, color)));
    }
}

/// A small coloured tag such as "2FA".
pub fn badge(text: &str, fg: Color32) -> RichText {
    RichText::new(text).small().strong().color(fg)
}
