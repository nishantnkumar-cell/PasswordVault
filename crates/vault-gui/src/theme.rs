//! The app's look: a light, neutral palette with one blue accent, the bundled
//! Inter and JetBrains Mono fonts, and the small drawn pieces (letter tiles,
//! code countdown, list rows) egui has no widget for.

use std::sync::Arc;

pub use crate::icon::Icon;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Pos2, Rect,
    RichText, Sense, Shadow, Shape, Stroke, TextStyle, Ui, Vec2, ViewportCommand, WidgetInfo,
};

pub const INK: Color32 = Color32::from_rgb(0x15, 0x17, 0x1C);
pub const TEXT: Color32 = Color32::from_rgb(0x2E, 0x33, 0x3D);
pub const MUTED: Color32 = Color32::from_rgb(0x4F, 0x56, 0x65);
pub const GROUND: Color32 = Color32::from_rgb(0xF6, 0xF7, 0xF9);
pub const SIDEBAR: Color32 = Color32::from_rgb(0xEE, 0xF0, 0xF3);
pub const SURFACE: Color32 = Color32::WHITE;
/// Lines between panes and around cards.
pub const BORDER: Color32 = Color32::from_rgb(0xDD, 0xE1, 0xE7);
/// Lines between rows inside a card: softer than the card's own edge.
pub const DIVIDER: Color32 = Color32::from_rgb(0xE8, 0xEB, 0xEF);
/// Edges of things you can type in or press.
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0xC9, 0xCE, 0xD6);
/// The empty part of a slider.
const RAIL: Color32 = Color32::from_rgb(0xE3, 0xE6, 0xEB);
pub const HOVER: Color32 = Color32::from_rgb(0xF0, 0xF2, 0xF5);
pub const ACCENT: Color32 = Color32::from_rgb(0x2C, 0x55, 0xD4);
pub const ACCENT_DARK: Color32 = Color32::from_rgb(0x1D, 0x3F, 0xA8);
pub const ACCENT_WEAK: Color32 = Color32::from_rgb(0xE8, 0xEE, 0xFC);
pub const OK: Color32 = Color32::from_rgb(0x1F, 0x7A, 0x4D);
pub const OK_WEAK: Color32 = Color32::from_rgb(0xDC, 0xEF, 0xE3);
pub const WARN: Color32 = Color32::from_rgb(0xA8, 0x4E, 0x06);
pub const WARN_WEAK: Color32 = Color32::from_rgb(0xFB, 0xEE, 0xE2);
pub const ERROR: Color32 = Color32::from_rgb(0xB4, 0x23, 0x18);
pub const ERROR_WEAK: Color32 = Color32::from_rgb(0xFD, 0xEC, 0xEA);

const RADIUS: u8 = 8;

/// The family for headings and names: Inter SemiBold.
pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

/// Text in Inter SemiBold, in ink.
pub fn bold(text: impl Into<String>) -> RichText {
    RichText::new(text).family(semibold()).color(INK)
}

/// A page or pane title.
pub fn title(text: impl Into<String>, size: f32) -> RichText {
    bold(text).size(size)
}

/// Load the bundled fonts. Inter and JetBrains Mono come first; egui's own
/// fonts stay behind them for characters the subsets leave out.
fn fonts(ctx: &egui::Context) {
    let mut f = FontDefinitions::default();
    for (name, bytes) in [
        ("Inter", &include_bytes!("../fonts/Inter-Regular.otf")[..]),
        (
            "Inter SemiBold",
            &include_bytes!("../fonts/Inter-SemiBold.otf")[..],
        ),
        (
            "JetBrains Mono",
            &include_bytes!("../fonts/JetBrainsMono-Regular.ttf")[..],
        ),
    ] {
        f.font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
    }
    let fallback = f.families[&FontFamily::Proportional].clone();
    f.families
        .get_mut(&FontFamily::Proportional)
        .expect("egui has a proportional family")
        .insert(0, "Inter".into());
    f.families
        .get_mut(&FontFamily::Monospace)
        .expect("egui has a monospace family")
        .insert(0, "JetBrains Mono".into());
    let mut strong = vec!["Inter SemiBold".to_owned()];
    strong.extend(fallback);
    f.families.insert(semibold(), strong);
    ctx.set_fonts(f);
}

/// Install the fonts, palette, spacing and type sizes. The app is always
/// light, even when the system is dark, title bar included.
pub fn apply(ctx: &egui::Context) {
    fonts(ctx);
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.send_viewport_cmd(ViewportCommand::SetTheme(egui::SystemTheme::Light));
    ctx.style_mut_of(egui::Theme::Light, |s| {
        s.text_styles = [
            (TextStyle::Heading, FontId::new(22.0, semibold())),
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
                FontId::new(13.5, FontFamily::Monospace),
            ),
        ]
        .into();
        let sp = &mut s.spacing;
        sp.item_spacing = Vec2::new(8.0, 8.0);
        sp.button_padding = Vec2::new(12.0, 6.0);
        sp.interact_size.y = 34.0;
        sp.window_margin = Margin::same(16);
        sp.menu_margin = Margin::same(6);
        sp.icon_width = 18.0;
        sp.icon_width_inner = 10.0;
        sp.icon_spacing = 8.0;

        let v = &mut s.visuals;
        v.panel_fill = GROUND;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_corner_radius = CornerRadius::same(14);
        v.window_shadow = Shadow {
            offset: [0, 12],
            blur: 40,
            spread: 0,
            color: Color32::from_black_alpha(28),
        };
        v.popup_shadow = Shadow {
            offset: [0, 6],
            blur: 18,
            spread: 0,
            color: Color32::from_black_alpha(22),
        };
        v.menu_corner_radius = CornerRadius::same(10);
        v.extreme_bg_color = SURFACE;
        v.text_edit_bg_color = Some(SURFACE);
        v.faint_bg_color = GROUND;
        v.code_bg_color = GROUND;
        v.hyperlink_color = ACCENT;
        v.error_fg_color = ERROR;
        v.warn_fg_color = WARN;
        v.selection.bg_fill = ACCENT_WEAK;
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.text_cursor.stroke = Stroke::new(1.5, INK);
        v.slider_trailing_fill = true;
        v.handle_shape = egui::style::HandleShape::Circle;

        let w = &mut v.widgets;
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.bg_fill = SURFACE;
        w.noninteractive.weak_bg_fill = SURFACE;
        w.noninteractive.corner_radius = CornerRadius::same(RADIUS);
        // `weak_bg_fill` paints buttons; `bg_fill` paints slider rails and
        // check boxes, which need to show on a white card.
        for (state, fill, rail, stroke) in [
            (&mut w.inactive, SURFACE, RAIL, BORDER_STRONG),
            (&mut w.hovered, HOVER, BORDER, BORDER_STRONG),
            (&mut w.active, SIDEBAR, BORDER, ACCENT),
            (&mut w.open, HOVER, BORDER, BORDER_STRONG),
        ] {
            state.weak_bg_fill = fill;
            state.bg_fill = rail;
            state.bg_stroke = Stroke::new(1.0, stroke);
            state.fg_stroke = Stroke::new(1.0, INK);
            state.corner_radius = CornerRadius::same(RADIUS);
            state.expansion = 0.0;
        }
    });
    // The system's dark mode must not leak in through the other style.
    let light = ctx.style_of(egui::Theme::Light);
    ctx.set_style_of(egui::Theme::Dark, (*light).clone());
}

/// Size the window to `want`, or smaller so it fits on the screen with
/// room left for the taskbar, dock or top bar and the title bar, then
/// center it. Call once, on the first frame: the monitor's size is only
/// known once the window exists. `monitor_size` is in points, so the
/// system's display scaling is already taken into account. Returns false
/// when the screen's size isn't known yet, to try again next frame.
pub fn fit_to_screen(ctx: &egui::Context, want: Vec2, min: Vec2) -> bool {
    let Some(screen) = ctx.input(|i| i.viewport().monitor_size) else {
        return false;
    };
    if screen.x < 1.0 || screen.y < 1.0 {
        return false;
    }
    let size = fitted_size(screen, want, min);
    ctx.send_viewport_cmd(ViewportCommand::InnerSize(size));
    // Center in the part of the screen the taskbar leaves free.
    let x = ((screen.x - size.x) / 2.0).max(0.0);
    let y = ((screen.y - RESERVED_Y - size.y) / 2.0).max(0.0);
    ctx.send_viewport_cmd(ViewportCommand::OuterPosition(Pos2::new(x, y)));
    true
}

/// Room kept free above and below the window: a taskbar or dock (48 points
/// on Windows 11) plus the window's own title bar, with a small margin.
const RESERVED_Y: f32 = 96.0;
const RESERVED_X: f32 = 48.0;

/// The largest size up to `want` that fits on `screen`, but never below `min`.
pub fn fitted_size(screen: Vec2, want: Vec2, min: Vec2) -> Vec2 {
    let room = Vec2::new(screen.x - RESERVED_X, screen.y - RESERVED_Y);
    want.min(room).max(min)
}

/// A white card with a hairline border.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(20, 16))
}

/// A line between rows of a card, from edge to edge of the card's content.
pub fn divider(ui: &mut Ui) {
    let w = ui.available_width();
    let (r, _) = ui.allocate_exact_size(Vec2::new(w, 1.0), Sense::hover());
    ui.painter()
        .hline(r.x_range(), r.center().y, Stroke::new(1.0, DIVIDER));
}

/// The filled blue button for a screen's main action.
pub fn primary(ui: &mut Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).family(semibold()).color(Color32::WHITE))
            .fill(ACCENT)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(0.0, 36.0)),
    )
}

/// A quiet button for actions inside a card, like Copy.
pub fn soft(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(13.0).color(INK))
            .fill(GROUND)
            .stroke(Stroke::new(1.0, BORDER))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

/// A quiet button with an icon before its label.
pub fn soft_icon(ui: &mut Ui, icon: Icon, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((icon.atom(14.0), RichText::new(text).size(13.0).color(INK)))
            .fill(GROUND)
            .stroke(Stroke::new(1.0, BORDER))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

/// The small blue button inside a card, with an icon, for its main copy.
pub fn primary_small(ui: &mut Ui, icon: Icon, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((
            icon.atom_in(14.0, Color32::WHITE),
            RichText::new(text)
                .family(semibold())
                .size(13.0)
                .color(Color32::WHITE),
        ))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 32.0)),
    )
}

/// A small uppercase heading over a group.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .size(11.0)
            .family(semibold())
            .extra_letter_spacing(0.6)
            .color(MUTED),
    );
}

/// The colours of a letter tile, picked from the title so each item keeps
/// its colour.
fn tint(title: &str) -> (Color32, Color32) {
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
    TINTS[n % TINTS.len()]
}

fn paint_monogram(ui: &Ui, rect: Rect, title: &str) {
    let (bg, fg) = tint(title);
    let letter = title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "·".into());
    let size = rect.width();
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same((size / 4.5) as u8), bg);
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        letter,
        FontId::new(size * 0.42, semibold()),
        fg,
    );
}

/// A rounded tile with the first letter of `title`.
pub fn monogram(ui: &mut Ui, title: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_monogram(ui, rect, title);
}

/// The app's mark, drawn like the app icon (contrib/icons): a white keyhole
/// on a red tile, or on a green one while the vault is unlocked.
pub fn lock_tile(ui: &mut Ui, size: f32, unlocked: bool) {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    resp.widget_info(|| {
        WidgetInfo::labeled(
            egui::Role::Image,
            true,
            if unlocked {
                "Secret Vault, unlocked"
            } else {
                "Secret Vault"
            },
        )
    });
    if ui.is_rect_visible(rect) {
        paint_mark(ui.painter(), rect, unlocked);
    }
}

/// The icon's tile gradient, top left to bottom right.
pub const MARK_RED: [Color32; 2] = [
    Color32::from_rgb(0xEE, 0x3B, 0x36),
    Color32::from_rgb(0xB5, 0x16, 0x1B),
];
/// The same tile while the vault is unlocked.
pub const MARK_GREEN: [Color32; 2] = [
    Color32::from_rgb(0x2E, 0xB8, 0x6B),
    Color32::from_rgb(0x15, 0x75, 0x42),
];

fn paint_mark(p: &egui::Painter, rect: Rect, unlocked: bool) {
    let [from, to] = if unlocked { MARK_GREEN } else { MARK_RED };
    // Fill a rounded rectangle, then shade its vertices along the diagonal.
    let mut mesh = egui::Mesh::default();
    let mut tess = egui::epaint::Tessellator::new(
        p.pixels_per_point(),
        egui::epaint::TessellationOptions::default(),
        [0, 0],
        Vec::new(),
    );
    tess.tessellate_rect(
        &egui::epaint::RectShape::filled(
            rect,
            CornerRadius::same((rect.width() * 96.0 / 512.0).round() as u8),
            Color32::WHITE,
        ),
        &mut mesh,
    );
    let span = rect.width() + rect.height();
    for v in &mut mesh.vertices {
        let t = ((v.pos.x - rect.left()) + (v.pos.y - rect.top())) / span;
        let shade = from.lerp_to_gamma(to, t.clamp(0.0, 1.0));
        v.color = Color32::from_rgba_premultiplied(
            (shade.r() as f32 * v.color.a() as f32 / 255.0) as u8,
            (shade.g() as f32 * v.color.a() as f32 / 255.0) as u8,
            (shade.b() as f32 * v.color.a() as f32 / 255.0) as u8,
            v.color.a(),
        );
    }
    p.add(Shape::mesh(mesh));
    // The keyhole of secret-vault-small.svg, in 512ths of the tile.
    let at = |x: f32, y: f32| rect.min + Vec2::new(x, y) * (rect.width() / 512.0);
    let k = rect.width() / 512.0;
    p.circle_filled(at(256.0, 195.6), 86.8 * k, Color32::WHITE);
    p.add(Shape::convex_polygon(
        vec![
            at(216.8, 237.6),
            at(295.2, 237.6),
            at(326.0, 411.2),
            at(186.0, 411.2),
        ],
        Color32::WHITE,
        Stroke::NONE,
    ));
}

/// A ring that empties as a one-time code nears its end.
pub fn countdown(ui: &mut Ui, left: f32, period: f32) {
    let size = 30.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - 3.0;
    let p = ui.painter();
    p.circle_stroke(c, r, Stroke::new(4.0, DIVIDER));
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

/// Paint a tag: small semibold text on a tinted pill, right-aligned at `right`.
/// Returns the pill's left edge.
fn paint_tag(ui: &Ui, right: f32, cy: f32, text: &str, fg: Color32, bg: Color32) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), FontId::new(11.0, semibold()), fg);
    let size = galley.size() + Vec2::new(12.0, 4.0);
    let rect = Rect::from_min_size(Pos2::new(right - size.x, cy - size.y / 2.0), size);
    ui.painter().rect_filled(rect, CornerRadius::same(4), bg);
    ui.painter()
        .galley(rect.min + Vec2::new(6.0, 2.0), galley, fg);
    rect.left()
}

/// One entry of the sidebar: an icon in a small square, a name and, on the
/// right, a count. The open one is a white button whose square turns blue.
pub fn nav_row(
    ui: &mut Ui,
    on: bool,
    icon: Icon,
    name: &str,
    count: Option<usize>,
) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 38.0), Sense::click());
    resp.widget_info(|| WidgetInfo::selected(egui::Role::Button, true, on, name));
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        if on {
            p.rect_filled(
                rect.translate(Vec2::new(0.0, 1.0)),
                CornerRadius::same(9),
                Color32::from_black_alpha(12),
            );
            p.rect(
                rect,
                CornerRadius::same(9),
                SURFACE,
                Stroke::new(1.0, BORDER),
                egui::StrokeKind::Inside,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, CornerRadius::same(9), Color32::from_black_alpha(10));
        }
        let square = Rect::from_min_size(
            Pos2::new(rect.left() + 7.0, rect.center().y - 12.0),
            Vec2::splat(24.0),
        );
        if on {
            p.rect_filled(square, CornerRadius::same(6), ACCENT_WEAK);
        }
        icon.paint(p, square.shrink(4.0), if on { ACCENT } else { MUTED });
        let font = if on {
            FontId::new(14.0, semibold())
        } else {
            FontId::proportional(14.0)
        };
        let ink = if on { INK } else { TEXT };
        p.text(
            Pos2::new(square.right() + 10.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            name,
            font,
            ink,
        );
        if let Some(n) = count {
            p.text(
                Pos2::new(rect.right() - 10.0, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                n.to_string(),
                FontId::proportional(13.0),
                MUTED,
            );
        }
    }
    resp
}

/// A white button with a hairline edge, an icon and a label.
pub fn button(ui: &mut Ui, icon: Icon, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((
            icon.atom(15.0),
            RichText::new(text).family(semibold()).size(13.0).color(INK),
        ))
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .min_size(Vec2::new(0.0, 34.0)),
    )
}

/// The filled blue button with an icon before its label.
pub fn primary_icon(ui: &mut Ui, enabled: bool, icon: Icon, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((
            icon.atom_in(15.0, Color32::WHITE),
            RichText::new(text).family(semibold()).color(Color32::WHITE),
        ))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 36.0)),
    )
}

/// A red outline button for an action that removes something.
pub fn danger(ui: &mut Ui, icon: Icon, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((
            icon.atom_in(15.0, ERROR),
            RichText::new(text)
                .family(semibold())
                .size(13.0)
                .color(ERROR),
        ))
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, Color32::from_rgb(0xF1, 0xC4, 0xC0)))
        .min_size(Vec2::new(0.0, 34.0)),
    )
}

/// One of a few choices stacked in a column, with a muted line under its
/// name. The chosen one is white with an accent edge.
pub fn choice_row(ui: &mut Ui, on: bool, name: &str, about: &str) -> egui::Response {
    let w = ui.available_width();
    // The line under the name wraps, and the row grows to fit it.
    let about = ui.painter().layout(
        about.to_owned(),
        FontId::proportional(12.0),
        MUTED,
        (w - 24.0).max(10.0),
    );
    let h = (about.size().y + 38.0).max(54.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    resp.widget_info(|| WidgetInfo::selected(egui::Role::Button, true, on, name));
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        if on {
            p.rect_filled(
                rect.translate(Vec2::new(0.0, 1.0)),
                CornerRadius::same(9),
                Color32::from_black_alpha(14),
            );
            p.rect(
                rect,
                CornerRadius::same(9),
                SURFACE,
                Stroke::new(1.0, ACCENT),
                egui::StrokeKind::Inside,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, CornerRadius::same(9), Color32::from_black_alpha(10));
        }
        let x = rect.left() + 12.0;
        let top = rect.center().y - (about.size().y + 20.0) / 2.0;
        p.text(
            Pos2::new(x, top),
            egui::Align2::LEFT_TOP,
            name,
            FontId::new(14.0, semibold()),
            INK,
        );
        p.galley(Pos2::new(x, top + 20.0), about, MUTED);
    }
    resp
}

/// A row of the Ctrl K palette. An item ("title\nsubtitle") gets its
/// letter tile and two lines; an action is one line. The highlighted row
/// says Enter runs it.
pub fn palette_row(ui: &mut Ui, on: bool, text: &str) -> egui::Response {
    let item = text.split_once('\n');
    let w = ui.available_width();
    let h = if item.is_some() { 50.0 } else { 38.0 };
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    resp.widget_info(|| WidgetInfo::selected(egui::Role::Button, true, on, text));
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        if on {
            p.rect_filled(rect, CornerRadius::same(9), ACCENT_WEAK);
        } else if resp.hovered() {
            p.rect_filled(rect, CornerRadius::same(9), HOVER);
        }
        let cy = rect.center().y;
        match item {
            Some((title, sub)) => {
                let tile = Rect::from_min_size(
                    Pos2::new(rect.left() + 10.0, cy - 15.0),
                    Vec2::splat(30.0),
                );
                paint_monogram(ui, tile, title);
                let x = tile.right() + 12.0;
                p.text(
                    Pos2::new(x, cy - 8.0),
                    egui::Align2::LEFT_CENTER,
                    title,
                    FontId::new(14.0, semibold()),
                    INK,
                );
                p.text(
                    Pos2::new(x, cy + 10.0),
                    egui::Align2::LEFT_CENTER,
                    sub,
                    FontId::proportional(12.0),
                    MUTED,
                );
            }
            None => {
                p.text(
                    Pos2::new(rect.left() + 12.0, cy),
                    egui::Align2::LEFT_CENTER,
                    text,
                    FontId::proportional(14.0),
                    INK,
                );
            }
        }
        if on {
            p.text(
                Pos2::new(rect.right() - 12.0, cy),
                egui::Align2::RIGHT_CENTER,
                "Enter",
                FontId::monospace(12.0),
                ACCENT_DARK,
            );
        }
    }
    resp
}

/// A row of the item list: letter tile, title over a muted second line,
/// tags on the right. Screen readers get "title\nsubtitle tags".
pub fn item_row(
    ui: &mut Ui,
    on: bool,
    title: &str,
    subtitle: &str,
    tags: &[&str],
) -> egui::Response {
    let w = ui.available_width();
    // Lay the text out first: a long title takes a second line and the row
    // grows to fit it, rather than cutting the title short.
    let tag_w: f32 = tags
        .iter()
        .map(|t| {
            ui.painter()
                .layout_no_wrap((*t).to_owned(), FontId::new(11.0, semibold()), INK)
                .size()
                .x
                + 16.0
        })
        .sum();
    let room = (w - 10.0 - 36.0 - 12.0 - tag_w - 16.0).max(10.0);
    let layout = |text: &str, font: FontId, color: Color32, rows: usize| {
        let mut job = egui::text::LayoutJob::single_section(
            text.to_owned(),
            egui::TextFormat::simple(font, color),
        );
        job.wrap = egui::text::TextWrapping {
            max_width: room,
            max_rows: rows,
            break_anywhere: false,
            overflow_character: Some('…'),
        };
        ui.painter().layout_job(job)
    };
    let t = layout(title, FontId::new(14.0, semibold()), INK, 2);
    let s = (!subtitle.is_empty()).then(|| layout(subtitle, FontId::proportional(12.0), MUTED, 1));
    let text_h = t.size().y + s.as_ref().map_or(0.0, |s| 2.0 + s.size().y);
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(w, (text_h + 18.0).max(56.0)), Sense::click());
    let mut label = title.to_owned();
    if !subtitle.is_empty() {
        label = format!("{label}\n{subtitle}");
    }
    if !tags.is_empty() {
        label = format!("{label} {}", tags.join(" · "));
    }
    resp.widget_info(|| WidgetInfo::selected(egui::Role::Button, true, on, &label));
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        if on {
            p.rect_filled(rect, CornerRadius::same(8), ACCENT_WEAK);
        } else if resp.hovered() {
            p.rect_filled(rect, CornerRadius::same(8), HOVER);
        }
        let tile = Rect::from_min_size(
            Pos2::new(rect.left() + 10.0, rect.center().y - 18.0),
            Vec2::splat(36.0),
        );
        paint_monogram(ui, tile, title);
        let mut right = rect.right() - 10.0;
        for t in tags.iter().rev() {
            let bg = if on { SURFACE } else { ACCENT_WEAK };
            right = paint_tag(ui, right, rect.center().y, t, ACCENT_DARK, bg) - 4.0;
        }
        let x = tile.right() + 12.0;
        let y = rect.center().y - text_h / 2.0;
        let below = y + t.size().y + 2.0;
        ui.painter().galley(Pos2::new(x, y), t, INK);
        if let Some(s) = s {
            ui.painter().galley(Pos2::new(x, below), s, MUTED);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_fit_the_screen() {
        let want = Vec2::new(1180.0, 760.0);
        let min = Vec2::new(760.0, 480.0);
        // 1920x1080 at 150%: 1280x720 points, so the height must shrink.
        let s = fitted_size(Vec2::new(1280.0, 720.0), want, min);
        assert_eq!(s, Vec2::new(1180.0, 624.0));
        // A big screen keeps the size asked for.
        assert_eq!(fitted_size(Vec2::new(2560.0, 1440.0), want, min), want);
        // A tiny one still gets the minimum.
        assert_eq!(fitted_size(Vec2::new(800.0, 500.0), want, min), min);
    }
}
