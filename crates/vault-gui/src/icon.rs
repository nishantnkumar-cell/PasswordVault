//! Line icons drawn with the painter, so no image files or icon font are
//! needed. Each icon is a few strokes on a 24 by 24 grid, scaled to the size
//! asked for and drawn in the colour of the text next to it.

use std::f32::consts::TAU;

use eframe::egui::{self, Color32, Painter, Pos2, Rect, Shape, Stroke, Vec2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// All items.
    Grid,
    /// Logins.
    Key,
    Note,
    Card,
    Identity,
    /// One-time codes.
    Clock,
    /// SSH and PGP keys.
    Terminal,
    /// The password generator.
    Dice,
    Import,
    Export,
    /// OpenPGP tools: encrypt and sign.
    Mail,
    /// Sign.
    Signature,
    /// Decrypt.
    Unlocked,
    /// Unlock methods.
    Shield,
    Sync,
    Lock,
    Search,
    Plus,
    ChevronDown,
    Eye,
    EyeOff,
    Copy,
    Pencil,
    Trash,
    Check,
    ArrowLeft,
    ArrowRight,
    /// A computer's TPM chip.
    Chip,
}

/// One stroke of an icon, in grid units.
enum Part {
    Path(&'static [(f32, f32)], bool),
    Circle(f32, f32, f32),
    Dot(f32, f32, f32),
    Rect(f32, f32, f32, f32, f32),
    /// Centre, radius, start and end angle in turns (0 = right, 0.25 = down).
    Arc(f32, f32, f32, f32, f32),
}

use Part::*;

impl Icon {
    fn parts(self) -> &'static [Part] {
        match self {
            Icon::Grid => &[
                Rect(3.0, 3.0, 7.0, 7.0, 1.5),
                Rect(14.0, 3.0, 7.0, 7.0, 1.5),
                Rect(3.0, 14.0, 7.0, 7.0, 1.5),
                Rect(14.0, 14.0, 7.0, 7.0, 1.5),
            ],
            Icon::Key => &[
                Circle(8.0, 15.0, 4.5),
                Path(&[(11.2, 11.8), (20.0, 3.0)], false),
                Path(&[(16.5, 6.5), (19.5, 9.5)], false),
            ],
            Icon::Note => &[
                Path(
                    &[
                        (6.0, 3.0),
                        (14.5, 3.0),
                        (19.0, 7.5),
                        (19.0, 21.0),
                        (6.0, 21.0),
                    ],
                    true,
                ),
                Path(&[(9.0, 12.0), (16.0, 12.0)], false),
                Path(&[(9.0, 16.0), (14.0, 16.0)], false),
            ],
            Icon::Card => &[
                Rect(2.5, 5.0, 19.0, 14.0, 2.0),
                Path(&[(2.5, 10.0), (21.5, 10.0)], false),
                Path(&[(6.5, 15.0), (10.0, 15.0)], false),
            ],
            Icon::Identity => &[
                Circle(9.0, 8.5, 3.8),
                Arc(9.0, 21.5, 6.5, 0.5, 1.0),
                Path(&[(15.5, 8.0), (21.0, 8.0)], false),
                Path(&[(15.5, 12.0), (21.0, 12.0)], false),
                Path(&[(17.5, 16.0), (21.0, 16.0)], false),
            ],
            Icon::Clock => &[
                Circle(12.0, 13.0, 8.0),
                Path(&[(12.0, 9.0), (12.0, 13.0), (14.5, 15.5)], false),
                Path(&[(9.0, 2.5), (15.0, 2.5)], false),
            ],
            Icon::Terminal => &[
                Rect(3.0, 4.0, 18.0, 16.0, 2.0),
                Path(&[(7.0, 9.0), (10.0, 12.0), (7.0, 15.0)], false),
                Path(&[(13.0, 15.0), (17.0, 15.0)], false),
            ],
            Icon::Dice => &[
                Rect(3.5, 3.5, 17.0, 17.0, 3.5),
                Dot(8.5, 8.5, 1.5),
                Dot(15.5, 8.5, 1.5),
                Dot(12.0, 12.0, 1.5),
                Dot(8.5, 15.5, 1.5),
                Dot(15.5, 15.5, 1.5),
            ],
            Icon::Import => &[
                Path(&[(12.0, 3.0), (12.0, 14.5)], false),
                Path(&[(7.5, 10.0), (12.0, 14.5), (16.5, 10.0)], false),
                Path(
                    &[(4.0, 15.0), (4.0, 20.0), (20.0, 20.0), (20.0, 15.0)],
                    false,
                ),
            ],
            Icon::Export => &[
                Path(&[(12.0, 14.5), (12.0, 3.0)], false),
                Path(&[(7.5, 7.5), (12.0, 3.0), (16.5, 7.5)], false),
                Path(
                    &[(4.0, 15.0), (4.0, 20.0), (20.0, 20.0), (20.0, 15.0)],
                    false,
                ),
            ],
            Icon::Mail => &[
                Rect(3.0, 5.5, 18.0, 13.0, 2.0),
                Path(&[(3.5, 7.0), (12.0, 13.0), (20.5, 7.0)], false),
            ],
            Icon::Signature => &[
                Path(
                    &[
                        (3.5, 15.0),
                        (6.0, 9.0),
                        (8.0, 15.5),
                        (10.5, 10.0),
                        (12.0, 14.5),
                        (13.5, 12.5),
                        (15.0, 14.0),
                    ],
                    false,
                ),
                Path(&[(3.5, 19.5), (20.5, 19.5)], false),
            ],
            Icon::Unlocked => &[
                Rect(4.5, 10.5, 15.0, 10.5, 2.0),
                Arc(12.0, 7.5, 3.8, 0.5, 1.0),
                Path(&[(8.2, 7.5), (8.2, 10.5)], false),
            ],
            Icon::Shield => &[
                Path(
                    &[
                        (12.0, 3.0),
                        (20.0, 6.0),
                        (20.0, 11.5),
                        (17.8, 16.6),
                        (12.0, 21.0),
                        (6.2, 16.6),
                        (4.0, 11.5),
                        (4.0, 6.0),
                    ],
                    true,
                ),
                Path(&[(9.0, 12.0), (11.2, 14.2), (15.2, 10.2)], false),
            ],
            Icon::Sync => &[
                Arc(12.0, 12.0, 7.5, 0.55, 0.95),
                Path(&[(19.2, 6.0), (19.4, 10.1), (15.4, 9.6)], false),
                Arc(12.0, 12.0, 7.5, 0.05, 0.45),
                Path(&[(4.8, 18.0), (4.6, 13.9), (8.6, 14.4)], false),
            ],
            Icon::Lock => &[
                Rect(4.5, 10.5, 15.0, 10.5, 2.0),
                Arc(12.0, 7.5, 3.8, 0.5, 1.0),
                Path(&[(8.2, 7.5), (8.2, 10.5)], false),
                Path(&[(15.8, 7.5), (15.8, 10.5)], false),
            ],
            Icon::Search => &[
                Circle(11.0, 11.0, 6.5),
                Path(&[(15.8, 15.8), (20.0, 20.0)], false),
            ],
            Icon::Plus => &[
                Path(&[(12.0, 5.0), (12.0, 19.0)], false),
                Path(&[(5.0, 12.0), (19.0, 12.0)], false),
            ],
            Icon::ChevronDown => &[Path(&[(6.0, 9.0), (12.0, 15.0), (18.0, 9.0)], false)],
            Icon::Eye => &[
                Arc(12.0, 18.0, 10.0, 0.6024, 0.8976),
                Arc(12.0, 6.0, 10.0, 0.1024, 0.3976),
                Circle(12.0, 12.0, 3.0),
            ],
            Icon::EyeOff => &[
                Arc(12.0, 18.0, 10.0, 0.6024, 0.8976),
                Arc(12.0, 6.0, 10.0, 0.1024, 0.3976),
                Circle(12.0, 12.0, 3.0),
                Path(&[(4.0, 4.0), (20.0, 20.0)], false),
            ],
            Icon::Copy => &[
                Rect(9.0, 9.0, 12.0, 12.0, 2.0),
                Path(
                    &[
                        (15.0, 9.0),
                        (15.0, 5.0),
                        (3.0, 5.0),
                        (3.0, 15.0),
                        (9.0, 15.0),
                    ],
                    false,
                ),
            ],
            Icon::Pencil => &[
                Path(
                    &[
                        (4.0, 20.0),
                        (4.5, 16.0),
                        (15.5, 5.0),
                        (19.0, 8.5),
                        (8.0, 19.5),
                    ],
                    true,
                ),
                Path(&[(13.0, 7.5), (16.5, 11.0)], false),
            ],
            Icon::Trash => &[
                Path(&[(4.0, 6.5), (20.0, 6.5)], false),
                Path(&[(9.5, 6.5), (9.5, 3.5), (14.5, 3.5), (14.5, 6.5)], false),
                Path(&[(6.0, 6.5), (7.0, 21.0), (17.0, 21.0), (18.0, 6.5)], false),
                Path(&[(10.0, 10.5), (10.0, 17.0)], false),
                Path(&[(14.0, 10.5), (14.0, 17.0)], false),
            ],
            Icon::Check => &[Path(&[(5.0, 12.5), (9.5, 17.0), (19.0, 7.5)], false)],
            Icon::Chip => &[
                Rect(6.5, 6.5, 11.0, 11.0, 2.0),
                Rect(9.5, 9.5, 5.0, 5.0, 1.0),
                Path(&[(10.0, 3.0), (10.0, 6.5)], false),
                Path(&[(14.0, 3.0), (14.0, 6.5)], false),
                Path(&[(10.0, 17.5), (10.0, 21.0)], false),
                Path(&[(14.0, 17.5), (14.0, 21.0)], false),
                Path(&[(3.0, 10.0), (6.5, 10.0)], false),
                Path(&[(3.0, 14.0), (6.5, 14.0)], false),
                Path(&[(17.5, 10.0), (21.0, 10.0)], false),
                Path(&[(17.5, 14.0), (21.0, 14.0)], false),
            ],
            Icon::ArrowLeft => &[
                Path(&[(19.0, 12.0), (5.0, 12.0)], false),
                Path(&[(11.0, 6.0), (5.0, 12.0), (11.0, 18.0)], false),
            ],
            Icon::ArrowRight => &[
                Path(&[(5.0, 12.0), (19.0, 12.0)], false),
                Path(&[(13.0, 6.0), (19.0, 12.0), (13.0, 18.0)], false),
            ],
        }
    }

    /// Draw the icon filling `rect` (best square) in `color`.
    pub fn paint(self, painter: &Painter, rect: Rect, color: Color32) {
        let size = rect.width().min(rect.height());
        let u = size / 24.0;
        let o = rect.center() - Vec2::splat(size / 2.0);
        let at = |x: f32, y: f32| o + Vec2::new(x, y) * u;
        let stroke = Stroke::new((1.9 * u).max(1.3), color);
        for part in self.parts() {
            match *part {
                Path(pts, closed) => {
                    let pts: Vec<Pos2> = pts.iter().map(|&(x, y)| at(x, y)).collect();
                    if closed {
                        painter.add(Shape::closed_line(pts, stroke));
                    } else {
                        painter.add(Shape::line(pts, stroke));
                    }
                }
                Circle(x, y, r) => {
                    painter.circle_stroke(at(x, y), r * u, stroke);
                }
                Dot(x, y, r) => {
                    painter.circle_filled(at(x, y), r * u, color);
                }
                Rect(x, y, w, h, r) => {
                    painter.rect_stroke(
                        egui::Rect::from_min_size(at(x, y), Vec2::new(w, h) * u),
                        r * u,
                        stroke,
                        egui::StrokeKind::Middle,
                    );
                }
                Arc(x, y, r, from, to) => {
                    let n = 20;
                    let pts: Vec<Pos2> = (0..=n)
                        .map(|i| {
                            let a = TAU * (from + (to - from) * i as f32 / n as f32);
                            at(x, y) + Vec2::new(a.cos(), a.sin()) * r * u
                        })
                        .collect();
                    painter.add(Shape::line(pts, stroke));
                }
            }
        }
    }

    /// The icon as a piece of a button, drawn in the button's text colour.
    pub fn atom(self, size: f32) -> egui::Atom<'static> {
        egui::Atom::paint(Vec2::splat(size), move |ui, args| {
            self.paint(ui.painter(), args.rect, args.fallback_text_color);
        })
    }

    /// The icon as a piece of a button, in a colour of its own.
    pub fn atom_in(self, size: f32, color: Color32) -> egui::Atom<'static> {
        egui::Atom::paint(Vec2::splat(size), move |ui, args| {
            self.paint(ui.painter(), args.rect, color);
        })
    }

    /// Draw the icon on its own, taking up `size` in the layout.
    pub fn show(self, ui: &mut egui::Ui, size: f32, color: Color32) {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
        self.paint(ui.painter(), rect, color);
    }
}
