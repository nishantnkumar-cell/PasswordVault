//! `vault-gui`: desktop app for `vaultd`.

#![forbid(unsafe_code)]
// No console window behind the app in release builds (debug builds keep it for logs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use vault_gui::{App, Paths, SystemClip};

/// The size the window opens at, and the smallest it can be made.
const SIZE: [f32; 2] = [1180.0, 760.0];
const MIN_SIZE: [f32; 2] = [760.0, 480.0];

struct Window(App, bool);

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.1 {
            // Shrink to the screen's free area on small or scaled displays.
            self.1 = vault_gui::theme::fit_to_screen(ui.ctx(), SIZE.into(), MIN_SIZE.into());
        }
        self.0.show(ui);
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Secret Vault")
            .with_app_id("dev.passwordvault.app")
            .with_icon(vault_gui::window_icon())
            .with_inner_size(SIZE)
            .with_min_inner_size(MIN_SIZE),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Secret Vault",
        options,
        Box::new(|cc| {
            let ctx = cc.egui_ctx.clone();
            let app = App::new(
                Paths::from_env(),
                Box::new(SystemClip::default()),
                move || ctx.request_repaint(),
            );
            Ok(Box::new(Window(app, false)))
        }),
    )
}
