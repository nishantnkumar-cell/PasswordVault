//! `vault-gui`: desktop app for `vaultd`.

#![forbid(unsafe_code)]
// No console window behind the app in release builds (debug builds keep it for logs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use vault_gui::{App, Paths, SystemClip};

struct Window(App);

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.show(ui);
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Secret Vault")
            .with_app_id("dev.passwordvault.app")
            .with_inner_size([1180.0, 740.0])
            .with_min_inner_size([760.0, 480.0]),
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
            Ok(Box::new(Window(app)))
        }),
    )
}
