//! `vault-prompt`: the approval window `vaultd` opens (pairing, key use). Exit status
//! 0 means Allow, 1 Deny (or no answer in time), 2 the window could not open.

#![forbid(unsafe_code)]
// A window only: no console behind it when vaultd runs in the background.
#![windows_subsystem = "windows"]

use std::cell::Cell;
use std::rc::Rc;

use eframe::egui;
use vault_gui::prompt::{Prompt, Request};

struct Window(Prompt, Rc<Cell<Option<bool>>>);

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.0.show(ui) {
            self.1.set(self.0.answer);
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = Request::from_args(&args).unwrap_or_else(|e| {
        eprintln!("vault-prompt: {e}");
        std::process::exit(2)
    });
    let answer = Rc::new(Cell::new(None));
    let a = answer.clone();
    let title = request.title();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id("dev.passwordvault.prompt")
            .with_icon(vault_gui::window_icon())
            .with_inner_size([460.0, 280.0])
            .with_resizable(false)
            .with_always_on_top(),
        centered: true,
        ..Default::default()
    };
    let r = eframe::run_native(
        "Secret Vault approval",
        options,
        Box::new(move |_| Ok(Box::new(Window(Prompt::new(request), a)))),
    );
    if let Err(e) = r {
        eprintln!("vault-prompt: {e}");
        std::process::exit(2);
    }
    std::process::exit(if answer.get() == Some(true) { 0 } else { 1 })
}
