//! The Cloud sync card on the Sync page (docs/cloud-sync.md, user guide
//! chapters 15 and 16): set up a sync server in the user's Cloudflare
//! account or on their own computer, add devices with a one-time link, list
//! and remove them, and turn it off. The steps are vault_cloud::flows, run
//! on the worker thread; this file only draws and collects the form.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui::{self, RichText, Ui};
use vault_cloud::flows::{self, Host};
use vault_cloud::{DeviceInfo, OwnCa};
use vault_ipc::{CloudInfo, Request, Response, Secret};

use super::{App, Op, ago, qr_code, secret_field, status_dot, text_field};
use crate::client::Work;
use crate::theme::{self, Icon};

/// Where the server goes, on the setup form.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Where {
    #[default]
    Cloudflare,
    Own,
    Join,
}

/// What the worker hands back besides vaultd's answer.
#[derive(Default)]
pub struct Out {
    pub link: Option<(Secret, u64)>,
    pub devices: Option<Vec<DeviceInfo>>,
}

#[derive(Default)]
pub struct CloudPage {
    /// The last CloudGet answer.
    pub info: Option<CloudInfo>,
    pub out: Arc<Mutex<Out>>,
    pub place: Where,
    pub account: String,
    pub token: Secret,
    pub keep_token: bool,
    pub server: String,
    pub fingerprint: String,
    pub admin_key: Secret,
    pub link: Secret,
    pub name: String,
    pub confirm_everywhere: bool,
}

impl CloudPage {
    /// Forgets the typed secrets and what was read (on lock).
    pub fn wipe(&mut self) {
        let name = std::mem::take(&mut self.name);
        *self = CloudPage {
            name,
            ..CloudPage::default()
        };
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl App {
    /// Asks vaultd for the cloud settings (when the Sync page opens and
    /// after each step).
    pub(super) fn cloud_refresh(&mut self) {
        self.send(Op::CloudInfo, Request::CloudGet);
    }

    fn cloud_work(&mut self, busy: &'static str, done: &'static str, job: crate::client::CloudJob) {
        self.act_work(busy, Op::Cloud(done), Work::Cloud(job));
    }

    pub(super) fn on_cloud_result(&mut self, op: Op, r: Response) {
        match (op, r) {
            (Op::CloudInfo, Response::Cloud(i)) => self.cloud.info = Some(i),
            (Op::Cloud(done), r) => {
                // It worked: the typed secrets are not needed again.
                self.cloud.token = Secret::default();
                self.cloud.admin_key = Secret::default();
                self.cloud.link = Secret::default();
                if !done.is_empty() {
                    self.notice = Some(done.into());
                }
                if let Response::Status(s) = r {
                    self.on_status(s);
                } else {
                    self.refresh();
                }
                // A device that just joined is not paired with this app yet.
                if self.screen == super::Screen::Unlocked {
                    self.cloud_refresh();
                }
            }
            _ => {}
        }
    }

    /// True when cloud sync is on here (the Sync page then shows only it).
    pub(super) fn cloud_on(&self) -> bool {
        self.cloud.info.as_ref().is_some_and(|i| i.device.is_some())
    }

    pub(super) fn cloud_card(&mut self, ui: &mut Ui) {
        let ok = self.busy.is_none();
        let info = self.cloud.info.take();
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            match &info {
                Some(i) if i.device.is_some() => self.cloud_on_card(ui, i, ok),
                _ => self.cloud_off_card(ui, info.as_ref(), ok),
            }
        });
        if self.cloud.info.is_none() {
            self.cloud.info = info;
        }
    }

    fn cloud_off_card(&mut self, ui: &mut Ui, info: Option<&CloudInfo>, ok: bool) {
        ui.horizontal(|ui| {
            status_dot(ui, theme::MUTED);
            ui.label(
                RichText::new("Cloud sync is off")
                    .family(theme::semibold())
                    .color(theme::INK),
            );
        });
        ui.add_space(6.0);
        if info.is_some_and(|i| i.settings.is_some()) {
            ui.label(
                RichText::new(
                    "This vault is set up for cloud sync on another device. To add this \
                     computer, make a link there (Cloud sync, Add a device) and paste it below.",
                )
                .color(theme::MUTED),
            );
            self.cloud.place = Where::Join;
        } else {
            ui.label(
                RichText::new(
                    "Sync through a small server that only ever stores the encrypted vault \
                     file. It runs in your own free Cloudflare account, or on a computer of \
                     yours with Docker.",
                )
                .color(theme::MUTED),
            );
            ui.add_space(8.0);
            for (place, name, about) in [
                (
                    Where::Cloudflare,
                    "My Cloudflare account",
                    "Secret Vault uploads its server there. You need the account ID and an \
                     API token (user guide, chapter 15).",
                ),
                (
                    Where::Own,
                    "A server on my own computer (Docker)",
                    "You started it with docker compose; it shows its address, admin key and \
                     fingerprint (chapter 16).",
                ),
                (
                    Where::Join,
                    "Join with a link from another device",
                    "Cloud sync is already set up on one of your devices.",
                ),
            ] {
                if theme::choice_row(ui, self.cloud.place == place, name, about).clicked() {
                    self.cloud.place = place;
                }
                ui.add_space(4.0);
            }
        }
        ui.add_space(8.0);
        if self.cloud.name.is_empty() {
            self.cloud.name = flows::host_name();
        }
        let c = &mut self.cloud;
        let mut go = false;
        egui::Grid::new("cloud-setup")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                match c.place {
                    Where::Cloudflare => {
                        text_field(ui, "Account ID", &mut c.account);
                        ui.end_row();
                        go |= secret_field(ui, "API token", &mut c.token);
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(
                            &mut c.keep_token,
                            "Keep the token in the vault for server updates",
                        );
                        ui.end_row();
                    }
                    Where::Own => {
                        text_field(ui, "Server address", &mut c.server);
                        ui.end_row();
                        text_field(ui, "Fingerprint", &mut c.fingerprint);
                        ui.end_row();
                        go |= secret_field(ui, "Admin key", &mut c.admin_key);
                        ui.end_row();
                    }
                    Where::Join => {
                        go |= secret_field(ui, "Join link", &mut c.link);
                        ui.end_row();
                    }
                }
                text_field(ui, "This computer's name", &mut c.name);
                ui.end_row();
            });
        if c.place == Where::Own {
            ui.label(
                RichText::new(
                    "For example https://192.168.1.20:8443. Leave the fingerprint empty for a \
                     server with a public certificate.",
                )
                .small()
                .color(theme::MUTED),
            );
        }
        ui.add_space(8.0);
        let ready = ok
            && match c.place {
                Where::Cloudflare => !c.account.trim().is_empty() && !c.token.trim().is_empty(),
                Where::Own => !c.server.trim().is_empty() && !c.admin_key.trim().is_empty(),
                Where::Join => !c.link.trim().is_empty(),
            };
        let label = if c.place == Where::Join {
            "Join"
        } else {
            "Set up"
        };
        if (theme::primary(ui, ready, label).clicked() || go) && ready {
            self.cloud_start();
        }
    }

    /// The join link field and button (the first-run wizard). True when
    /// Join was pressed with a link.
    pub(super) fn cloud_join_form(&mut self, ui: &mut Ui) -> bool {
        let mut go = false;
        egui::Grid::new("cloud-join").num_columns(2).show(ui, |ui| {
            go |= secret_field(ui, "Join link", &mut self.cloud.link);
            ui.end_row();
        });
        let ready = self.busy.is_none() && !self.cloud.link.trim().is_empty();
        (ui.add_enabled(ready, egui::Button::new("Join with the link"))
            .clicked()
            || go)
            && ready
    }

    pub(super) fn cloud_join(&mut self) {
        self.cloud.place = Where::Join;
        if self.cloud.name.trim().is_empty() {
            self.cloud.name = flows::host_name();
        }
        self.cloud_start();
    }

    fn cloud_start(&mut self) {
        let joined = if self.screen == super::Screen::Unlocked {
            "Joined. Start the sync helper on this computer (see below)."
        } else {
            "Joined. Unlock with your master password, then start the sync helper (Sync page)."
        };
        let c = &mut self.cloud;
        let name = c.name.trim().to_owned();
        match c.place {
            Where::Join => {
                let link = c.link.clone();
                self.cloud_work(
                    "Joining…",
                    joined,
                    Box::new(move |call| {
                        flows::join(call, &link, &name).map(|(_, s)| Response::Status(s))
                    }),
                );
            }
            Where::Cloudflare => {
                let host = Host::Cloudflare {
                    account: c.account.trim().to_owned(),
                    token: c.token.clone(),
                    worker: String::new(),
                    keep_token: c.keep_token,
                };
                self.cloud_work(
                    "Uploading the sync server to your Cloudflare account…",
                    "Cloud sync is set up. Start the sync helper on this computer (see below).",
                    Box::new(move |call| {
                        flows::setup(call, host, &name, &|_| {}).map(|_| Response::Ok)
                    }),
                );
            }
            Where::Own => {
                let fp = c.fingerprint.trim().to_owned();
                let host = Host::Own {
                    server: c.server.trim().to_owned(),
                    fingerprint: (!fp.is_empty()).then_some(fp),
                    admin_key: c.admin_key.clone(),
                };
                self.cloud_work(
                    "Connecting to your server…",
                    "Cloud sync is set up. Start the sync helper on this computer (see below).",
                    Box::new(move |call| {
                        flows::setup(call, host, &name, &|_| {}).map(|_| Response::Ok)
                    }),
                );
            }
        }
    }

    fn cloud_on_card(&mut self, ui: &mut Ui, i: &CloudInfo, ok: bool) {
        let Some(d) = &i.device else { return };
        let sync = self.status.as_ref().and_then(|(s, _)| s.sync.clone());
        let problem = sync.as_ref().and_then(|s| s.error.clone());
        let (colour, state) = match &problem {
            Some(_) => (theme::ERROR, "Cloud sync is on, with a problem"),
            None => (theme::OK, "Cloud sync is on"),
        };
        ui.horizontal(|ui| {
            status_dot(ui, colour);
            ui.label(
                RichText::new(state)
                    .family(theme::semibold())
                    .color(theme::INK),
            );
        });
        ui.add_space(10.0);
        let own = d
            .ca_cert
            .as_deref()
            .and_then(|p| OwnCa::from_pem(p).ok())
            .map(|c| c.fingerprint());
        egui::Grid::new("cloud")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                let row = |ui: &mut Ui, k: &str, v: String| {
                    ui.label(RichText::new(k).color(theme::MUTED));
                    ui.add(egui::Label::new(RichText::new(v).color(theme::INK)).wrap());
                    ui.end_row();
                };
                row(ui, "Server", d.server.clone());
                if let Some(s) = &i.settings {
                    row(
                        ui,
                        "Runs in",
                        if s.account_id.is_empty() {
                            "Your own server".into()
                        } else {
                            format!("Your Cloudflare account (Worker \"{}\")", s.worker)
                        },
                    );
                }
                if let Some(f) = &own {
                    row(
                        ui,
                        "Certificate",
                        format!("The server's own, fingerprint {f}"),
                    );
                }
                row(ui, "This device", d.device.clone());
                let (helper, bad) = flows::helper_line(i);
                ui.label(RichText::new("Sync helper").color(theme::MUTED));
                ui.add(
                    egui::Label::new(RichText::new(helper).color(if bad {
                        theme::ERROR
                    } else {
                        theme::INK
                    }))
                    .wrap(),
                );
                ui.end_row();
                row(
                    ui,
                    "Last merged here",
                    match sync.as_ref().and_then(|s| s.last_sync) {
                        Some(t) => ago(now().saturating_sub(t)),
                        None if self.status.as_ref().is_some_and(|(s, _)| !s.unlocked) => {
                            "not while locked".into()
                        }
                        None => "not yet".into(),
                    },
                );
            });
        if let Some(e) = problem {
            ui.add_space(8.0);
            ui.colored_label(theme::ERROR, format!("Problem: {e}"));
        }
        ui.add_space(10.0);
        let info = i.clone();
        ui.horizontal_wrapped(|ui| {
            if theme::primary_icon(ui, ok, Icon::Plus, "Add a device").clicked() && ok {
                let out = self.cloud.out.clone();
                let info = info.clone();
                self.cloud_work(
                    "Making a join link…",
                    "",
                    Box::new(move |_: &mut flows::Call<'_>| {
                        let l = flows::link(&info)?;
                        if let Ok(mut o) = out.lock() {
                            o.link = Some(l);
                        }
                        Ok(Response::Ok)
                    }),
                );
            }
            if ui.add_enabled(ok, egui::Button::new("Devices")).clicked() {
                self.cloud_devices(&info);
            }
            if theme::primary_icon(ui, ok, Icon::Sync, "Sync now").clicked() && ok {
                self.act("Syncing…", Op::Sync, Request::SyncNow);
            }
            if ui
                .add_enabled(ok, egui::Button::new("Turn off on this computer"))
                .clicked()
            {
                self.cloud_work(
                    "Turning off…",
                    "Cloud sync is off on this computer. Its own vault file is unchanged.",
                    Box::new(|call| flows::off(call, false).map(|_| Response::Ok)),
                );
            }
        });
        self.cloud_link(ui);
        self.cloud_device_list(ui, &info, ok);
        ui.add_space(12.0);
        helper_hint(ui);
        if i.settings.is_some() {
            ui.add_space(12.0);
            if self.cloud.confirm_everywhere {
                ui.colored_label(
                    theme::ERROR,
                    "Delete the vault and every device's access from the server? Each device \
                     keeps its own copy.",
                );
                ui.horizontal(|ui| {
                    if theme::danger(ui, Icon::Trash, "Delete from the server").clicked() && ok {
                        self.cloud.confirm_everywhere = false;
                        self.cloud_work(
                            "Deleting from the server…",
                            "Deleted from the server. Cloud sync is off everywhere.",
                            Box::new(|call| flows::off(call, true).map(|_| Response::Ok)),
                        );
                    }
                    if ui.button("Cancel").clicked() {
                        self.cloud.confirm_everywhere = false;
                    }
                });
            } else if ui
                .add_enabled(ok, egui::Button::new("Turn off everywhere…"))
                .clicked()
            {
                self.cloud.confirm_everywhere = true;
            }
        }
    }

    fn cloud_devices(&mut self, info: &CloudInfo) {
        let out = self.cloud.out.clone();
        let info = info.clone();
        self.cloud_work(
            "Asking the server…",
            "",
            Box::new(move |_: &mut flows::Call<'_>| {
                let list = flows::devices(&info)?;
                if let Ok(mut o) = out.lock() {
                    o.devices = Some(list);
                }
                Ok(Response::Ok)
            }),
        );
    }

    fn cloud_link(&mut self, ui: &mut Ui) {
        let Some((link, minutes)) = self.cloud.out.lock().ok().and_then(|o| o.link.clone()) else {
            return;
        };
        ui.add_space(12.0);
        theme::caption(ui, "Add a device");
        ui.label(format!(
            "On the other computer, paste this link in Cloud sync (Join with a link), or run \
             vault cloud join with it. It works once, for {minutes} minutes."
        ));
        ui.add_space(6.0);
        qr_code(ui, &link);
        ui.add(
            egui::Label::new(
                RichText::new(&*link)
                    .monospace()
                    .size(11.5)
                    .color(theme::INK),
            )
            .wrap(),
        );
        ui.horizontal(|ui| {
            if theme::button(ui, Icon::Copy, "Copy link").clicked() {
                self.copy(&link, "Join link");
            }
            if ui.button("Done").clicked()
                && let Ok(mut o) = self.cloud.out.lock()
            {
                o.link = None;
            }
        });
        ui.label(
            RichText::new(
                "Anyone with this link can download the encrypted vault, so send it only to \
                 your own devices.",
            )
            .small()
            .color(theme::MUTED),
        );
    }

    fn cloud_device_list(&mut self, ui: &mut Ui, info: &CloudInfo, ok: bool) {
        let Some(list) = self.cloud.out.lock().ok().and_then(|o| o.devices.clone()) else {
            return;
        };
        ui.add_space(12.0);
        theme::caption(ui, "Devices");
        let mut remove = None;
        egui::Grid::new("cloud-devices")
            .num_columns(4)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                for d in &list {
                    ui.label(RichText::new(&d.name).color(theme::INK));
                    ui.label(RichText::new(&d.id).monospace().color(theme::MUTED));
                    ui.label(
                        RichText::new(format!("seen {}", ago(now().saturating_sub(d.last_seen))))
                            .color(theme::MUTED),
                    );
                    if d.current {
                        ui.label(RichText::new("this device").color(theme::MUTED));
                    } else if ui.add_enabled(ok, egui::Button::new("Remove")).clicked() {
                        remove = Some(d.id.clone());
                    }
                    ui.end_row();
                }
            });
        if let Some(id) = remove {
            let out = self.cloud.out.clone();
            let info = info.clone();
            self.cloud_work(
                "Removing…",
                "Removed. That device can no longer read or save the vault on the server.",
                Box::new(move |_: &mut flows::Call<'_>| {
                    flows::remove(&info, &id)?;
                    let list = flows::devices(&info)?;
                    if let Ok(mut o) = out.lock() {
                        o.devices = Some(list);
                    }
                    Ok(Response::Ok)
                }),
            );
        }
    }
}

/// How to start vault-sync on this system.
fn helper_hint(ui: &mut Ui) {
    let how = if cfg!(windows) {
        "The sync helper, vault-sync.exe, does the network part. Put a shortcut to it in \
         your Startup folder (Win+R, shell:startup) and start it once."
    } else if cfg!(target_os = "macos") {
        "The sync helper, vault-sync, does the network part. Start it in Terminal: vault-sync &"
    } else {
        "The sync helper, vault-sync, does the network part. Start it once with: \
         systemctl --user enable --now vault-sync (or sudo systemctl enable --now \
         vault-sync@$USER next to the system service)."
    };
    ui.label(RichText::new(how).small().color(theme::MUTED));
}
