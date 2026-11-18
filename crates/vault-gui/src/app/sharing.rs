//! The Sharing page (docs/sharing.md, user guide chapter 17): this person's
//! sharing card and safety code, shared collections with their members, and
//! the steps to make one, add or remove a person, join with an invite link
//! and leave. The network steps are vault_cloud::share, run on the worker
//! thread; this file only draws and collects the forms.

use std::sync::{Arc, Mutex};

use eframe::egui::{self, RichText, Ui};
use vault_cloud::share;
use vault_ipc::{CollectionInfo, Request, Response, Secret};

use super::{App, Op, page_header, qr_code, secret_field, status_dot, text_field};
use crate::client::Work;
use crate::theme::{self, Icon};

/// An invite link to show: the link, its minutes, who it is for and their
/// safety code.
#[derive(Clone)]
pub struct Invite {
    pub link: Secret,
    pub minutes: u64,
    pub who: String,
    pub safety: Option<String>,
}

/// What the worker hands back besides vaultd's answer.
#[derive(Default)]
pub struct Out {
    pub invite: Option<Invite>,
    pub list: Option<Vec<CollectionInfo>>,
}

#[derive(Default)]
pub struct SharingPage {
    /// This person's card, once there is one.
    pub card: Option<(String, String, String)>,
    /// True when vaultd says there is no sharing identity yet.
    pub no_card: bool,
    pub list: Option<Vec<CollectionInfo>>,
    pub out: Arc<Mutex<Out>>,
    pub my_name: String,
    pub new_name: String,
    /// The collection the Add form is open for.
    pub add_to: Option<[u8; 16]>,
    pub add_card: String,
    pub add_name: String,
    pub join_link: Secret,
    pub confirm_leave: Option<[u8; 16]>,
    pub confirm_remove: Option<([u8; 16], [u8; 32])>,
}

impl SharingPage {
    /// Forgets what was read and typed (on lock).
    pub fn wipe(&mut self) {
        *self = SharingPage::default();
    }
}

impl App {
    /// Asks vaultd for this person's card and collections (when the page
    /// opens and after each step).
    pub(super) fn sharing_refresh(&mut self) {
        self.send(Op::SharingCard, Request::SharingIdentity { name: None });
        self.send(Op::Collections, Request::Collections);
    }

    fn share_work(&mut self, busy: &'static str, done: &'static str, job: crate::client::CloudJob) {
        self.act_work(busy, Op::Sharing(done), Work::Cloud(job));
    }

    /// True when the error is vaultd saying there is no sharing card yet,
    /// which the page shows as the form to make one.
    pub(super) fn on_sharing_error(&mut self, op: Op, m: &str) -> bool {
        if op == Op::SharingCard && m.contains("give the name") {
            self.sharing.no_card = true;
            self.sharing.card = None;
            return true;
        }
        false
    }

    pub(super) fn on_sharing_result(&mut self, op: Op, r: Response) {
        match (op, r) {
            (
                Op::SharingCard,
                Response::SharingCard {
                    name, card, safety, ..
                },
            ) => {
                self.sharing.no_card = false;
                self.sharing.card = Some((name, card, safety));
            }
            (Op::Collections, Response::Collections(c)) => self.sharing.list = Some(c),
            (Op::Sharing(done), r) => {
                self.sharing.join_link = Secret::default();
                if !done.is_empty() {
                    self.notice = Some(done.into());
                }
                if let Response::Collections(c) = r {
                    self.sharing.list = Some(c);
                }
                if let Some(c) = self.sharing.out.lock().ok().and_then(|mut o| o.list.take()) {
                    self.sharing.list = Some(c);
                }
                self.send(Op::SharingCard, Request::SharingIdentity { name: None });
                self.send(Op::ListItems, Request::ListItems);
            }
            (Op::MoveItem(to), Response::ItemSaved { id }) => {
                self.notice = Some(
                    if to.is_some() {
                        "Moved into the shared collection. Everyone in it sees it after the next sync."
                    } else {
                        "Moved back to your own vault. Only you see it now."
                    }
                    .into(),
                );
                self.send(Op::ListItems, Request::ListItems);
                self.send(Op::Collections, Request::Collections);
                self.select(id);
            }
            _ => {}
        }
    }

    pub(super) fn sharing_page(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Sharing",
            "Share some items with family: a shared collection is a small vault of its own \
             that only the people in it can open. Everything else stays in your own vault, \
             where only you can see it. Shared collections travel through cloud sync.",
        );
        let ok = self.busy.is_none();
        self.my_card(ui, ok);
        if self.sharing.card.is_none() {
            return;
        }
        self.invite_box(ui);
        let list = self.sharing.list.clone().unwrap_or_default();
        for c in &list {
            ui.add_space(12.0);
            self.collection_card(ui, c, ok);
        }
        ui.add_space(12.0);
        self.new_collection_card(ui, ok);
    }

    fn my_card(&mut self, ui: &mut Ui, ok: bool) {
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::caption(ui, "Your sharing card");
            let Some((name, card, safety)) = self.sharing.card.clone() else {
                if !self.sharing.no_card {
                    ui.spinner();
                    return;
                }
                ui.label(
                    RichText::new(
                        "To share, first make your sharing card. It holds only public keys, so \
                         it is safe to send by email or chat. Pick the name your family will \
                         see you as.",
                    )
                    .color(theme::MUTED),
                );
                ui.add_space(6.0);
                egui::Grid::new("share-me").num_columns(2).show(ui, |ui| {
                    text_field(ui, "Your name", &mut self.sharing.my_name);
                    ui.end_row();
                });
                ui.add_space(6.0);
                let name = self.sharing.my_name.trim().to_owned();
                let ready = ok && !name.is_empty();
                if theme::primary(ui, ready, "Make my sharing card").clicked() && ready {
                    self.act(
                        "Making your keys…",
                        Op::SharingCard,
                        Request::SharingIdentity { name: Some(name) },
                    );
                }
                return;
            };
            ui.label(
                RichText::new(format!(
                    "Send this to the person who makes a shared collection, so they can add \
                     you as {name}. It holds only public keys."
                ))
                .color(theme::MUTED),
            );
            ui.add_space(6.0);
            egui::Grid::new("share-card")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Name").color(theme::MUTED));
                    ui.label(RichText::new(&name).color(theme::INK));
                    ui.end_row();
                    ui.label(RichText::new("Safety code").color(theme::MUTED));
                    ui.label(RichText::new(&safety).monospace().color(theme::INK));
                    ui.end_row();
                });
            ui.add_space(6.0);
            if theme::button(ui, Icon::Copy, "Copy my card").clicked() {
                self.copy(&card, "Sharing card");
            }
            ui.add_space(10.0);
            theme::caption(ui, "Join a shared collection");
            ui.label(
                RichText::new(
                    "Once they have added you, they send you an invite link. Paste it here.",
                )
                .color(theme::MUTED),
            );
            let mut go = false;
            egui::Grid::new("share-join").num_columns(2).show(ui, |ui| {
                go |= secret_field(ui, "Invite link", &mut self.sharing.join_link);
                ui.end_row();
            });
            let ready = ok && !self.sharing.join_link.trim().is_empty();
            if (theme::primary(ui, ready, "Join").clicked() || go) && ready {
                let link = self.sharing.join_link.clone();
                self.share_work(
                    "Joining…",
                    "Joined. Compare the owner's safety code below with them, in person or \
                     on a call, before you put anything in it.",
                    Box::new(move |call| share::join(call, &link).map(Response::Collections)),
                );
            }
        });
    }

    fn invite_box(&mut self, ui: &mut Ui) {
        let Some(inv) = self.sharing.out.lock().ok().and_then(|o| o.invite.clone()) else {
            return;
        };
        ui.add_space(12.0);
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::caption(ui, &format!("Invite link for {}", inv.who));
            if let Some(s) = &inv.safety {
                ui.label(
                    RichText::new(format!(
                        "First read each other this safety code, in person or on a call. If \
                         theirs is different, do not send the link: {s}"
                    ))
                    .color(theme::INK),
                );
                ui.add_space(6.0);
            }
            ui.label(format!(
                "They paste it on their Sharing page (Join), or run vault share join with it. \
                 It works once, for {} minutes, and only for people you added.",
                inv.minutes
            ));
            ui.add_space(6.0);
            qr_code(ui, &inv.link);
            ui.add(
                egui::Label::new(
                    RichText::new(&*inv.link)
                        .monospace()
                        .size(11.5)
                        .color(theme::INK),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                if theme::button(ui, Icon::Copy, "Copy link").clicked() {
                    self.copy(&inv.link, "Invite link");
                }
                if ui.button("Done").clicked()
                    && let Ok(mut o) = self.sharing.out.lock()
                {
                    o.invite = None;
                }
            });
        });
    }

    fn collection_card(&mut self, ui: &mut Ui, c: &CollectionInfo, ok: bool) {
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                status_dot(
                    ui,
                    if c.error.is_some() {
                        theme::ERROR
                    } else {
                        theme::OK
                    },
                );
                ui.label(
                    RichText::new(&c.name)
                        .family(theme::semibold())
                        .color(theme::INK),
                );
                ui.label(
                    RichText::new(format!(
                        "{} item{}{}",
                        c.items,
                        if c.items == 1 { "" } else { "s" },
                        if c.owner { ", you made it" } else { "" }
                    ))
                    .color(theme::MUTED),
                );
            });
            ui.add_space(8.0);
            let mut remove = None;
            egui::Grid::new(("share-members", c.id))
                .num_columns(3)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for (i, m) in c.members.iter().enumerate() {
                        let who = if i == 0 {
                            format!("{} (owner)", m.name)
                        } else {
                            m.name.clone()
                        };
                        ui.label(RichText::new(who).color(theme::INK));
                        ui.label(
                            RichText::new(format!("safety code {}", m.safety))
                                .monospace()
                                .size(11.5)
                                .color(theme::MUTED),
                        );
                        if c.owner && i > 0 {
                            if self.sharing.confirm_remove == Some((c.id, m.fingerprint)) {
                                ui.horizontal(|ui| {
                                    if theme::danger(ui, Icon::Trash, "Yes, remove").clicked() && ok
                                    {
                                        remove = Some((m.fingerprint, m.name.clone()));
                                    }
                                    if ui.button("Cancel").clicked() {
                                        self.sharing.confirm_remove = None;
                                    }
                                });
                            } else if ui.add_enabled(ok, egui::Button::new("Remove")).clicked() {
                                self.sharing.confirm_remove = Some((c.id, m.fingerprint));
                            }
                        } else {
                            ui.label("");
                        }
                        ui.end_row();
                    }
                });
            if let Some((fp, _)) = remove {
                self.sharing.confirm_remove = None;
                let id = c.id;
                self.share_work(
                    "Removing and changing the collection's key…",
                    "Removed. The collection has a new key; they keep only what they \
                     already had.",
                    Box::new(move |call| share::remove(call, id, fp).map(Response::Collections)),
                );
            }
            if let Some(e) = &c.error {
                ui.add_space(6.0);
                ui.colored_label(theme::ERROR, format!("Problem: {e}"));
            }
            ui.add_space(8.0);
            if c.owner {
                self.add_member_form(ui, c, ok);
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "To put an item in it, open the item and use Move to. Every item in it \
                     can be seen and changed by everyone in it.",
                )
                .small()
                .color(theme::MUTED),
            );
            ui.add_space(6.0);
            let (ask, button, busy, done) = if c.owner {
                (
                    "Delete this shared collection for everyone? Its items come back into \
                     your own vault; the others lose them.",
                    "Delete for everyone",
                    "Deleting…",
                    "Deleted from the server for everyone. Its items are back in your own vault.",
                )
            } else {
                (
                    "Leave this shared collection? Its items go from your devices; the others \
                     keep them.",
                    "Leave",
                    "Leaving…",
                    "Left the shared collection.",
                )
            };
            if self.sharing.confirm_leave == Some(c.id) {
                ui.colored_label(theme::ERROR, ask);
                ui.horizontal(|ui| {
                    if theme::danger(ui, Icon::Trash, button).clicked() && ok {
                        self.sharing.confirm_leave = None;
                        let id = c.id;
                        self.share_work(
                            busy,
                            done,
                            Box::new(move |call| share::leave(call, id).map(Response::Collections)),
                        );
                    }
                    if ui.button("Cancel").clicked() {
                        self.sharing.confirm_leave = None;
                    }
                });
            } else if ui
                .add_enabled(ok, egui::Button::new(format!("{button}…")))
                .clicked()
            {
                self.sharing.confirm_leave = Some(c.id);
            }
        });
    }

    fn add_member_form(&mut self, ui: &mut Ui, c: &CollectionInfo, ok: bool) {
        if self.sharing.add_to != Some(c.id) {
            ui.horizontal_wrapped(|ui| {
                if theme::primary_icon(ui, ok, Icon::Plus, "Add a person").clicked() && ok {
                    self.sharing.add_to = Some(c.id);
                    self.sharing.add_card.clear();
                    self.sharing.add_name.clear();
                }
                if ui
                    .add_enabled(ok, egui::Button::new("New invite link"))
                    .on_hover_text("For someone already added whose link ran out")
                    .clicked()
                {
                    let out = self.sharing.out.clone();
                    let c = c.clone();
                    self.share_work(
                        "Making an invite link…",
                        "",
                        Box::new(move |_: &mut vault_cloud::flows::Call<'_>| {
                            let (link, minutes) = share::invite(&c)?;
                            if let Ok(mut o) = out.lock() {
                                o.invite = Some(Invite {
                                    link,
                                    minutes,
                                    who: "the people you added".into(),
                                    safety: None,
                                });
                            }
                            Ok(Response::Ok)
                        }),
                    );
                }
            });
            return;
        }
        theme::caption(ui, "Add a person");
        ui.label(
            RichText::new(
                "Paste the sharing card they sent you (they find it on their Sharing page, or \
                 with vault share card).",
            )
            .color(theme::MUTED),
        );
        ui.add(
            egui::TextEdit::multiline(&mut self.sharing.add_card)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace)
                .hint_text("svcard1.…"),
        );
        egui::Grid::new(("share-add", c.id))
            .num_columns(2)
            .show(ui, |ui| {
                text_field(ui, "Name (optional)", &mut self.sharing.add_name);
                ui.end_row();
            });
        ui.add_space(6.0);
        let ready = ok && !self.sharing.add_card.trim().is_empty();
        ui.horizontal(|ui| {
            if theme::primary(ui, ready, "Add and make an invite link").clicked() && ready {
                let (id, card, name) = (
                    c.id,
                    self.sharing.add_card.trim().to_owned(),
                    self.sharing.add_name.trim().to_owned(),
                );
                self.sharing.add_to = None;
                let out = self.sharing.out.clone();
                self.share_work(
                    "Adding and wrapping the key for them…",
                    "Added. Compare the safety code with them, then send the link.",
                    Box::new(move |call| {
                        let (link, minutes, list) = share::add(call, id, &name, &card)?;
                        let added = list
                            .iter()
                            .find(|x| x.id == id)
                            .and_then(|x| x.members.last())
                            .map(|m| (m.name.clone(), m.safety.clone()));
                        if let Ok(mut o) = out.lock() {
                            o.invite = Some(Invite {
                                link,
                                minutes,
                                who: added.as_ref().map_or_else(String::new, |a| a.0.clone()),
                                safety: added.map(|a| a.1),
                            });
                        }
                        Ok(Response::Collections(list))
                    }),
                );
            }
            if ui.button("Cancel").clicked() {
                self.sharing.add_to = None;
            }
        });
    }

    fn new_collection_card(&mut self, ui: &mut Ui, ok: bool) {
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::caption(ui, "Make a shared collection");
            let own_server = self
                .cloud
                .info
                .as_ref()
                .is_some_and(|i| i.settings.is_some() && i.device.is_some());
            if !own_server {
                ui.label(
                    RichText::new(
                        "Making one needs cloud sync set up on this computer (Sync page), since \
                         it is kept on your sync server. Joining someone else's does not.",
                    )
                    .color(theme::MUTED),
                );
                return;
            }
            ui.label(
                RichText::new(
                    "It is kept on your sync server. You decide who is in it: only you can add \
                     or remove people.",
                )
                .color(theme::MUTED),
            );
            egui::Grid::new("share-new").num_columns(2).show(ui, |ui| {
                text_field(ui, "Name", &mut self.sharing.new_name);
                ui.end_row();
            });
            ui.add_space(6.0);
            let name = self.sharing.new_name.trim().to_owned();
            let ready = ok && !name.is_empty();
            if theme::primary_icon(ui, ready, Icon::Plus, "Make it").clicked() && ready {
                self.sharing.new_name.clear();
                self.share_work(
                    "Making the shared collection…",
                    "Made. Add the people it is for.",
                    Box::new(move |call| share::create(call, &name).map(Response::Collections)),
                );
            }
        });
    }

    /// The Move to row on an open item: into one of the shared collections,
    /// or back into this person's own vault.
    pub(super) fn move_to(&mut self, ui: &mut Ui, id: vault_ipc::ItemId) {
        let list = self.sharing.list.clone().unwrap_or_default();
        if list.is_empty() {
            return;
        }
        let here = self
            .items
            .iter()
            .find(|i| i.id == id)
            .and_then(|i| i.collection.clone());
        let ok = self.busy.is_none();
        let mut to = None;
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(match &here {
                    Some((_, n)) => format!("In the shared collection {n}."),
                    None => "Only in your own vault.".into(),
                })
                .color(theme::MUTED),
            );
            egui::ComboBox::from_id_salt(("move-to", id))
                .selected_text("Move to…")
                .show_ui(ui, |ui| {
                    if here.is_some() && ui.selectable_label(false, "My own vault").clicked() {
                        to = Some(None);
                    }
                    for c in &list {
                        if here.as_ref().is_some_and(|(h, _)| *h == c.id) || c.error.is_some() {
                            continue;
                        }
                        if ui.selectable_label(false, &c.name).clicked() {
                            to = Some(Some(c.id));
                        }
                    }
                });
        });
        if let Some(to) = to
            && ok
        {
            self.act("Moving…", Op::MoveItem(to), Request::MoveItem { id, to });
        }
    }
}
