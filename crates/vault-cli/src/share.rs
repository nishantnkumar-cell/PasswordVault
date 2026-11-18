//! `vault share`: shared collections for a family (docs/sharing.md, user
//! guide chapter 17). Needs cloud sync, which carries the collections.

use vault_cloud::share;
use vault_ipc::{CollectionInfo, Request, Response};

use crate::{Client, die, item_id, print_qr};

const USAGE: &str = "usage: vault share card [--name NAME] | list | create NAME | add COLLECTION CARD [--name NAME] \
     | invite COLLECTION | join LINK | remove COLLECTION MEMBER | leave COLLECTION | move ITEM COLLECTION|--mine";

fn ok<T>(r: vault_cloud::Result<T>) -> T {
    r.unwrap_or_else(|e| die(e))
}

fn call(c: &mut Client) -> impl FnMut(Request) -> vault_cloud::Result<Response> + '_ {
    |r| Ok(c.try_call(r))
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).map(|i| {
        rest.get(i + 1)
            .cloned()
            .unwrap_or_else(|| die(format!("{name} needs a value")))
    })
}

fn arg(rest: &[String], i: usize) -> &str {
    rest.get(i)
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .unwrap_or_else(|| die(USAGE))
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

/// A collection by name (any case) or by the start of its ID.
fn pick<'a>(list: &'a [CollectionInfo], s: &str) -> &'a CollectionInfo {
    let by_name: Vec<_> = list
        .iter()
        .filter(|c| c.name.eq_ignore_ascii_case(s))
        .collect();
    let found: Vec<_> = if by_name.is_empty() {
        list.iter()
            .filter(|c| s.len() >= 4 && hex(&c.id).starts_with(&s.to_lowercase()))
            .collect()
    } else {
        by_name
    };
    match found.as_slice() {
        [c] => c,
        [] => die(format!(
            "no shared collection called {s:?}; see `vault share list`"
        )),
        _ => die(format!(
            "more than one shared collection matches {s:?}; use the start of its ID from `vault share list`"
        )),
    }
}

fn print(list: &[CollectionInfo]) {
    if list.is_empty() {
        println!("No shared collections. Make one with `vault share create NAME`.");
        return;
    }
    for c in list {
        println!(
            "{}  {}  ({} item{}{})",
            &hex(&c.id)[..8],
            c.name,
            c.items,
            if c.items == 1 { "" } else { "s" },
            if c.owner { ", you made it" } else { "" }
        );
        for (i, m) in c.members.iter().enumerate() {
            println!(
                "    {}{}  safety code {}  member {}",
                m.name,
                if i == 0 { " (owner)" } else { "" },
                m.safety,
                &hex(&m.fingerprint)[..8]
            );
        }
        if let Some(e) = &c.error {
            println!("    problem: {e}");
        }
    }
}

pub fn share(rest: &[String]) {
    let sub = rest.first().map(String::as_str).unwrap_or("list");
    let rest = rest.get(1..).unwrap_or_default();
    let mut c = Client::connect();
    match sub {
        "card" => {
            let card = ok(share::card(&mut call(&mut c), flag(rest, "--name")));
            println!("{}", card.card);
            eprintln!();
            eprintln!(
                "This is {}'s sharing card. Send it to the person who makes the shared collection.",
                card.name
            );
            eprintln!(
                "When they add you, read each other this safety code (in person or on a call): {}",
                card.safety
            );
        }
        "list" => print(&ok(share::list(&mut call(&mut c)))),
        "create" => {
            let name = rest.join(" ");
            if name.trim().is_empty() {
                die("usage: vault share create NAME");
            }
            print(&ok(share::create(&mut call(&mut c), &name)));
        }
        "add" => {
            let list = ok(share::list(&mut call(&mut c)));
            let id = pick(&list, arg(rest, 0)).id;
            let card = arg(rest, 1).to_owned();
            let name = flag(rest, "--name").unwrap_or_default();
            let (link, minutes, list) = ok(share::add(&mut call(&mut c), id, &name, &card));
            let col = list
                .iter()
                .find(|x| x.id == id)
                .unwrap_or_else(|| die("gone"));
            let added = col.members.last().unwrap_or_else(|| die("no members"));
            println!(
                "Added {}. Compare this safety code with them before you send the link: {}",
                added.name, added.safety
            );
            print_qr(&link);
            println!("{}", *link);
            eprintln!(
                "They open it with `vault share join '<link>'` or on the app's Sharing page. It works once, for {minutes} minutes."
            );
        }
        "invite" => {
            let list = ok(share::list(&mut call(&mut c)));
            let (link, minutes) = ok(share::invite(pick(&list, arg(rest, 0))));
            print_qr(&link);
            println!("{}", *link);
            eprintln!("It works once, for {minutes} minutes, and only for people you added.");
        }
        "join" => {
            let list = ok(share::join(&mut call(&mut c), arg(rest, 0)));
            print(&list);
            eprintln!(
                "Compare the owner's safety code above with them (in person or on a call) before you put anything in it."
            );
        }
        "remove" => {
            let list = ok(share::list(&mut call(&mut c)));
            let col = pick(&list, arg(rest, 0));
            let who = arg(rest, 1).to_lowercase();
            let m = col
                .members
                .iter()
                .skip(1)
                .find(|m| {
                    m.name.eq_ignore_ascii_case(&who) || hex(&m.fingerprint).starts_with(&who)
                })
                .unwrap_or_else(|| die(format!("no member {who:?} in {}", col.name)));
            let (id, fp, name) = (col.id, m.fingerprint, m.name.clone());
            ok(share::remove(&mut call(&mut c), id, fp));
            println!(
                "Removed {name}. The collection has a new key; they keep only what they already had."
            );
        }
        "leave" => {
            let list = ok(share::list(&mut call(&mut c)));
            let col = pick(&list, arg(rest, 0));
            let (id, owner) = (col.id, col.owner);
            ok(share::leave(&mut call(&mut c), id));
            println!(
                "{}",
                if owner {
                    "Deleted the shared collection from the server for everyone. Its items are back in your own vault."
                } else {
                    "Left the shared collection. Its items are no longer on your devices."
                }
            );
        }
        "move" => {
            let item = item_id(&mut c, arg(rest, 0));
            let to = if rest.iter().any(|a| a == "--mine") {
                None
            } else {
                let list = ok(share::list(&mut call(&mut c)));
                Some(pick(&list, arg(rest, 1)).id)
            };
            c.call(Request::MoveItem { id: item, to });
            println!(
                "{}",
                if to.is_some() {
                    "Moved into the shared collection."
                } else {
                    "Moved back to your own vault."
                }
            );
        }
        _ => die(USAGE),
    }
}
