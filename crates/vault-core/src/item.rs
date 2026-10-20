//! Item data model (`docs/items.md`). Stored as the opaque item payload of a
//! vault record, encoded with postcard.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::origin::MatchMode;
use crate::totp::TotpConfig;

/// Version tags of the item payload, so the schema can evolve independently
/// of the file format. Schema 1 held logins only; schema 2 added
/// [`ItemData::key`]; schema 3 added kinds, cards, identities and custom
/// fields. Older items are still read and are upgraded when next saved.
const ITEM_SCHEMA_V1: u8 = 1;
const ITEM_SCHEMA_V2: u8 = 2;
const ITEM_SCHEMA_V3: u8 = 3;

/// What an item holds.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// Username, password, websites and an optional TOTP seed.
    #[default]
    Login,
    /// Text only.
    Note,
    /// A payment card.
    Card,
    /// Name, address and contact details for filling forms.
    Identity,
}

impl ItemKind {
    /// Every kind, in display order.
    pub const ALL: [ItemKind; 4] = [
        ItemKind::Login,
        ItemKind::Note,
        ItemKind::Card,
        ItemKind::Identity,
    ];

    /// Lowercase name for tools and wire formats.
    pub fn name(self) -> &'static str {
        match self {
            ItemKind::Login => "login",
            ItemKind::Note => "note",
            ItemKind::Card => "card",
            ItemKind::Identity => "identity",
        }
    }

    /// Display name.
    pub fn label(self) -> &'static str {
        match self {
            ItemKind::Login => "Login",
            ItemKind::Note => "Secure note",
            ItemKind::Card => "Card",
            ItemKind::Identity => "Identity",
        }
    }

    /// Parse [`Self::name`].
    pub fn from_name(s: &str) -> Option<ItemKind> {
        ItemKind::ALL.into_iter().find(|k| k.name() == s)
    }
}

/// One stored item. Which parts are used depends on `kind`; see
/// [`ItemData::normalize`]. Zeroized on drop.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemData {
    /// What this item is.
    #[zeroize(skip)]
    pub kind: ItemKind,
    /// Display name.
    pub title: String,
    /// Account name (logins).
    pub username: String,
    /// Password (logins).
    pub password: String,
    /// Sites this login may be filled on (logins).
    pub urls: Vec<UrlEntry>,
    /// TOTP seed and parameters, if any (logins).
    pub totp: Option<TotpConfig>,
    /// Payment card details (cards).
    pub card: Option<Card>,
    /// Name and address (identities).
    pub identity: Option<Identity>,
    /// Extra fields the user added.
    pub fields: Vec<CustomField>,
    /// Free-form notes.
    pub notes: String,
    /// Seconds since the Unix epoch.
    pub created: u64,
    /// Seconds since the Unix epoch.
    pub modified: u64,
    /// A private key the daemon uses on the user's behalf. Set only through
    /// the daemon's key requests, never returned to clients.
    pub key: Option<KeyData>,
}

/// A private key held in the vault. Stored unencrypted inside the item: the
/// vault's own encryption protects it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Zeroize)]
pub enum KeyData {
    /// An SSH key, in OpenSSH private key format without a passphrase.
    Ssh {
        /// The `-----BEGIN OPENSSH PRIVATE KEY-----` text.
        openssh: String,
        /// Ask the user before each use.
        confirm: bool,
    },
    /// An OpenPGP transferable secret key, binary, without a passphrase.
    OpenPgp {
        /// The secret key packets.
        tsk: Vec<u8>,
        /// Ask the user before each signature or decryption.
        confirm: bool,
    },
}

impl KeyData {
    /// Whether each use needs the user's approval.
    pub fn confirm(&self) -> bool {
        match self {
            KeyData::Ssh { confirm, .. } | KeyData::OpenPgp { confirm, .. } => *confirm,
        }
    }

    /// Change whether each use needs the user's approval.
    pub fn set_confirm(&mut self, on: bool) {
        match self {
            KeyData::Ssh { confirm, .. } | KeyData::OpenPgp { confirm, .. } => *confirm = on,
        }
    }
}

/// A URL an item is bound to, with its matching mode.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct UrlEntry {
    /// URL as entered; matched by origin, path ignored.
    pub url: String,
    /// How strictly to match.
    #[zeroize(skip)]
    pub mode: MatchMode,
    /// Permit filling over plain `http` for this entry (off by default).
    pub allow_http: bool,
}

/// A payment card.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Zeroize)]
pub struct Card {
    /// Name on the card.
    pub holder: String,
    /// Card number, digits only.
    pub number: String,
    /// Expiry month, 1..=12, or 0 if not set.
    pub exp_month: u8,
    /// Four-digit expiry year, or 0 if not set.
    pub exp_year: u16,
    /// Security code.
    pub cvv: String,
    /// PIN.
    pub pin: String,
}

/// Card networks recognised from the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardBrand {
    /// Visa.
    Visa,
    /// Mastercard.
    Mastercard,
    /// American Express.
    Amex,
    /// Discover.
    Discover,
    /// JCB.
    Jcb,
    /// Diners Club.
    DinersClub,
    /// UnionPay.
    UnionPay,
    /// Maestro.
    Maestro,
}

impl CardBrand {
    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            CardBrand::Visa => "Visa",
            CardBrand::Mastercard => "Mastercard",
            CardBrand::Amex => "American Express",
            CardBrand::Discover => "Discover",
            CardBrand::Jcb => "JCB",
            CardBrand::DinersClub => "Diners Club",
            CardBrand::UnionPay => "UnionPay",
            CardBrand::Maestro => "Maestro",
        }
    }
}

impl Card {
    /// Keep only the digits of a number as typed ("4111 1111-1111 1111").
    pub fn clean_number(s: &str) -> String {
        s.chars().filter(char::is_ascii_digit).collect()
    }

    /// The network, from the number's issuer prefix.
    pub fn brand(&self) -> Option<CardBrand> {
        let n = &self.number;
        let p = |len: usize| n.get(..len).and_then(|s| s.parse::<u32>().ok());
        let in_range = |len, lo, hi| p(len).is_some_and(|v| (lo..=hi).contains(&v));
        Some(if n.starts_with('4') {
            CardBrand::Visa
        } else if in_range(2, 51, 55) || in_range(4, 2221, 2720) {
            CardBrand::Mastercard
        } else if in_range(2, 34, 34) || in_range(2, 37, 37) {
            CardBrand::Amex
        } else if n.starts_with("6011") || n.starts_with("65") || in_range(3, 644, 649) {
            CardBrand::Discover
        } else if in_range(4, 3528, 3589) {
            CardBrand::Jcb
        } else if in_range(3, 300, 305) || in_range(2, 36, 36) || in_range(2, 38, 39) {
            CardBrand::DinersClub
        } else if n.starts_with("62") {
            CardBrand::UnionPay
        } else if in_range(2, 50, 50) || in_range(2, 56, 69) {
            CardBrand::Maestro
        } else {
            return None;
        })
    }

    /// The number passes the Luhn check. A typo check, not proof of a real card.
    pub fn luhn_ok(&self) -> bool {
        let digits: Vec<u32> = self.number.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() < 12 || digits.len() != self.number.len() {
            return false;
        }
        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| match (i % 2, d * 2) {
                (0, _) => d,
                (_, dd) if dd > 9 => dd - 9,
                (_, dd) => dd,
            })
            .sum();
        sum.is_multiple_of(10)
    }

    /// The last four digits, for display.
    pub fn last4(&self) -> &str {
        let n = &self.number;
        n.get(n.len().saturating_sub(4)..).unwrap_or("")
    }

    /// "MM/YYYY", or empty if not set.
    pub fn expiry(&self) -> String {
        match (self.exp_month, self.exp_year) {
            (0, 0) => String::new(),
            (m, y) => format!("{m:02}/{y:04}"),
        }
    }

    /// Parse "MM/YY", "MM/YYYY", "MM-YY" or "MMYY" into (month, four-digit year).
    pub fn parse_expiry(s: &str) -> Option<(u8, u16)> {
        let s = s.trim();
        let (m, y) = match s.split_once(['/', '-', ' ']) {
            Some((m, y)) => (m.trim(), y.trim()),
            None if s.len() == 4 || s.len() == 6 => s.split_at(2),
            None => return None,
        };
        let m: u8 = m.parse().ok().filter(|m| (1..=12).contains(m))?;
        let y: u16 = match y.len() {
            2 => 2000 + y.parse::<u16>().ok()?,
            4 => y.parse().ok().filter(|y| (2000..=2199).contains(y))?,
            _ => return None,
        };
        Some((m, y))
    }

    /// "Visa •••• 1111", or "Card" when there is no number yet.
    pub fn describe(&self) -> String {
        let brand = self.brand().map_or("Card", CardBrand::name);
        if self.number.len() >= 4 {
            format!("{brand} \u{2022}\u{2022}\u{2022}\u{2022} {}", self.last4())
        } else {
            brand.to_owned()
        }
    }
}

/// Name, contact and address details.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Zeroize)]
pub struct Identity {
    /// Mr, Ms, Dr, ...
    pub honorific: String,
    /// First name.
    pub given_name: String,
    /// Middle name.
    pub middle_name: String,
    /// Last name.
    pub family_name: String,
    /// Company.
    pub company: String,
    /// Email address.
    pub email: String,
    /// Phone number.
    pub phone: String,
    /// Address, first line.
    pub address1: String,
    /// Address, second line.
    pub address2: String,
    /// Address, third line.
    pub address3: String,
    /// City or town.
    pub city: String,
    /// State, province or county.
    pub region: String,
    /// Postcode or ZIP code.
    pub postcode: String,
    /// Country.
    pub country: String,
}

impl Identity {
    /// Given, middle and family name joined with spaces.
    pub fn full_name(&self) -> String {
        [&self.given_name, &self.middle_name, &self.family_name]
            .into_iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// One line for lists: the name, else the email.
    pub fn describe(&self) -> String {
        let name = self.full_name();
        if name.is_empty() {
            self.email.clone()
        } else {
            name
        }
    }
}

/// How a custom field is shown.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FieldKind {
    /// Shown as typed.
    #[default]
    Text,
    /// Hidden until revealed, like a password.
    Hidden,
    /// A link.
    Url,
}

/// A field the user added to an item.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Zeroize)]
pub struct CustomField {
    /// Label.
    pub name: String,
    /// Value.
    pub value: String,
    /// How it is shown.
    #[zeroize(skip)]
    pub kind: FieldKind,
}

/// Schema 1 payload, read for upgrading only.
#[derive(Serialize, Deserialize, Default)]
struct ItemDataV1 {
    title: String,
    username: String,
    password: String,
    urls: Vec<UrlEntry>,
    totp: Option<TotpConfig>,
    notes: String,
    created: u64,
    modified: u64,
}

impl Drop for ItemDataV1 {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.urls.zeroize();
        self.notes.zeroize();
    }
}

/// How [`crate::Vault::merge`] treats items: of two concurrent edits, the
/// later `modified` time wins, and the other edit is kept as a copy titled
/// "... (conflict)".
pub struct ItemMerge;

impl crate::Resolve for ItemMerge {
    fn rank(&self, data: &[u8]) -> i64 {
        ItemData::from_bytes(data)
            .map_or(i64::MIN, |i| i64::try_from(i.modified).unwrap_or(i64::MAX))
    }

    fn conflict_copy(&self, data: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        match ItemData::from_bytes(data) {
            Ok(mut item) => {
                item.title.push_str(" (conflict)");
                item.to_bytes()
            }
            Err(_) => zeroize::Zeroizing::new(data.to_vec()),
        }
    }
}

/// Schema 2 payload: schema 1 plus a key. Read for upgrading only.
#[derive(Serialize, Deserialize, Default)]
struct ItemDataV2 {
    title: String,
    username: String,
    password: String,
    urls: Vec<UrlEntry>,
    totp: Option<TotpConfig>,
    notes: String,
    created: u64,
    modified: u64,
    key: Option<KeyData>,
}

impl Drop for ItemDataV2 {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.urls.zeroize();
        self.notes.zeroize();
        self.key.zeroize();
    }
}

impl ItemData {
    /// An empty item of `kind`. (`ItemData` zeroizes on drop, so struct
    /// update syntax is not available; start here and set fields.)
    pub fn new(kind: ItemKind, title: impl Into<String>) -> ItemData {
        let mut item = ItemData::default();
        item.kind = kind;
        item.title = title.into();
        item
    }

    /// Encode for [`crate::Vault::put_item`].
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(vec![ITEM_SCHEMA_V3]);
        out.extend_from_slice(&crate::format::encode(self));
        out
    }

    /// Decode bytes from [`crate::Vault::get_item`]. Schema 1 and 2 items
    /// come back as logins.
    pub fn from_bytes(bytes: &[u8]) -> Result<ItemData, Error> {
        match bytes.split_first() {
            Some((&ITEM_SCHEMA_V3, rest)) => {
                crate::format::decode_canonical(rest).map_err(|_| Error::CorruptItem)
            }
            Some((&ITEM_SCHEMA_V2, rest)) => {
                let mut v2: ItemDataV2 =
                    crate::format::decode_canonical(rest).map_err(|_| Error::CorruptItem)?;
                let mut item = ItemData::new(ItemKind::Login, std::mem::take(&mut v2.title));
                item.username = std::mem::take(&mut v2.username);
                item.password = std::mem::take(&mut v2.password);
                item.urls = std::mem::take(&mut v2.urls);
                item.totp = v2.totp.take();
                item.notes = std::mem::take(&mut v2.notes);
                item.created = v2.created;
                item.modified = v2.modified;
                item.key = v2.key.take();
                Ok(item)
            }
            Some((&ITEM_SCHEMA_V1, rest)) => {
                let mut v1: ItemDataV1 =
                    crate::format::decode_canonical(rest).map_err(|_| Error::CorruptItem)?;
                let mut item = ItemData::new(ItemKind::Login, std::mem::take(&mut v1.title));
                item.username = std::mem::take(&mut v1.username);
                item.password = std::mem::take(&mut v1.password);
                item.urls = std::mem::take(&mut v1.urls);
                item.totp = v1.totp.take();
                item.notes = std::mem::take(&mut v1.notes);
                item.created = v1.created;
                item.modified = v1.modified;
                Ok(item)
            }
            _ => Err(Error::CorruptItem),
        }
    }

    /// Make the item consistent with its kind: a card has card details and an
    /// identity has identity details, and parts another kind uses are cleared
    /// so no secret hides where no screen shows it. Card numbers keep only
    /// their digits.
    pub fn normalize(&mut self) {
        if self.kind != ItemKind::Login {
            self.username.zeroize();
            self.password.zeroize();
            self.urls.zeroize();
            self.urls.clear();
            self.totp = None;
        }
        match self.kind {
            ItemKind::Card => {
                let card = self.card.get_or_insert_with(Card::default);
                card.number = Card::clean_number(&card.number);
            }
            _ => self.card = None,
        }
        match self.kind {
            ItemKind::Identity => {
                self.identity.get_or_insert_with(Identity::default);
            }
            _ => self.identity = None,
        }
        self.fields
            .retain(|f| !f.name.trim().is_empty() || !f.value.is_empty());
    }

    /// One line for lists, never a secret: the username, the card's network
    /// and last four digits, or the identity's name.
    pub fn subtitle(&self) -> String {
        match self.kind {
            ItemKind::Login => self.username.clone(),
            ItemKind::Note => String::new(),
            ItemKind::Card => self.card.as_ref().map(Card::describe).unwrap_or_default(),
            ItemKind::Identity => self
                .identity
                .as_ref()
                .map(Identity::describe)
                .unwrap_or_default(),
        }
    }

    /// A copy holding only what a form fill needs: the card or identity, with
    /// notes and custom fields left out.
    pub fn for_form_fill(&self) -> ItemData {
        let mut item = ItemData::new(self.kind, self.title.clone());
        item.card = self.card.clone();
        item.identity = self.identity.clone();
        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(number: &str) -> Card {
        Card {
            number: number.into(),
            ..Card::default()
        }
    }

    #[test]
    fn schema_1_items_read_as_logins() {
        let mut v1 = ItemDataV1::default();
        v1.title = "t".into();
        v1.username = "u".into();
        v1.notes = "n".into();
        v1.created = 5;
        v1.modified = 6;
        let mut bytes = vec![ITEM_SCHEMA_V1];
        bytes.extend_from_slice(&crate::format::encode(&v1));
        let item = ItemData::from_bytes(&bytes).unwrap();
        assert_eq!(item.kind, ItemKind::Login);
        assert_eq!((item.title.as_str(), item.username.as_str()), ("t", "u"));
        assert_eq!(
            (item.notes.as_str(), item.created, item.modified),
            ("n", 5, 6)
        );
        // Saved again, it is schema 3 and reads back the same.
        let again = item.to_bytes();
        assert_eq!(again[0], ITEM_SCHEMA_V3);
        assert!(ItemData::from_bytes(&again).unwrap() == item);
        assert!(ItemData::from_bytes(&[9, 0]).is_err());
    }

    #[test]
    fn schema_2_items_keep_their_key() {
        let mut v2 = ItemDataV2::default();
        v2.title = "deploy key".into();
        v2.modified = 6;
        v2.key = Some(KeyData::Ssh {
            openssh: "k".into(),
            confirm: true,
        });
        let mut bytes = vec![ITEM_SCHEMA_V2];
        bytes.extend_from_slice(&crate::format::encode(&v2));
        let item = ItemData::from_bytes(&bytes).unwrap();
        assert_eq!(item.kind, ItemKind::Login);
        assert_eq!((item.title.as_str(), item.modified), ("deploy key", 6));
        assert!(item.key.as_ref().is_some_and(KeyData::confirm));
        assert!(ItemData::from_bytes(&item.to_bytes()).unwrap() == item);
    }

    #[test]
    fn every_kind_round_trips() {
        let mut item = ItemData::new(ItemKind::Card, "Travel card");
        item.card = Some(Card {
            holder: "A Person".into(),
            number: "4111111111111111".into(),
            exp_month: 7,
            exp_year: 2031,
            cvv: "123".into(),
            pin: String::new(),
        });
        item.fields = vec![CustomField {
            name: "Bank".into(),
            value: "x".into(),
            kind: FieldKind::Hidden,
        }];
        assert!(ItemData::from_bytes(&item.to_bytes()).unwrap() == item);
    }

    #[test]
    fn normalize_keeps_only_what_the_kind_uses() {
        let mut item = ItemData::new(ItemKind::Card, "");
        item.password = "leftover".into();
        item.identity = Some(Identity::default());
        item.card = Some(card("4111 1111-1111 1111"));
        item.fields = vec![CustomField::default()];
        item.normalize();
        assert!(item.password.is_empty() && item.identity.is_none());
        assert_eq!(item.card.as_ref().unwrap().number, "4111111111111111");
        assert!(item.fields.is_empty());

        let mut note = ItemData::new(ItemKind::Identity, "");
        note.normalize();
        assert!(note.identity.is_some() && note.card.is_none());
    }

    #[test]
    fn cards_are_described_and_checked() {
        let visa = card("4111111111111111");
        assert_eq!(visa.brand(), Some(CardBrand::Visa));
        assert!(visa.luhn_ok());
        assert_eq!(
            visa.describe(),
            "Visa \u{2022}\u{2022}\u{2022}\u{2022} 1111"
        );
        assert!(!card("4111111111111112").luhn_ok());
        assert!(!card("4111").luhn_ok());
        assert_eq!(
            card("5500005555555559").brand(),
            Some(CardBrand::Mastercard)
        );
        assert_eq!(
            card("2221000000000009").brand(),
            Some(CardBrand::Mastercard)
        );
        assert_eq!(card("378282246310005").brand(), Some(CardBrand::Amex));
        assert_eq!(card("6011111111111117").brand(), Some(CardBrand::Discover));
        assert_eq!(card("3530111333300000").brand(), Some(CardBrand::Jcb));
        assert_eq!(card("9999").brand(), None);
        assert_eq!(card("").describe(), "Card");
    }

    #[test]
    fn expiry_dates_parse() {
        assert_eq!(Card::parse_expiry("07/31"), Some((7, 2031)));
        assert_eq!(Card::parse_expiry("7/2031"), Some((7, 2031)));
        assert_eq!(Card::parse_expiry("0731"), Some((7, 2031)));
        assert_eq!(Card::parse_expiry("13/31"), None);
        assert_eq!(Card::parse_expiry("hello"), None);
        let mut c = card("");
        c.exp_month = 7;
        c.exp_year = 2031;
        assert_eq!(c.expiry(), "07/2031");
    }

    #[test]
    fn subtitles_never_show_secrets() {
        let mut item = ItemData::new(ItemKind::Card, "");
        item.card = Some(card("4111111111111111"));
        assert!(!item.subtitle().contains("41111111"));
        item.kind = ItemKind::Identity;
        item.identity = Some(Identity {
            given_name: "Ada".into(),
            family_name: "Lovelace".into(),
            ..Identity::default()
        });
        assert_eq!(item.subtitle(), "Ada Lovelace");
        let mut note = ItemData::new(ItemKind::Note, "");
        note.notes = "secret".into();
        assert_eq!(note.subtitle(), "");
    }

    #[test]
    fn merge_keeps_the_later_edit_and_a_titled_copy() {
        use crate::Resolve;
        let mut a = ItemData::new(ItemKind::Note, "Wifi");
        a.modified = 10;
        let mut b = ItemData::new(ItemKind::Note, "Wifi");
        b.modified = 20;
        assert!(ItemMerge.rank(&b.to_bytes()) > ItemMerge.rank(&a.to_bytes()));
        let copy = ItemData::from_bytes(&ItemMerge.conflict_copy(&a.to_bytes())).unwrap();
        assert_eq!(copy.title, "Wifi (conflict)");
        assert_eq!(copy.modified, 10);
    }
}
