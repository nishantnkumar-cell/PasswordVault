//! Autofill origin policy (brief section 12).
//!
//! The page origin must come from the browser (the extension background's
//! `sender` data), never from page content. This module only decides whether
//! a stored URL may be filled on that origin.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::item::UrlEntry;

/// How a stored URL matches a page.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MatchMode {
    /// Scheme, host and port must all be equal. The default.
    #[default]
    Origin,
    /// Same registrable domain (eTLD+1) under the public suffix list, over
    /// `https`. Opt-in per item, for sites that span subdomains.
    RegistrableDomain,
}

/// A parsed, normalized web origin. Hosts are lowercase punycode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// `https` or `http`.
    pub scheme: String,
    /// Normalized host (punycode for internationalized names).
    pub host: String,
    /// Effective port (default ports filled in).
    pub port: u16,
    is_domain: bool,
}

impl Origin {
    /// Parse a URL or origin string. Only `http` and `https` are accepted.
    pub fn parse(s: &str) -> Option<Origin> {
        let u = Url::parse(s.trim()).ok()?;
        let scheme = u.scheme().to_owned();
        if scheme != "https" && scheme != "http" {
            return None;
        }
        let (host, is_domain) = match u.host()? {
            // `url` applies UTS-46 processing, so domains are already
            // lowercase punycode here.
            Host::Domain(d) => (d.trim_end_matches('.').to_owned(), true),
            Host::Ipv4(a) => (a.to_string(), false),
            Host::Ipv6(a) => (format!("[{a}]"), false),
        };
        if host.is_empty() {
            return None;
        }
        Some(Origin {
            scheme,
            host,
            port: u.port_or_known_default()?,
            is_domain,
        })
    }

    /// The registrable domain (eTLD+1), if the host has one.
    pub fn registrable_domain(&self) -> Option<&str> {
        if !self.is_domain {
            return None;
        }
        psl::domain_str(&self.host)
    }

    /// Whether any label is punycode, so the UI should show a homograph warning
    /// next to the Unicode form.
    pub fn has_punycode(&self) -> bool {
        self.host.split('.').any(|l| l.starts_with("xn--"))
    }
}

/// Decide whether `entry` may be filled on the page at `page_origin`.
pub fn may_fill(entry: &UrlEntry, page_origin: &str) -> bool {
    let (Some(stored), Some(page)) = (Origin::parse(&entry.url), Origin::parse(page_origin)) else {
        return false;
    };
    if page.scheme == "http" && !(entry.allow_http && stored.scheme == "http") {
        return false;
    }
    match entry.mode {
        MatchMode::Origin => stored == page,
        MatchMode::RegistrableDomain => {
            if page.scheme != "https" || stored.scheme != "https" {
                return stored == page;
            }
            match (stored.registrable_domain(), page.registrable_domain()) {
                (Some(a), Some(b)) => a == b,
                // IP addresses and bare public suffixes match exactly or not at all.
                _ => stored == page,
            }
        }
    }
}
