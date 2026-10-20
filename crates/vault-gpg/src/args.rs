//! gpg's command line, as far as git, pass and mail clients use it.
//!
//! Options may be long (`--local-user KEY`, `--local-user=KEY`) or short
//! clusters (`-bsau KEY`, `-uKEY`). Options that only tune GnuPG itself
//! (trust models, agents, compression) are accepted and ignored.

/// Long options that take a value we have no use for.
const IGNORED_WITH_VALUE: &[&str] = &[
    "agent-program",
    "attribute-fd",
    "auto-key-locate",
    "charset",
    "cipher-algo",
    "command-fd",
    "comment",
    "compress-algo",
    "compress-level",
    "debug-level",
    "default-recipient",
    "digest-algo",
    "display-charset",
    "export-options",
    "faked-system-time",
    "homedir",
    "import-options",
    "keyid-format",
    "keyring",
    "keyserver",
    "keyserver-options",
    "list-options",
    "log-file",
    "logger-fd",
    "options",
    "passphrase",
    "passphrase-fd",
    "passphrase-file",
    "personal-cipher-preferences",
    "personal-compress-preferences",
    "personal-digest-preferences",
    "pinentry-mode",
    "primary-keyring",
    "s2k-cipher-algo",
    "s2k-count",
    "s2k-digest-algo",
    "s2k-mode",
    "secret-keyring",
    "set-filename",
    "trust-model",
    "trustdb-name",
    "trusted-key",
    "verify-options",
    "weak-digest",
];

/// Long switches we accept and ignore.
const IGNORED: &[&str] = &[
    "always-trust",
    "batch",
    "emit-version",
    "enable-progress-filter",
    "exit-on-status-write-error",
    "fixed-list-mode",
    "force-mdc",
    "lock-never",
    "no-auto-check-trustdb",
    "no-auto-key-locate",
    "no-default-keyring",
    "no-emit-version",
    "no-encrypt-to",
    "no-greeting",
    "no-permission-warning",
    "no-secmem-warning",
    "no-sig-cache",
    "no-throw-keyids",
    "no-tty",
    "no-use-agent",
    "no-verbose",
    "throw-keyids",
    "use-agent",
    "utf8-strings",
    "with-fingerprint",
    "with-key-origin",
    "with-keygrip",
    "with-secret",
    "with-subkey-fingerprint",
    "with-subkey-fingerprints",
    "yes",
];

/// gpg commands this front end does not provide, with what to use instead.
const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "clear-sign",
        "clear-signed messages are not supported; use --detach-sign",
    ),
    (
        "clearsign",
        "clear-signed messages are not supported; use --detach-sign",
    ),
    ("symmetric", "password-only encryption is not supported"),
    ("gen-key", "generate keys with `vault pgp new`"),
    ("generate-key", "generate keys with `vault pgp new`"),
    ("full-gen-key", "generate keys with `vault pgp new`"),
    ("full-generate-key", "generate keys with `vault pgp new`"),
    ("quick-gen-key", "generate keys with `vault pgp new`"),
    ("quick-generate-key", "generate keys with `vault pgp new`"),
    (
        "export-secret-keys",
        "export secret keys with `vault pgp export`",
    ),
    (
        "export-secret-subkeys",
        "export secret keys with `vault pgp export`",
    ),
    ("delete-keys", "delete keys from the vault with `vault rm`"),
    (
        "delete-secret-keys",
        "delete keys from the vault with `vault rm`",
    ),
    ("edit-key", "key editing is not supported"),
    ("sign-key", "key certification is not supported"),
    ("lsign-key", "key certification is not supported"),
    ("card-status", "OpenPGP cards are not supported"),
];

#[derive(Debug, Default, PartialEq)]
pub struct Args {
    pub sign: bool,
    pub detach: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub verify: bool,
    /// `--list-keys` (false) or `--list-secret-keys` (true).
    pub list: Option<bool>,
    pub import: bool,
    pub export: bool,
    pub version: bool,
    pub help: bool,
    /// `--list-config`: we have no groups or other settings to report.
    pub list_config: bool,
    /// `--decrypt --list-only`: name the recipients, decrypt nothing.
    pub list_only: bool,
    pub armor: bool,
    pub textmode: bool,
    pub colons: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub local_users: Vec<String>,
    pub default_key: Option<String>,
    pub recipients: Vec<String>,
    pub output: Option<String>,
    pub status_fd: Option<i32>,
    pub files: Vec<String>,
}

pub fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = argv.iter().peekable();
    while let Some(arg) = it.next() {
        if arg == "--" {
            a.files.extend(it.by_ref().cloned());
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (long, None),
            };
            let mut value = || -> Result<String, String> {
                match &inline {
                    Some(v) => Ok(v.clone()),
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("option \"--{name}\" requires an argument")),
                }
            };
            match name {
                "sign" => a.sign = true,
                "detach-sign" => a.detach = true,
                "encrypt" => a.encrypt = true,
                "decrypt" => a.decrypt = true,
                "verify" => a.verify = true,
                "list-keys" | "list-public-keys" | "fingerprint" | "list-sigs" | "check-sigs" => {
                    a.list.get_or_insert(false);
                }
                "list-secret-keys" => a.list = Some(true),
                "import" => a.import = true,
                "export" => a.export = true,
                "version" => a.version = true,
                "help" => a.help = true,
                "list-config" => a.list_config = true,
                "list-only" => a.list_only = true,
                "armor" | "armour" => a.armor = true,
                "no-armor" | "no-armour" => a.armor = false,
                "textmode" => a.textmode = true,
                "no-textmode" => a.textmode = false,
                "with-colons" => a.colons = true,
                "quiet" => a.quiet = true,
                "verbose" => a.verbose = true,
                "local-user" => a.local_users.push(value()?),
                "default-key" => a.default_key = Some(value()?),
                "recipient" | "hidden-recipient" | "encrypt-to" | "hidden-encrypt-to" => {
                    a.recipients.push(value()?)
                }
                "output" => a.output = Some(value()?),
                "status-fd" => {
                    let v = value()?;
                    a.status_fd = Some(v.parse().map_err(|_| format!("bad --status-fd {v}"))?);
                }
                n if IGNORED_WITH_VALUE.contains(&n) => {
                    value()?;
                }
                n if IGNORED.contains(&n) => {}
                n => {
                    if let Some((_, why)) = UNSUPPORTED.iter().find(|(u, _)| *u == n) {
                        return Err((*why).into());
                    }
                    return Err(format!("invalid option \"--{n}\""));
                }
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            a.files.push(arg.clone());
            continue;
        };
        for (i, c) in cluster.char_indices() {
            if matches!(c, 'u' | 'r' | 'R' | 'o' | 'z') {
                // The rest of the cluster, or the next argument, is the value.
                let rest = &cluster[i + c.len_utf8()..];
                let v = if rest.is_empty() {
                    it.next()
                        .cloned()
                        .ok_or_else(|| format!("option \"-{c}\" requires an argument"))?
                } else {
                    rest.to_owned()
                };
                match c {
                    'u' => a.local_users.push(v),
                    'r' | 'R' => a.recipients.push(v),
                    'o' => a.output = Some(v),
                    _ => {} // -z: compression level
                }
                break;
            }
            match c {
                's' => a.sign = true,
                'b' => a.detach = true,
                'e' => a.encrypt = true,
                'd' => a.decrypt = true,
                'k' => {
                    a.list.get_or_insert(false);
                }
                'K' => a.list = Some(true),
                'a' => a.armor = true,
                't' => a.textmode = true,
                'q' => a.quiet = true,
                'v' => a.verbose = true,
                'n' | 'y' => {}
                'h' => a.help = true,
                'c' => return Err("password-only encryption is not supported".into()),
                _ => return Err(format!("invalid option \"-{c}\"")),
            }
        }
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Args {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn git_signing() {
        let a = p("--status-fd=2 -bsau Alex_Example");
        assert!(a.detach && a.sign && a.armor);
        assert_eq!(a.local_users, ["Alex_Example"]);
        assert_eq!(a.status_fd, Some(2));
        assert!(a.files.is_empty());
    }

    #[test]
    fn git_verify() {
        let a = p("--keyid-format=long --status-fd=1 --verify /tmp/sig -");
        assert!(a.verify);
        assert_eq!(a.status_fd, Some(1));
        assert_eq!(a.files, ["/tmp/sig", "-"]);
    }

    #[test]
    fn pass_encrypt_and_decrypt() {
        let a = p(
            "-e -r ABCDEF0123456789 -o /s/x.gpg --quiet --yes --compress-algo=none --no-encrypt-to --batch --use-agent",
        );
        assert!(a.encrypt && a.quiet);
        assert_eq!(a.recipients, ["ABCDEF0123456789"]);
        assert_eq!(a.output.as_deref(), Some("/s/x.gpg"));

        let a = p("-d --quiet --yes --compress-algo none --no-encrypt-to /s/x.gpg");
        assert!(a.decrypt);
        assert_eq!(a.files, ["/s/x.gpg"]);
    }

    #[test]
    fn mutt_style() {
        let a = p(
            "--batch --quiet --no-verbose --output - --textmode --armor --always-trust --encrypt-to 0xC9C40C31 --encrypt --sign -u alex@example.com -r bo@example.org -r cy@example.net -- -f",
        );
        assert!(a.encrypt && a.sign && a.textmode && a.armor);
        assert_eq!(
            a.recipients,
            ["0xC9C40C31", "bo@example.org", "cy@example.net"]
        );
        // After `--` everything is a file name, as with gpg.
        assert_eq!(a.files, ["-f"]);

        let a = p("--passphrase-fd 0 --detach-sign --local-user=alex /tmp/f");
        assert!(a.detach);
        assert_eq!(a.local_users, ["alex"]);
        assert_eq!(a.files, ["/tmp/f"]);
    }

    #[test]
    fn values_glued_to_short_options() {
        let a = p("-uALEX -ro.txt");
        assert_eq!(a.local_users, ["ALEX"]);
        assert_eq!(a.recipients, ["o.txt"]);
    }

    #[test]
    fn rejects_unknown_and_unsupported() {
        let e = |s: &str| parse(&[s.to_owned()]).unwrap_err();
        assert!(e("--frobnicate").contains("invalid option"));
        assert!(e("--clearsign").contains("--detach-sign"));
        assert!(e("--gen-key").contains("vault pgp new"));
        assert!(e("-x").contains("invalid option"));
        assert!(parse(&["--local-user".into()]).is_err());
    }
}
