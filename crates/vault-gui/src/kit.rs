//! The emergency kit: one printable page with the recovery code and the
//! steps to use it, for a drawer or a safe.
//!
//! The code is shown only once, at setup, so the page is made then: written
//! to the system temporary folder (readable only by this user), opened in the
//! default browser to print, and deleted a minute later. It is never kept.

use std::path::PathBuf;
use std::time::Duration;

/// How long the page stays on disk after it is opened.
pub const KEEP: Duration = Duration::from_secs(90);

/// `YYYY-MM-DD` (UTC) for a Unix time.
pub fn date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The page, as HTML.
pub fn html(code: &str, made: &str) -> String {
    let code = escape(code);
    let made = escape(made);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Secret Vault emergency kit</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#111}}
h1{{margin-bottom:0}} .sub{{color:#555;margin-top:.2rem}}
.code{{font:600 1.35rem/1.8 ui-monospace,Consolas,monospace;border:2px solid #111;border-radius:8px;padding:1rem;text-align:center;letter-spacing:.05em;word-break:break-word}}
h2{{margin-top:1.8rem}} li{{margin:.3rem 0}} code{{background:#eee;padding:0 .25rem;border-radius:3px}}
.warn{{border-left:4px solid #b00;padding:.2rem 1rem;background:#fff4f4}}
</style></head><body>
<h1>Secret Vault emergency kit</h1>
<p class="sub">Made on {made}. Keep this page somewhere safe, away from the computer.</p>
<h2>Recovery code</h2>
<p class="code">{code}</p>
<p class="warn">Anyone who has this code and a copy of your vault file can open the vault. Do not photograph it or save it on a computer. Nobody can reset it for you.</p>
<h2>If you cannot unlock your vault</h2>
<ol>
<li>Install Secret Vault on a computer and start <code>vaultd</code>. If your vault file is gone, copy a backup or the synced file to the folder below first.</li>
<li>Run <code>vault unlock --recovery</code> and type the code above (capitals, small letters, hyphens and spaces do not matter).</li>
<li>Once in, set a new password: run <code>vault add-slot password</code>, then remove the old one with <code>vault rm-slot</code>. The desktop app does the same under <b>Unlock methods</b>.</li>
</ol>
<h2>Where the vault file is</h2>
<ul>
<li>Linux: <code>~/.local/share/vault/vault.svault</code></li>
<li>Windows: <code>%LOCALAPPDATA%\vault\vault.svault</code></li>
<li>macOS: <code>~/Library/Application Support/vault/vault.svault</code></li>
<li>Synced vault: the <code>vault.svault</code> file in your OneDrive, Google Drive or Dropbox folder</li>
</ul>
<h2>Other notes</h2>
<p>Your master password: <i>(do not write it here; remember it)</i><br>
Where my backup copies are: ____________________________________________</p>
</body></html>
"#
    )
}

/// Write the page, open it, and delete it after [`KEEP`].
pub fn print(code: &str) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!(
        "secret-vault-emergency-kit-{}.html",
        std::process::id()
    ));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o
        .open(&path)
        .map_err(|e| format!("could not write the page: {e}"))?;
    std::io::Write::write_all(&mut f, html(code, &date(now)).as_bytes())
        .map_err(|e| format!("could not write the page: {e}"))?;
    drop(f);
    open(&path)?;
    let p = path.clone();
    std::thread::spawn(move || {
        std::thread::sleep(KEEP);
        let _ = std::fs::remove_file(p);
    });
    Ok(())
}

fn open(path: &std::path::Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let mut c = std::process::Command::new("xdg-open");
    #[cfg(target_os = "macos")]
    let mut c = std::process::Command::new("open");
    #[cfg(windows)]
    let mut c = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    c.arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open the page: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_holds_the_code_and_escapes_it() {
        let h = html("ABCDEF-GHJKMN", "2026-11-11");
        assert!(h.contains("ABCDEF-GHJKMN"));
        assert!(h.contains("vault unlock --recovery"));
        assert!(!html("<b>&", "x").contains("<b>&"));
        // No personal names in the page.
        assert!(!h.to_lowercase().contains("nishant"));
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_794_355_200), "2026-11-11");
    }
}
