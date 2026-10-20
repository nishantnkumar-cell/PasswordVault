# App icon

A white keyhole on a signal-red tile (`#EE3B36` to `#B5161B`). Every file here
except this README is made by `generate.py`; edit the shapes there and rerun:

    pip install resvg-py pillow
    python3 contrib/icons/generate.py

| File | Used for |
|---|---|
| `secret-vault.svg` | Master artwork, 64 px and up (inset tile, halo, ring) |
| `secret-vault-small.svg` | 48 px and below (full tile, bigger keyhole, no halo or ring) |
| `secret-vault-macos.svg`, `secret-vault.icns` | macOS: tile on a 1024 canvas with a transparent margin and shadow |
| `secret-vault.ico` | Windows: 16 to 256 px, embedded in the `vault-gui` binaries by `crates/vault-gui/build.rs` and used by the installer |
| `hicolor/` | Linux icon theme tree named after the app id `dev.passwordvault.app`, plus a GNOME symbolic icon; copy it to `~/.local/share/icons/` |

The window icon (title bar, X11 taskbar) is `hicolor/256x256/apps/dev.passwordvault.app.png`,
built into the app by `vault_gui::window_icon`.
