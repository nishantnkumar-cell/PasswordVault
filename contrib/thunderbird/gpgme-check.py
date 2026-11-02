#!/usr/bin/env python3
"""Check that GPGME can sign and decrypt with a vault key through vault-gpg.

Thunderbird reaches "external GnuPG keys" through the GPGME library. This
script loads the same library and makes the same calls Thunderbird makes,
so you can find a set-up problem without Thunderbird:

    python3 gpgme-check.py /path/to/vault-gpg alex@example.com
    python3 gpgme-check.py /path/to/vault-gpg alex@example.com mail.asc

The first form signs a short text (the approval window opens); the second
also decrypts an encrypted message, as Thunderbird does for incoming mail.
Standard library only (ctypes); works on Linux, Windows and macOS.
"""

import ctypes
import ctypes.util
import sys

GPGME_PROTOCOL_OPENPGP = 0
GPGME_SIG_MODE_DETACH = 1
GPGME_DECRYPT_UNWRAP = 128

# The names Thunderbird tries, in its order.
NAMES = ["libgpgme.so.11", "libgpgme-11.dll", "libgpgme6-11.dll",
         "libgpgme.11.dylib", "/opt/homebrew/lib/libgpgme.11.dylib",
         "/usr/local/lib/libgpgme.11.dylib",
         "/usr/local/MacGPG2/lib/libgpgme.11.dylib"]


def load():
    found = ctypes.util.find_library("gpgme")
    for name in ([found] if found else []) + NAMES:
        try:
            return ctypes.CDLL(name)
        except OSError:
            pass
    sys.exit("GPGME not found: install GnuPG (Gpg4win on Windows, "
             "`brew install gpgme` on macOS, libgpgme11 on Linux)")


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    vault_gpg, key = sys.argv[1], sys.argv[2]
    g = load()
    g.gpgme_check_version.restype = ctypes.c_char_p
    g.gpgme_strerror.restype = ctypes.c_char_p
    g.gpgme_data_release_and_get_mem.restype = ctypes.c_void_p
    version = g.gpgme_check_version(b"1.9.0")
    if not version:
        sys.exit("GPGME is older than 1.9.0; Thunderbird needs 1.9.0 or later")
    print("GPGME", version.decode())

    def check(err, what):
        if err:
            sys.exit(f"{what} failed: {g.gpgme_strerror(err).decode()}")

    # Thunderbird: mail.openpgp.alternative_gpg_path
    check(g.gpgme_set_engine_info(GPGME_PROTOCOL_OPENPGP,
                                  vault_gpg.encode(), None), "set_engine_info")

    def new_ctx():
        c = ctypes.c_void_p()
        check(g.gpgme_new(ctypes.byref(c)), "gpgme_new")
        return c

    def data(b=None):
        d = ctypes.c_void_p()
        if b is None:
            check(g.gpgme_data_new(ctypes.byref(d)), "data_new")
        else:
            check(g.gpgme_data_new_from_mem(ctypes.byref(d), b, len(b), 1),
                  "data_new_from_mem")
        return d

    def take(d):
        n = ctypes.c_size_t()
        p = g.gpgme_data_release_and_get_mem(d, ctypes.byref(n))
        out = ctypes.string_at(p, n.value) if p else b""
        g.gpgme_free(ctypes.c_void_p(p))
        return out

    # Thunderbird's signDetached(): armored text-mode detached signature.
    c = new_ctx()
    g.gpgme_set_armor(c, 1)
    g.gpgme_set_textmode(c, 1)
    k = ctypes.c_void_p()
    check(g.gpgme_get_key(c, key.encode(), ctypes.byref(k), 1),
          f"finding the secret key {key!r}")
    check(g.gpgme_signers_add(c, k), "signers_add")
    out = data()
    check(g.gpgme_op_sign(c, data(b"gpgme-check\r\n"), out,
                          GPGME_SIG_MODE_DETACH), "signing")
    sig = take(out)
    g.gpgme_key_release(k)
    g.gpgme_release(c)
    print("Signed: OK" if sig.startswith(b"-----BEGIN PGP SIGNATURE-----")
          else "Signed, but the output is not a signature")

    if len(sys.argv) == 4:
        # Thunderbird's decryptArray(): decrypt, keep the message inside.
        with open(sys.argv[3], "rb") as f:
            ciphertext = f.read()
        c = new_ctx()
        g.gpgme_set_armor(c, 1)
        out = data()
        check(g.gpgme_op_decrypt_ext(c, GPGME_DECRYPT_UNWRAP,
                                     data(ciphertext), out), "decrypting")
        inner = take(out)
        g.gpgme_release(c)
        print(f"Decrypted: OK ({len(inner)} bytes of OpenPGP message)")


if __name__ == "__main__":
    main()
