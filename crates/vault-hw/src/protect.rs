//! A 32-byte key kept encrypted in memory while it is not in use. On Windows
//! that is `CryptProtectMemory`, whose key never leaves the kernel, so the
//! bytes are useless in a crash dump, the page file or a memory scan from
//! outside the process. Elsewhere the bytes are only zeroized on drop.

use vault_core::HwKey;
use zeroize::Zeroizing;

pub struct ProtectedKey(Zeroizing<[u8; 32]>);

impl ProtectedKey {
    /// Take `key` and protect it.
    pub fn new(mut key: [u8; 32]) -> ProtectedKey {
        let mut p = ProtectedKey(Zeroizing::new(key));
        zeroize::Zeroize::zeroize(&mut key);
        p.protect();
        p
    }

    /// Run `f` with the plain key, protecting it again afterwards.
    pub fn with<T>(&mut self, f: impl FnOnce(&HwKey) -> T) -> T {
        self.unprotect();
        let k = HwKey::new(*self.0);
        self.protect();
        f(&k)
    }

    #[cfg(windows)]
    fn protect(&mut self) {
        use windows_sys::Win32::Security::Cryptography::{
            CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
        };
        // SAFETY: 32 bytes we own, a multiple of the 16-byte block size.
        let ok = unsafe {
            CryptProtectMemory(
                self.0.as_mut_ptr().cast(),
                32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
        };
        assert!(ok != 0, "CryptProtectMemory failed");
    }

    #[cfg(windows)]
    fn unprotect(&mut self) {
        use windows_sys::Win32::Security::Cryptography::{
            CRYPTPROTECTMEMORY_SAME_PROCESS, CryptUnprotectMemory,
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectMemory(
                self.0.as_mut_ptr().cast(),
                32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
        };
        assert!(ok != 0, "CryptUnprotectMemory failed");
    }

    #[cfg(not(windows))]
    fn protect(&mut self) {}

    #[cfg(not(windows))]
    fn unprotect(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut p = ProtectedKey::new([3; 32]);
        assert!(p.with(|k| k.ct_eq(&[3; 32])));
        assert!(p.with(|k| k.ct_eq(&[3; 32])));
        #[cfg(windows)]
        assert_ne!(*p.0, [3; 32]);
    }
}
