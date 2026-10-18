use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit secret key. Zeroized on drop; deliberately not `Debug`, `Clone`
/// or `Serialize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Key([u8; 32]);

impl Key {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Key(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A 32-byte secret from a hardware factor: a FIDO2 hmac-secret output or a
/// TPM-unsealed secret (section 4.2). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HwKey([u8; 32]);

impl HwKey {
    /// Wrap a hardware-derived secret. The caller should zeroize its own copy.
    pub fn new(bytes: [u8; 32]) -> Self {
        HwKey(bytes)
    }

    /// Constant-time comparison, for callers that verify a factor round-trips.
    pub fn ct_eq(&self, other: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(other).into()
    }

    /// Constant-time comparison of two hardware secrets.
    pub fn ct_eq_key(&self, other: &HwKey) -> bool {
        self.ct_eq(&other.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
