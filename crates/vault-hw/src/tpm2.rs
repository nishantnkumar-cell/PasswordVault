//! A small TPM 2.0 client that speaks the command protocol itself: just
//! enough to seal a secret under a persistent storage key and unseal it,
//! with a PIN, a PCR 7 policy, and a salted session that encrypts the secret
//! and the PIN on the way to and from the TPM.
//!
//! Windows uses it through TPM Base Services (`wintpm.rs`), which any user
//! may call, to seal under the storage key Windows keeps at `0x81000001`.
//! The Platform Crypto Provider only offers RSA and ECC keys, and a secret
//! wrapped with RSA can be recovered from the vault file by a future quantum
//! computer; a sealed object's private part is protected by the TPM's own
//! symmetric key instead (docs/threat-model.md A6).
//!
//! The protocol is TPM 2.0 Library Part 1 (sessions: 19, parameter
//! encryption: 21, KDFa: 11.4.10.2) and Part 3 (commands). Tests run it
//! against swtpm, see `tests` below.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vault_core::{HwKey, OsRandom, SecureRandom};
use zeroize::Zeroizing;

use super::HwResult;

/// The storage key Windows creates when it takes ownership of the TPM.
pub const WINDOWS_SRK: u32 = 0x8100_0001;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

#[cfg(test)]
const CC_EVICT_CONTROL: u32 = 0x120;
#[cfg(test)]
const CC_CREATE_PRIMARY: u32 = 0x131;
#[cfg(test)]
const CC_DA_LOCK_RESET: u32 = 0x139;
const CC_CREATE: u32 = 0x153;
const CC_LOAD: u32 = 0x157;
const CC_UNSEAL: u32 = 0x15E;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_POLICY_AUTH_VALUE: u32 = 0x16B;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_PCR_READ: u32 = 0x17E;
const CC_POLICY_PCR: u32 = 0x17F;
#[cfg(test)]
const CC_PCR_EXTEND: u32 = 0x182;

const RS_PW: u32 = 0x4000_0009;
#[cfg(test)]
const RH_OWNER: u32 = 0x4000_0001;
const RH_NULL: u32 = 0x4000_0007;
#[cfg(test)]
const RH_LOCKOUT: u32 = 0x4000_000A;

const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_KEYEDHASH: u16 = 0x0008;
const ALG_SHA256: u16 = 0x000B;
const ALG_NULL: u16 = 0x0010;
const ALG_CFB: u16 = 0x0043;

const SE_HMAC: u8 = 0;
const SE_POLICY: u8 = 1;

const SA_CONTINUE: u8 = 0x01;
const SA_DECRYPT: u8 = 0x20;
const SA_ENCRYPT: u8 = 0x40;

const OA_FIXED_TPM: u32 = 1 << 1;
const OA_FIXED_PARENT: u32 = 1 << 4;
#[cfg(test)]
const OA_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const OA_USER_WITH_AUTH: u32 = 1 << 6;
const OA_NO_DA: u32 = 1 << 10;
const OA_RESTRICTED: u32 = 1 << 16;
const OA_DECRYPT: u32 = 1 << 17;

const RC_AUTH_FAIL: u32 = 0x08E;
const RC_POLICY_FAIL: u32 = 0x09D;
const RC_BAD_AUTH: u32 = 0x0A2;
const RC_HANDLE: u32 = 0x08B;
const RC_PCR_CHANGED: u32 = 0x167;
const RC_LOCKOUT: u32 = 0x921;
const RC_RETRY: u32 = 0x922;
const RC_YIELDED: u32 = 0x908;
const RC_TESTING: u32 = 0x90A;
/// What Windows answers for a command its TPM Base Services block.
const TPM_E_COMMAND_BLOCKED: u32 = 0x8028_0400;

/// Sends one command and returns the whole response.
pub trait Transport {
    fn transact(&mut self, command: &[u8]) -> HwResult<Vec<u8>>;
}

/// The storage key's RSA public key: modulus (big-endian) and exponent.
pub struct RsaPublic {
    pub n: Vec<u8>,
    pub e: u32,
}

/// RSA-OAEP with SHA-256 and the label `"SECRET\0"`: how a session salt is
/// sent to an RSA storage key (Part 1, annex B.10.3). Supplied by the
/// platform, since this crate has no RSA of its own.
pub type EncryptSalt = fn(&RsaPublic, &[u8]) -> HwResult<Vec<u8>>;

type HmacSha256 = Hmac<Sha256>;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// KDFa with SHA-256 (Part 1, 11.4.10.2). `label` without its NUL.
fn kdfa(key: &[u8], label: &[u8], u: &[u8], v: &[u8], bits: u32) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    let mut i = 1u32;
    while out.len() * 8 < bits as usize {
        out.extend_from_slice(&hmac(
            key,
            &[&i.to_be_bytes(), label, &[0], u, v, &bits.to_be_bytes()],
        ));
        i += 1;
    }
    out.truncate(bits as usize / 8);
    out
}

/// AES-128-CFB over `data` in place; `decrypt` picks the direction.
fn cfb(key: &[u8], iv: &[u8], data: &mut [u8], decrypt: bool) {
    let aes = Aes128::new_from_slice(key).expect("16-byte key");
    let mut reg = aes::Block::default();
    reg.copy_from_slice(iv);
    for chunk in data.chunks_mut(16) {
        let mut ks = reg;
        aes.encrypt_block(&mut ks);
        let mut next = aes::Block::default();
        for (j, b) in chunk.iter_mut().enumerate() {
            let input = *b;
            *b ^= ks[j];
            // The next register is the ciphertext either way.
            next[j] = if decrypt { input } else { *b };
        }
        reg = next;
    }
}

fn random32() -> HwResult<[u8; 32]> {
    let mut b = [0u8; 32];
    OsRandom.fill(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

/// A TPM2B: u16 big-endian length, then the bytes.
fn put_b(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> HwResult<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n).ok_or("TPM response truncated")?;
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> HwResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> HwResult<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> HwResult<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn b(&mut self) -> HwResult<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// TPML_PCR_SELECTION for PCR 7 in the SHA-256 bank.
fn pcr7_selection() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&1u32.to_be_bytes());
    s.extend_from_slice(&ALG_SHA256.to_be_bytes());
    s.extend_from_slice(&[3, 0x80, 0, 0]);
    s
}

/// A TPM error code, kept so callers can tell a wrong PIN from the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rc(pub u32);

impl Rc {
    /// The code without the handle, session or parameter number.
    pub fn base(self) -> u32 {
        if self.0 & 0x80 != 0 {
            0x80 | (self.0 & 0x3F)
        } else {
            self.0
        }
    }

    pub fn message(self, what: &str) -> String {
        match self.base() {
            RC_AUTH_FAIL | RC_BAD_AUTH => format!("TPM {what}: wrong TPM PIN"),
            RC_LOCKOUT => format!(
                "TPM {what}: the TPM is locked out after too many wrong PINs; wait (usually 10 \
                 minutes to 2 hours) or unlock with another method"
            ),
            RC_POLICY_FAIL | RC_PCR_CHANGED => format!(
                "TPM {what}: PCR 7 changed (Secure Boot settings or keys changed), so this slot \
                 no longer works; unlock with another method and enroll the TPM again"
            ),
            TPM_E_COMMAND_BLOCKED => format!(
                "TPM {what}: Windows blocks this TPM command for programs (see the group policy \
                 \"Configure the list of blocked TPM commands\")"
            ),
            _ => format!("TPM {what}: error 0x{:03x}", self.0),
        }
    }
}

/// An authorization session started by this client.
struct Session {
    handle: u32,
    key: Zeroizing<Vec<u8>>,
    nonce_tpm: Vec<u8>,
}

/// How a command is authorized.
enum Auth<'s> {
    None,
    /// The empty password, for objects with no authValue.
    Password,
    /// A salted session, the authorized object's authValue, and the
    /// session attributes (which say what is encrypted).
    Session(&'s mut Session, &'s [u8], u8),
}

/// The authValue as the HMAC key uses it: trailing zeros removed.
fn trimmed(auth: &[u8]) -> &[u8] {
    let n = auth.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &auth[..n]
}

pub struct Client<T: Transport> {
    t: T,
    srk: u32,
    encrypt_salt: EncryptSalt,
    srk_name: Vec<u8>,
    srk_public: RsaPublic,
}

impl<T: Transport> Client<T> {
    /// Connect to the storage key at `srk`, which must be an RSA restricted
    /// decryption key with no authValue (Windows' is).
    pub fn new(t: T, srk: u32, encrypt_salt: EncryptSalt) -> HwResult<Client<T>> {
        let mut c = Client {
            t,
            srk,
            encrypt_salt,
            srk_name: Vec::new(),
            srk_public: RsaPublic {
                n: Vec::new(),
                e: 0,
            },
        };
        let (public, name) = c.read_public(srk).map_err(|e| {
            if e.0.base() == RC_HANDLE {
                format!(
                    "the TPM has no storage key at 0x{srk:08x}; Windows makes it when it sets up \
                     the TPM (check tpm.msc shows \"The TPM is ready for use\")"
                )
            } else {
                e.1
            }
        })?;
        if name.len() != 34
            || name[..2] != ALG_SHA256.to_be_bytes()
            || name[2..] != sha256(&[&public])
        {
            return Err("TPM storage key: name does not match its public area".into());
        }
        c.srk_public = parse_rsa_storage_key(&public)?;
        c.srk_name = name;
        Ok(c)
    }

    fn transact(&mut self, cmd: &[u8]) -> HwResult<Vec<u8>> {
        // A TPM may ask to have a command sent again.
        for _ in 0..5 {
            let r = self.t.transact(cmd)?;
            let rc = r
                .get(6..10)
                .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
                .ok_or("TPM response truncated")?;
            if !matches!(rc, RC_RETRY | RC_YIELDED | RC_TESTING) {
                return Ok(r);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Err("TPM stayed busy; try again".into())
    }

    /// Run one command. `names` are the Names of handles that need
    /// authorization (only those enter the cpHash with a session). Returns
    /// the response handles and the response parameters (decrypted).
    fn run(
        &mut self,
        cc: u32,
        handles: &[u32],
        names: &[&[u8]],
        auth: Auth,
        params: Vec<u8>,
        n_out_handles: usize,
    ) -> Result<(Vec<u32>, Vec<u8>), (Rc, String)> {
        let wrap = |s: String| (Rc(0), s);
        let mut params = params;
        let mut area = Vec::new();
        let mut verify: Option<(Zeroizing<Vec<u8>>, [u8; 32], u8)> = None;
        match &auth {
            Auth::None => {}
            Auth::Password => {
                area.extend_from_slice(&RS_PW.to_be_bytes());
                put_b(&mut area, &[]);
                area.push(SA_CONTINUE);
                put_b(&mut area, &[]);
            }
            Auth::Session(s, auth_value, attrs) => {
                let nonce = random32().map_err(wrap)?;
                let mut value = Zeroizing::new(s.key.to_vec());
                value.extend_from_slice(trimmed(auth_value));
                if attrs & SA_DECRYPT != 0 {
                    let kv = kdfa(&value, b"CFB", &nonce, &s.nonce_tpm, 256);
                    let n = u16::from_be_bytes([params[0], params[1]]) as usize;
                    cfb(&kv[..16], &kv[16..], &mut params[2..2 + n], false);
                }
                let mut cp = Sha256::new();
                cp.update(cc.to_be_bytes());
                for n in names {
                    cp.update(n);
                }
                cp.update(&params);
                let cp: [u8; 32] = cp.finalize().into();
                let mac = hmac(&value, &[&cp, &nonce, &s.nonce_tpm, &[*attrs]]);
                area.extend_from_slice(&s.handle.to_be_bytes());
                put_b(&mut area, &nonce);
                area.push(*attrs);
                put_b(&mut area, &mac);
                verify = Some((value, nonce, *attrs));
            }
        }
        let sessions = !matches!(auth, Auth::None);
        let mut cmd = Vec::with_capacity(64 + params.len());
        cmd.extend_from_slice(
            &if sessions {
                ST_SESSIONS
            } else {
                ST_NO_SESSIONS
            }
            .to_be_bytes(),
        );
        cmd.extend_from_slice(&[0; 4]);
        cmd.extend_from_slice(&cc.to_be_bytes());
        for h in handles {
            cmd.extend_from_slice(&h.to_be_bytes());
        }
        if sessions {
            cmd.extend_from_slice(&(area.len() as u32).to_be_bytes());
            cmd.extend_from_slice(&area);
        }
        cmd.extend_from_slice(&params);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        let cmd = Zeroizing::new(cmd);

        let resp = Zeroizing::new(self.transact(&cmd).map_err(wrap)?);
        let mut r = Reader(&resp);
        let tag = r.u16().map_err(wrap)?;
        let size = r.u32().map_err(wrap)? as usize;
        let rc = r.u32().map_err(wrap)?;
        if size != resp.len() {
            return Err(wrap("TPM response has the wrong length".into()));
        }
        if rc != 0 {
            return Err((Rc(rc), format!("TPM error 0x{rc:03x}")));
        }
        let mut out_handles = Vec::new();
        for _ in 0..n_out_handles {
            out_handles.push(r.u32().map_err(wrap)?);
        }
        let mut out = if tag == ST_SESSIONS {
            let n = r.u32().map_err(wrap)? as usize;
            r.take(n).map_err(wrap)?.to_vec()
        } else {
            r.0.to_vec()
        };
        if let (Auth::Session(s, _, _), Some((value, nonce, attrs))) = (auth, verify) {
            if tag != ST_SESSIONS {
                return Err(wrap("TPM response has no session".into()));
            }
            let nonce_tpm = r.b().map_err(wrap)?.to_vec();
            let r_attrs = r.u8().map_err(wrap)?;
            let mac = r.b().map_err(wrap)?;
            let rp = sha256(&[&0u32.to_be_bytes(), &cc.to_be_bytes(), &out]);
            let expect = hmac(&value, &[&rp, &nonce_tpm, &nonce, &[r_attrs]]);
            if mac.len() != 32 || !bool::from(expect.ct_eq(mac)) {
                return Err(wrap(
                    "TPM response failed its integrity check (tampered with on the way?)".into(),
                ));
            }
            if attrs & SA_ENCRYPT != 0 {
                let kv = kdfa(&value, b"CFB", &nonce_tpm, &nonce, 256);
                let n = u16::from_be_bytes([out[0], out[1]]) as usize;
                cfb(&kv[..16], &kv[16..], &mut out[2..2 + n], true);
            }
            s.nonce_tpm = nonce_tpm;
        }
        Ok((out_handles, out))
    }

    fn read_public(&mut self, h: u32) -> Result<(Vec<u8>, Vec<u8>), (Rc, String)> {
        let (_, p) = self.run(CC_READ_PUBLIC, &[h], &[], Auth::None, Vec::new(), 0)?;
        let mut r = Reader(&p);
        let w = |e: String| (Rc(0), e);
        let public = r.b().map_err(w)?.to_vec();
        let name = r.b().map_err(w)?.to_vec();
        Ok((public, name))
    }

    /// A session salted to the storage key, with AES-128-CFB parameter encryption.
    fn start_session(&mut self, kind: u8) -> HwResult<Session> {
        let salt = Zeroizing::new(random32()?);
        let encrypted = (self.encrypt_salt)(&self.srk_public, &salt[..])?;
        let nonce = random32()?;
        let mut p = Vec::new();
        put_b(&mut p, &nonce);
        put_b(&mut p, &encrypted);
        p.push(kind);
        p.extend_from_slice(&ALG_AES.to_be_bytes());
        p.extend_from_slice(&128u16.to_be_bytes());
        p.extend_from_slice(&ALG_CFB.to_be_bytes());
        p.extend_from_slice(&ALG_SHA256.to_be_bytes());
        let (h, out) = self
            .run(
                CC_START_AUTH_SESSION,
                &[self.srk, RH_NULL],
                &[],
                Auth::None,
                p,
                1,
            )
            .map_err(|e| e.0.message("start session"))?;
        let nonce_tpm = Reader(&out).b()?.to_vec();
        Ok(Session {
            handle: h[0],
            key: kdfa(&salt[..], b"ATH", &nonce_tpm, &nonce, 256),
            nonce_tpm,
        })
    }

    fn flush(&mut self, h: u32) {
        let _ = self.run(
            CC_FLUSH_CONTEXT,
            &[],
            &[],
            Auth::None,
            h.to_be_bytes().to_vec(),
            0,
        );
    }

    /// The policy a PCR 7 bound object requires: PolicyPCR(SHA-256 bank,
    /// PCR 7, its current value) then PolicyAuthValue.
    fn pcr7_policy_digest(&mut self) -> HwResult<[u8; 32]> {
        let (_, out) = self
            .run(CC_PCR_READ, &[], &[], Auth::None, pcr7_selection(), 0)
            .map_err(|e| e.0.message("read PCR 7"))?;
        let mut r = Reader(&out);
        r.u32()?; // update counter
        let banks = r.u32()?;
        for _ in 0..banks {
            r.u16()?;
            let n = r.u8()? as usize;
            r.take(n)?;
        }
        if r.u32()? != 1 {
            return Err("this TPM has no SHA-256 PCR bank".into());
        }
        let pcr = r.b()?;
        let pcr_digest = sha256(&[pcr]);
        let d = sha256(&[
            &[0u8; 32],
            &CC_POLICY_PCR.to_be_bytes(),
            &pcr7_selection(),
            &pcr_digest,
        ]);
        Ok(sha256(&[&d, &CC_POLICY_AUTH_VALUE.to_be_bytes()]))
    }

    fn policy_pcr7(&mut self, s: &Session) -> HwResult<()> {
        let mut p = Vec::new();
        put_b(&mut p, &[]);
        p.extend_from_slice(&pcr7_selection());
        self.run(CC_POLICY_PCR, &[s.handle], &[], Auth::None, p, 0)
            .map_err(|e| e.0.message("policy PCR"))?;
        self.run(
            CC_POLICY_AUTH_VALUE,
            &[s.handle],
            &[],
            Auth::None,
            Vec::new(),
            0,
        )
        .map_err(|e| e.0.message("policy auth value"))?;
        Ok(())
    }

    /// Seal `secret` under the storage key. Returns the object's public and
    /// private areas (TPMT_PUBLIC, TPM2B_PRIVATE contents), which only this
    /// TPM can load.
    pub fn seal(
        &mut self,
        secret: &[u8; 32],
        pin: Option<&[u8]>,
        bind_pcr7: bool,
    ) -> HwResult<(Vec<u8>, Vec<u8>)> {
        let pin = pin.unwrap_or(&[]);
        if pin.len() > 32 {
            return Err("TPM PIN too long (at most 32 bytes)".into());
        }
        let policy = if bind_pcr7 {
            Some(self.pcr7_policy_digest()?)
        } else {
            None
        };
        let mut attrs = OA_FIXED_TPM | OA_FIXED_PARENT;
        if policy.is_none() {
            attrs |= OA_USER_WITH_AUTH;
        }
        // Objects with a PIN count towards the TPM's dictionary-attack
        // lockout; without one there is nothing to guess.
        if pin.is_empty() {
            attrs |= OA_NO_DA;
        }
        let mut public = Vec::new();
        public.extend_from_slice(&ALG_KEYEDHASH.to_be_bytes());
        public.extend_from_slice(&ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&attrs.to_be_bytes());
        put_b(&mut public, policy.as_ref().map_or(&[][..], |p| &p[..]));
        public.extend_from_slice(&ALG_NULL.to_be_bytes());
        put_b(&mut public, &[]);

        let mut sensitive = Zeroizing::new(Vec::new());
        put_b(&mut sensitive, pin);
        put_b(&mut sensitive, secret);
        let mut p = Zeroizing::new(Vec::new());
        put_b(&mut p, &sensitive);
        put_b(&mut p, &public);
        put_b(&mut p, &[]); // outsideInfo
        p.extend_from_slice(&0u32.to_be_bytes()); // creationPCR

        let mut s = self.start_session(SE_HMAC)?;
        let srk_name = self.srk_name.clone();
        let res = self.run(
            CC_CREATE,
            &[self.srk],
            &[&srk_name],
            Auth::Session(&mut s, &[], SA_CONTINUE | SA_DECRYPT),
            p.to_vec(),
            0,
        );
        self.flush(s.handle);
        let (_, out) = res.map_err(|e| e.0.message("create sealed object"))?;
        let mut r = Reader(&out);
        let private = r.b()?.to_vec();
        let public = r.b()?.to_vec();
        Ok((public, private))
    }

    /// Load and unseal an object from `seal`.
    pub fn unseal(
        &mut self,
        public: &[u8],
        private: &[u8],
        pin: Option<&[u8]>,
        bind_pcr7: bool,
    ) -> HwResult<HwKey> {
        let pin = pin.unwrap_or(&[]);
        let mut p = Vec::new();
        put_b(&mut p, private);
        put_b(&mut p, public);
        let srk_name = self.srk_name.clone();
        let (h, out) = self
            .run(CC_LOAD, &[self.srk], &[&srk_name], Auth::Password, p, 1)
            .map_err(|e| e.0.message("load"))?;
        let obj = h[0];
        let name = Reader(&out).b()?.to_vec();
        let expect_name = [&ALG_SHA256.to_be_bytes()[..], &sha256(&[public])].concat();
        let res = (|| {
            if name != expect_name {
                return Err("TPM loaded a different object".to_string());
            }
            let mut s = self.start_session(if bind_pcr7 { SE_POLICY } else { SE_HMAC })?;
            let res = (|| {
                if bind_pcr7 {
                    self.policy_pcr7(&s)?;
                }
                self.run(
                    CC_UNSEAL,
                    &[obj],
                    &[&name],
                    Auth::Session(&mut s, pin, SA_CONTINUE | SA_ENCRYPT),
                    Vec::new(),
                    0,
                )
                .map_err(|e| e.0.message("unseal"))
            })();
            self.flush(s.handle);
            res
        })();
        self.flush(obj);
        let (_, out) = res?;
        let out = Zeroizing::new(out);
        let data = Reader(&out).b()?;
        let arr: [u8; 32] = data.try_into().map_err(|_| "TPM secret has wrong length")?;
        Ok(HwKey::new(arr))
    }
}

/// The RSA public key of a storage key's TPMT_PUBLIC, after checking it is
/// one: RSA, restricted, decrypt, SHA-256 names.
fn parse_rsa_storage_key(public: &[u8]) -> HwResult<RsaPublic> {
    let bad = || "TPM storage key is not an RSA storage key".to_string();
    let mut r = Reader(public);
    let ty = r.u16()?;
    let name_alg = r.u16()?;
    let attrs = r.u32()?;
    r.b()?; // authPolicy
    if ty != ALG_RSA
        || name_alg != ALG_SHA256
        || attrs & (OA_RESTRICTED | OA_DECRYPT) != (OA_RESTRICTED | OA_DECRYPT)
    {
        return Err(bad());
    }
    if r.u16()? != ALG_NULL {
        r.u16()?; // key bits
        r.u16()?; // mode
    }
    if r.u16()? != ALG_NULL {
        r.u16()?; // scheme hash
    }
    r.u16()?; // key bits
    let e = match r.u32()? {
        0 => 65537,
        e => e,
    };
    let n = r.b()?.to_vec();
    if n.len() < 256 {
        return Err(bad());
    }
    Ok(RsaPublic { n, e })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn kdfa_matches_the_definition() {
        // Two blocks, second truncated: HMAC(key, i || label || 0 || u || v || bits).
        let k = kdfa(b"key", b"CFB", b"u", b"v", 384);
        let one = hmac(
            b"key",
            &[
                &1u32.to_be_bytes(),
                b"CFB\0",
                b"u",
                b"v",
                &384u32.to_be_bytes(),
            ],
        );
        let two = hmac(
            b"key",
            &[
                &2u32.to_be_bytes(),
                b"CFB\0",
                b"u",
                b"v",
                &384u32.to_be_bytes(),
            ],
        );
        assert_eq!(&k[..32], &one);
        assert_eq!(&k[32..], &two[..16]);
    }

    #[test]
    fn cfb_round_trip_and_known_answer() {
        // NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt, first two blocks.
        let key = data_encoding::HEXLOWER
            .decode(b"2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap();
        let iv = data_encoding::HEXLOWER
            .decode(b"000102030405060708090a0b0c0d0e0f")
            .unwrap();
        let pt = data_encoding::HEXLOWER
            .decode(b"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
            .unwrap();
        let mut d = pt.clone();
        cfb(&key, &iv, &mut d, false);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&d),
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
        );
        let mut e = pt.clone();
        cfb(&key, &iv, &mut e, false);
        cfb(&key, &iv, &mut e, true);
        assert_eq!(e, pt);
    }

    /// swtpm's TCP command port, from `TCTI=swtpm:port=N` (as for `tpm.rs`).
    struct Swtpm(TcpStream);

    impl Swtpm {
        fn connect() -> Swtpm {
            let port = std::env::var("TCTI")
                .ok()
                .and_then(|t| {
                    t.split("port=")
                        .nth(1)
                        .and_then(|p| p.split(',').next()?.parse().ok())
                })
                .unwrap_or(2321u16);
            Swtpm(TcpStream::connect(("127.0.0.1", port)).expect("swtpm listening"))
        }
    }

    impl Transport for Swtpm {
        fn transact(&mut self, cmd: &[u8]) -> HwResult<Vec<u8>> {
            self.0.write_all(cmd).map_err(|e| e.to_string())?;
            let mut head = [0u8; 10];
            self.0.read_exact(&mut head).map_err(|e| e.to_string())?;
            let size = u32::from_be_bytes(head[2..6].try_into().unwrap()) as usize;
            let mut r = head.to_vec();
            r.resize(size.max(10), 0);
            self.0.read_exact(&mut r[10..]).map_err(|e| e.to_string())?;
            Ok(r)
        }
    }

    fn encrypt_salt(k: &RsaPublic, salt: &[u8]) -> HwResult<Vec<u8>> {
        use rsa::{BigUint, Oaep, RsaPublicKey};
        let pk = RsaPublicKey::new(BigUint::from_bytes_be(&k.n), BigUint::from(k.e))
            .map_err(|e| e.to_string())?;
        pk.encrypt(
            &mut rand::thread_rng(),
            Oaep::new_with_label::<sha2_010::Sha256, _>("SECRET\0"),
            salt,
        )
        .map_err(|e| e.to_string())
    }

    /// Not Windows' handle, so a test TPM can hold both.
    const TEST_SRK: u32 = 0x8100_0101;

    /// Make a Windows-style RSA-2048 storage key at `TEST_SRK` if absent.
    fn ensure_srk(t: &mut Swtpm) {
        let mut probe = Client {
            t: Swtpm(t.0.try_clone().unwrap()),
            srk: TEST_SRK,
            encrypt_salt,
            srk_name: Vec::new(),
            srk_public: RsaPublic {
                n: Vec::new(),
                e: 0,
            },
        };
        if probe.read_public(TEST_SRK).is_ok() {
            return;
        }
        let attrs = OA_FIXED_TPM
            | OA_FIXED_PARENT
            | OA_SENSITIVE_DATA_ORIGIN
            | OA_USER_WITH_AUTH
            | OA_NO_DA
            | OA_RESTRICTED
            | OA_DECRYPT;
        let mut public = Vec::new();
        public.extend_from_slice(&ALG_RSA.to_be_bytes());
        public.extend_from_slice(&ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&attrs.to_be_bytes());
        put_b(&mut public, &[]);
        public.extend_from_slice(&ALG_AES.to_be_bytes());
        public.extend_from_slice(&128u16.to_be_bytes());
        public.extend_from_slice(&ALG_CFB.to_be_bytes());
        public.extend_from_slice(&ALG_NULL.to_be_bytes());
        public.extend_from_slice(&2048u16.to_be_bytes());
        public.extend_from_slice(&0u32.to_be_bytes());
        put_b(&mut public, &[0u8; 256]);
        let mut p = Vec::new();
        put_b(&mut p, &[0, 0, 0, 0]); // empty userAuth and data
        put_b(&mut p, &public);
        put_b(&mut p, &[]);
        p.extend_from_slice(&0u32.to_be_bytes());
        let (h, _) = probe
            .run(CC_CREATE_PRIMARY, &[RH_OWNER], &[], Auth::Password, p, 1)
            .unwrap();
        probe
            .run(
                CC_EVICT_CONTROL,
                &[RH_OWNER, h[0]],
                &[],
                Auth::Password,
                TEST_SRK.to_be_bytes().to_vec(),
                0,
            )
            .unwrap();
        probe.flush(h[0]);
    }

    fn reset_lockout<T: Transport>(c: &mut Client<T>) {
        let _ = c.run(
            CC_DA_LOCK_RESET,
            &[RH_LOCKOUT],
            &[],
            Auth::Password,
            Vec::new(),
            0,
        );
    }

    /// Clear the simulator's dictionary-attack counter, which wrong-PIN
    /// tests raise and which outlives a test run.
    pub(crate) fn reset_swtpm_lockout() {
        let mut t = Swtpm::connect();
        ensure_srk(&mut t);
        reset_lockout(&mut Client::new(t, TEST_SRK, encrypt_salt).unwrap());
    }

    /// Runs against swtpm, like `tpm::tests` (see there), in CI's TPM step.
    #[test]
    #[ignore = "needs swtpm; see tpm::tests"]
    fn seal_unseal_against_swtpm() {
        let _g = crate::TPM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut t = Swtpm::connect();
        ensure_srk(&mut t);
        let mut c = Client::new(t, TEST_SRK, encrypt_salt).unwrap();
        reset_lockout(&mut c);
        let secret = [9u8; 32];
        for pcr in [false, true] {
            let (public, private) = c.seal(&secret, Some(b"1234"), pcr).unwrap();
            let k = c.unseal(&public, &private, Some(b"1234"), pcr).unwrap();
            assert!(k.ct_eq(&secret));
            let wrong = c
                .unseal(&public, &private, Some(b"0000"), pcr)
                .err()
                .unwrap();
            assert!(wrong.contains("wrong TPM PIN"), "{wrong}");
            reset_lockout(&mut c);
        }
        let (public, private) = c.seal(&secret, None, false).unwrap();
        assert!(
            c.unseal(&public, &private, None, false)
                .unwrap()
                .ct_eq(&secret)
        );

        // A tampered blob does not load.
        let mut bad = private.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(c.unseal(&public, &bad, None, false).is_err());

        // Changing PCR 7 breaks only the PCR-bound object.
        let (bpub, bpriv) = c.seal(&secret, None, true).unwrap();
        assert!(c.unseal(&bpub, &bpriv, None, true).unwrap().ct_eq(&secret));
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&ALG_SHA256.to_be_bytes());
        p.extend_from_slice(&[2u8; 32]);
        c.run(CC_PCR_EXTEND, &[7], &[], Auth::Password, p, 0)
            .unwrap();
        let err = c.unseal(&bpub, &bpriv, None, true).err().unwrap();
        assert!(err.contains("PCR 7"), "{err}");
        assert!(
            c.unseal(&public, &private, None, false)
                .unwrap()
                .ct_eq(&secret)
        );
    }
}
