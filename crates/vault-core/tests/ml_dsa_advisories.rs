//! The ML-DSA library the vault links is a patched copy (vendor/README.md),
//! whose own tests CI does not run. These cases fail without the patches for
//! GHSA-5x2r-hc65-25f9 (a signature with a repeated hint is accepted) and
//! GHSA-h37v-hp6w-2pp8 (a valid signature is refused).

use data_encoding::HEXLOWER_PERMISSIVE as HEX;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

const CASES: &str = include_str!("data/mldsa65_wycheproof.txt");

fn verifies(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
        return false;
    };
    let Ok(sig) = EncodedSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&sig) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(msg, ctx, &sig)
}

#[test]
fn the_published_cases_for_both_advisories_pass() {
    // Git on Windows may check the file out with CR LF line ends.
    let cases = CASES.replace('\r', "");
    let mut seen = 0;
    for block in cases.split("\n\n").filter(|b| b.contains("tcId=")) {
        let field = |name: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
                .unwrap_or_else(|| panic!("no {name}"))
        };
        let bytes = |name: &str| HEX.decode(field(name).as_bytes()).unwrap();
        let got = verifies(&bytes("pk"), &bytes("msg"), &bytes("ctx"), &bytes("sig"));
        assert_eq!(
            got,
            field("result") == "valid",
            "case {} ({})",
            field("tcId"),
            field("comment")
        );
        seen += 1;
    }
    assert_eq!(seen, 2, "both cases are present");
}
