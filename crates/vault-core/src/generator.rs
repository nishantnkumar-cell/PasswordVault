//! Password and passphrase generation from the OS CSPRNG.

use zeroize::Zeroizing;

use crate::Error;
use crate::rng::SecureRandom;

/// Character classes for [`generate_password`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charset {
    /// a-z
    pub lower: bool,
    /// A-Z
    pub upper: bool,
    /// 0-9
    pub digits: bool,
    /// Printable ASCII symbols.
    pub symbols: bool,
    /// Drop look-alike characters (0 O o 1 l I).
    pub avoid_ambiguous: bool,
}

impl Default for Charset {
    fn default() -> Self {
        Charset {
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "0Oo1lI";

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
pub(crate) fn uniform(rng: &mut dyn SecureRandom, n: u32) -> Result<u32, Error> {
    assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % n);
        }
    }
}

/// A random password of `len` characters with at least one character from
/// each selected class.
pub fn generate_password(
    rng: &mut dyn SecureRandom,
    len: usize,
    cs: Charset,
) -> Result<Zeroizing<String>, Error> {
    let classes: Vec<Vec<char>> = [
        (cs.lower, ('a'..='z').collect::<String>()),
        (cs.upper, ('A'..='Z').collect::<String>()),
        (cs.digits, ('0'..='9').collect::<String>()),
        (cs.symbols, SYMBOLS.to_owned()),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, s)| {
        s.chars()
            .filter(|c| !(cs.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect();
    if classes.is_empty() || len < classes.len() || len > 1024 {
        return Err(Error::Malformed);
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(len));
        for _ in 0..len {
            out.push(all[uniform(rng, all.len() as u32)? as usize]);
        }
        // Resample rather than patch, which keeps the distribution uniform
        // over passwords that contain every class.
        if classes
            .iter()
            .all(|c| out.chars().any(|ch| c.contains(&ch)))
        {
            return Ok(out);
        }
    }
}

/// A passphrase of `words` words from `wordlist`, joined by `sep`.
pub fn generate_passphrase(
    rng: &mut dyn SecureRandom,
    wordlist: &[&str],
    words: usize,
    sep: &str,
) -> Result<Zeroizing<String>, Error> {
    if wordlist.len() < 2 || words == 0 || words > 64 {
        return Err(Error::Malformed);
    }
    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(wordlist[uniform(rng, wordlist.len() as u32)? as usize]);
    }
    Ok(out)
}

/// The EFF Long Wordlist (7,772 words; see `wordlist/README.md`).
pub fn wordlist() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| include_str!("wordlist/eff_large.txt").lines().collect())
}

/// Symbols [`Style::Words`] may add; ones every site accepts.
const WORD_SYMBOLS: &str = "!#$%&*?@";
/// Consonants and vowels for [`Style::Apple`]; no `l`, so nothing reads as `1` or `I`.
const CONSONANTS: &str = "bcdfghjkmnpqrstvwxz";
const VOWELS: &str = "aeiouy";

/// What kind of password to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Style {
    /// Random characters, as [`generate_password`].
    Random {
        /// Number of characters.
        length: usize,
        /// Which characters to use.
        charset: Charset,
    },
    /// Random words from [`wordlist`], as the UK NCSC's "three random words".
    Words {
        /// 3 to 10.
        words: usize,
        /// Up to 3 characters between words; may be empty.
        separator: String,
        /// Start each word with a capital letter.
        capitalize: bool,
        /// End with one digit and one symbol, for sites that demand them.
        number_and_symbol: bool,
    },
    /// Three groups of six letters joined by hyphens, with one capital and one
    /// digit, like the passwords Apple devices suggest: `fokjyb-Xewpud-hamu4s`.
    Apple,
}

impl Style {
    /// The UK NCSC's advice: three random words, written together with capitals.
    pub fn three_random_words() -> Self {
        Style::Words {
            words: 3,
            separator: String::new(),
            capitalize: true,
            number_and_symbol: false,
        }
    }

    /// How hard the result is to guess, in bits, for an attacker who knows
    /// the style and its settings.
    pub fn strength_bits(&self) -> f64 {
        match self {
            Style::Random { length, charset } => {
                let n: usize = [
                    (charset.lower, 26),
                    (charset.upper, 26),
                    (charset.digits, 10),
                    (charset.symbols, SYMBOLS.len()),
                ]
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, n)| n)
                .sum();
                let n = if charset.avoid_ambiguous {
                    n.saturating_sub(AMBIGUOUS.len())
                } else {
                    n
                };
                *length as f64 * (n.max(1) as f64).log2()
            }
            Style::Words {
                words,
                number_and_symbol,
                ..
            } => {
                let extra = if *number_and_symbol {
                    (10.0 * WORD_SYMBOLS.len() as f64).log2()
                } else {
                    0.0
                };
                *words as f64 * (wordlist().len() as f64).log2() + extra
            }
            Style::Apple => {
                // 18 letters, then one becomes a digit and another a capital.
                let letters = 3.0
                    * (2.0 * (VOWELS.len() as f64).log2() + 4.0 * (CONSONANTS.len() as f64).log2());
                let digit = (18.0 * 10.0f64).log2() - (CONSONANTS.len() as f64).log2();
                letters + digit + 17f64.log2()
            }
        }
    }
}

/// A password in `style`.
pub fn generate(rng: &mut dyn SecureRandom, style: &Style) -> Result<Zeroizing<String>, Error> {
    match style {
        Style::Random { length, charset } => generate_password(rng, *length, *charset),
        Style::Words {
            words,
            separator,
            capitalize,
            number_and_symbol,
        } => {
            if !(3..=10).contains(words) || separator.chars().count() > 3 {
                return Err(Error::Malformed);
            }
            let list = wordlist();
            let mut out = Zeroizing::new(String::new());
            for i in 0..*words {
                if i > 0 {
                    out.push_str(separator);
                }
                let w = list[uniform(rng, list.len() as u32)? as usize];
                let mut c = w.chars();
                if *capitalize && let Some(first) = c.next() {
                    out.push(first.to_ascii_uppercase());
                    out.push_str(c.as_str());
                } else {
                    out.push_str(w);
                }
            }
            if *number_and_symbol {
                out.push(pick(rng, "0123456789")?);
                out.push(pick(rng, WORD_SYMBOLS)?);
            }
            Ok(out)
        }
        Style::Apple => {
            let mut letters = Zeroizing::new(Vec::with_capacity(18));
            for _ in 0..3 {
                // Consonant-vowel syllables are easier to read out and type.
                for set in [
                    CONSONANTS, VOWELS, CONSONANTS, CONSONANTS, VOWELS, CONSONANTS,
                ] {
                    letters.push(pick(rng, set)?);
                }
            }
            let digit = uniform(rng, 18)? as usize;
            letters[digit] = pick(rng, "0123456789")?;
            let mut upper = uniform(rng, 17)? as usize;
            if upper >= digit {
                upper += 1;
            }
            letters[upper] = letters[upper].to_ascii_uppercase();
            let mut out = Zeroizing::new(String::with_capacity(20));
            for (i, c) in letters.iter().enumerate() {
                if i > 0 && i % 6 == 0 {
                    out.push('-');
                }
                out.push(*c);
            }
            Ok(out)
        }
    }
}

fn pick(rng: &mut dyn SecureRandom, set: &str) -> Result<char, Error> {
    let n = set.chars().count() as u32;
    Ok(set
        .chars()
        .nth(uniform(rng, n)? as usize)
        .expect("uniform stays below n"))
}
