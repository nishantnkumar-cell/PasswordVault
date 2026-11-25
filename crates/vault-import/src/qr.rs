//! Read the QR code a site shows when it turns on two-factor sign-in, from
//! a screenshot or photo, so a one-time code can be added without typing
//! its setup key.

use zeroize::Zeroizing;

/// The largest image read, in pixels on a side; bigger ones are scaled down
/// first so a huge photo can't take minutes.
const MAX_SIDE: u32 = 2400;

/// Why no code came out of an image.
#[derive(Debug, PartialEq, Eq)]
pub enum QrError {
    /// Not a PNG, JPEG, GIF or BMP image, or a damaged one.
    Image(String),
    /// No QR code could be read.
    NoCode,
    /// A Google Authenticator export (`otpauth-migration://`), which holds
    /// many codes in its own format.
    Migration,
    /// A QR code, but not an authenticator one.
    NotOtp,
}

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            QrError::Image(m) => return write!(f, "can't read that image: {m}"),
            QrError::NoCode => {
                "no QR code found in that image; crop it to the code, or paste the setup key"
            }
            QrError::Migration => {
                "that is a Google Authenticator export, which isn't supported yet; \
                 add each code from its site, or paste each setup key"
            }
            QrError::NotOtp => "that QR code is not for an authenticator app",
        })
    }
}

impl std::error::Error for QrError {}

/// The `otpauth://` link in an image file's QR code. The link holds the
/// code's secret, so it is zeroized when dropped.
pub fn otpauth_from_image(bytes: &[u8]) -> Result<Zeroizing<String>, QrError> {
    let img = image::load_from_memory(bytes).map_err(|e| QrError::Image(e.to_string()))?;
    let img = if img.width().max(img.height()) > MAX_SIDE {
        img.thumbnail(MAX_SIDE, MAX_SIDE)
    } else {
        img
    };
    let luma = img.to_luma8();
    // A file can declare a picture with no width or height; the QR reader
    // assumes there is at least one pixel.
    if luma.width() == 0 || luma.height() == 0 {
        return Err(QrError::NoCode);
    }
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        luma.width() as usize,
        luma.height() as usize,
        |x, y| luma.get_pixel(x as u32, y as u32).0[0],
    );
    let mut other = false;
    for grid in prepared.detect_grids() {
        let Ok((_, text)) = grid.decode() else {
            continue;
        };
        let text = Zeroizing::new(text);
        let lower = text.trim().to_ascii_lowercase();
        if lower.starts_with("otpauth://") {
            return Ok(Zeroizing::new(text.trim().to_owned()));
        }
        if lower.starts_with("otpauth-migration://") {
            return Err(QrError::Migration);
        }
        other = true;
    }
    Err(if other {
        QrError::NotOtp
    } else {
        QrError::NoCode
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A PNG of `text` as a QR code, with a quiet zone, `scale` pixels per
    /// Found by the fuzzer: a GIF that declares a picture with no width.
    #[test]
    fn a_picture_with_no_area_is_an_error_not_a_crash() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x47, 0x49, 0x46, 0x38, 0x37, 0x61, 0x00, 0x00, 0xff, 0x00, 0xd8, 0xff,
            0xa3, 0x00, 0x7e, 0x7e, 0x98, 0x00, 0x42, 0x2c, 0x2c, 0x7e, 0x18, 0x00,
            0xd8, 0x0a, 0x00, 0x00, 0x7e, 0x07, 0xf2, 0x7e, 0x42, 0x5f, 0x57, 0x57,
            0x57, 0x56, 0x57, 0x57, 0x2a, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57,
            0x57, 0x57, 0x5f, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57,
            0x57, 0x47, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57,
            0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57,
            0x57, 0x57, 0x57, 0x57, 0x57, 0x29, 0x57, 0x49, 0x49, 0x2a, 0x10, 0x57,
            0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0xc3, 0xa9, 0x89,
            0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x22, 0x22, 0x22, 0x00, 0x00,
            0xb2, 0x22, 0x22, 0x22, 0x0c, 0xa8, 0xa8, 0xab, 0x57, 0xa1, 0x57, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x57, 0x57, 0x57, 0xd4,
            0x57, 0x57, 0x57, 0x57, 0xc3, 0xa9, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a,
            0x1a, 0x0a, 0x22, 0x22, 0x22, 0x00, 0x00, 0xb2, 0x22, 0x1f, 0x00, 0x00,
            0x00, 0xa8, 0xab, 0x57, 0xa1, 0xa8, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57,
            0xb8, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x0a,
        ];
        assert!(otpauth_from_image(bytes).is_err());
    }

    #[test]
    fn very_small_pictures_are_handled() {
        for (w, h) in [(1, 1), (1, 40), (40, 1), (2, 2), (7, 7)] {
            let mut png = Cursor::new(Vec::new());
            image::GrayImage::new(w, h)
                .write_to(&mut png, image::ImageFormat::Png)
                .unwrap();
            assert_eq!(
                otpauth_from_image(png.get_ref()).unwrap_err(),
                QrError::NoCode,
                "{w}x{h}"
            );
        }
    }

    /// module.
    fn qr_png(text: &str, scale: u32) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let n = code.width() as u32;
        let side = (n + 8) * scale;
        let img = image::GrayImage::from_fn(side, side, |x, y| {
            let (mx, my) = (x / scale, y / scale);
            let dark = (4..n + 4).contains(&mx)
                && (4..n + 4).contains(&my)
                && code[((mx - 4) as usize, (my - 4) as usize)] == qrcode::Color::Dark;
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn reads_an_authenticator_qr_code() {
        let link =
            "otpauth://totp/Example:alex%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        assert_eq!(otpauth_from_image(&qr_png(link, 6)).unwrap().as_str(), link);
    }

    #[test]
    fn explains_what_it_cannot_use() {
        assert_eq!(
            otpauth_from_image(&qr_png("https://example.com/", 6)),
            Err(QrError::NotOtp)
        );
        assert_eq!(
            otpauth_from_image(&qr_png("otpauth-migration://offline?data=AAAA", 6)),
            Err(QrError::Migration)
        );
        let blank = image::GrayImage::from_pixel(64, 64, image::Luma([255]));
        let mut png = Vec::new();
        blank
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(otpauth_from_image(&png), Err(QrError::NoCode));
        assert!(matches!(
            otpauth_from_image(b"not an image"),
            Err(QrError::Image(_))
        ));
    }
}
