//! Big-number base62 encode / decode.
//!
//! A radix-62 encoding over a configurable 62-character alphabet. This is the
//! wire encoding for Branca tokens (see [`crate::branca`]). The standard
//! alphabet is `0-9A-Za-z`.
//!
//! # This is an integer codec, not a byte-string codec
//!
//! The input is treated as one big base-256 integer and re-expressed in base 62.
//! Two consequences follow, and callers MUST account for both:
//!
//! - **Leading `0x00` bytes are lost.** A blob starting with `0x00` does not
//!   survive `encode` → `decode`; the leading zero carries no digit weight.
//!   Branca is unaffected because every blob starts with the fixed `0xBA`
//!   version byte, but code that round-trips arbitrary bytes (hashes, IDs,
//!   serialized blobs) will silently corrupt them. Frame the length yourself, or
//!   use a byte-oriented codec (hex / base64) for that.
//! - **Decoding is non-canonical.** Leading `'0'` digits add no value, so
//!   `"X"`, `"0X"`, `"00X"`, … all decode to the same bytes, and embedded
//!   `\n` / `\r` are stripped. Do not treat a base62 string as a unique handle
//!   for its decoded value. Token layers that need a unique string (so that
//!   revocation / replay keys are stable) MUST re-encode and compare — see the
//!   canonicality gate in [`crate::branca::decode`].
//!
//! There is no length bound here; callers on untrusted input must cap the input
//! size themselves (the [`crate::branca`] layer does).

use std::error::Error;
use std::fmt;
use std::sync::LazyLock;

/// Standard base62 alphabet: digits, upper, lower.
pub const ENCODE_STD: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A base62 decode / encode failure.
///
/// Carries only the offending byte and position — never secret data.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Base62Error {
    /// An input byte is not in the alphabet.
    InvalidByte { byte: u8, position: usize },
    /// A custom alphabet was malformed (wrong length, duplicates, non-ASCII, or newline).
    InvalidAlphabet,
}

impl fmt::Display for Base62Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base62Error::InvalidByte { byte, position } => write!(
                f,
                "illegal base62 byte 0x{byte:02x} at position {position}",
                byte = *byte,
                position = *position,
            ),
            Base62Error::InvalidAlphabet => {
                f.write_str("base62 alphabet must be 62 unique ASCII non-newline bytes")
            }
        }
    }
}

impl Error for Base62Error {}

/// A radix-62 encoding defined by a 62-byte alphabet.
#[derive(Clone)]
pub struct Encoding {
    encode: [u8; 62],
    decode_map: [u8; 256],
}

impl Encoding {
    /// Build an encoding from a 62-byte alphabet.
    ///
    /// The alphabet must be exactly 62 ASCII bytes, contain no `\n` / `\r`,
    /// and have no duplicate bytes. User-supplied alphabets are validated; the
    /// standard alphabet should be obtained via [`Encoding::std`].
    pub fn new(alphabet: &str) -> Result<Self, Base62Error> {
        let bytes = alphabet.as_bytes();
        if bytes.len() != 62 {
            return Err(Base62Error::InvalidAlphabet);
        }
        if bytes
            .iter()
            .any(|&b| !b.is_ascii() || matches!(b, b'\n' | b'\r'))
        {
            return Err(Base62Error::InvalidAlphabet);
        }

        let mut encoding = Encoding {
            encode: [0; 62],
            decode_map: [0xFF; 256],
        };
        encoding.encode.copy_from_slice(bytes);

        // A duplicate byte would map two positions to the same value, breaking
        // round-tripping — reject it.
        #[allow(clippy::cast_possible_truncation)]
        for (i, &byte) in bytes.iter().enumerate() {
            if encoding.decode_map[byte as usize] != 0xFF {
                return Err(Base62Error::InvalidAlphabet);
            }
            encoding.decode_map[byte as usize] = i as u8;
        }

        Ok(encoding)
    }

    /// The standard `0-9A-Za-z` encoding. Built from the const
    /// [`ENCODE_STD`], which is known-valid at compile time, so this never
    /// validates or panics.
    #[must_use]
    pub fn std() -> Self {
        from_known_good_alphabet(ENCODE_STD)
    }

    /// Encode `src` to base62 bytes.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn encode(&self, src: &[u8]) -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }

        let allocated_len = ((src.len() as f64) * (256_f64.ln() / 62_f64.ln())).ceil() as usize;
        let mut result = vec![0u8; allocated_len];
        let mut significant_digits = 0;

        for &byte in src {
            let mut digits_this_pass = 0;
            let mut carry = usize::from(byte);

            for idx in (0..allocated_len).rev() {
                if carry == 0 && digits_this_pass >= significant_digits {
                    break;
                }
                carry += 256 * usize::from(result[idx]);
                #[allow(clippy::cast_possible_truncation)]
                let digit = (carry % 62) as u8;
                result[idx] = digit;
                carry /= 62;
                digits_this_pass += 1;
            }

            significant_digits = digits_this_pass;
        }

        for digit in &mut result {
            *digit = self.encode[usize::from(*digit)];
        }

        if allocated_len > significant_digits {
            result[allocated_len - significant_digits..].to_vec()
        } else {
            result
        }
    }

    /// Encode `src` to a base62 [`String`].
    #[must_use]
    pub fn encode_to_string(&self, src: &[u8]) -> String {
        let encoded = self.encode(src);
        // `Encoding::new` validates every alphabet byte as ASCII, and
        // `Encoding::std` is a known-good ASCII constant, so the Ok path moves
        // the encoded bytes into the String. The Err branch is unreachable for
        // validated alphabets but avoids panicking in production code if this
        // module is refactored incorrectly.
        match String::from_utf8(encoded) {
            Ok(value) => value,
            Err(err) => String::from_utf8_lossy(&err.into_bytes()).into_owned(),
        }
    }

    /// Decode base62 `src`, tolerating embedded `\n` / `\r`.
    pub fn decode(&self, src: &[u8]) -> Result<Vec<u8>, Base62Error> {
        // Strip newlines (some encoders wrap lines).
        let filtered: Vec<u8> = src
            .iter()
            .copied()
            .filter(|&b| b != b'\n' && b != b'\r')
            .collect();
        if filtered.is_empty() {
            return Ok(Vec::new());
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let allocated_len =
            ((filtered.len() as f64) * (62_f64.ln() / 256_f64.ln())).ceil() as usize;
        let mut result = vec![0u8; allocated_len];
        let mut significant_digits = 0;

        for (position, &byte) in filtered.iter().enumerate() {
            let mut digits_this_pass = 0;
            let decoded_val = self.decode_map[usize::from(byte)];

            if decoded_val == 0xFF {
                return Err(Base62Error::InvalidByte { byte, position });
            }

            let mut carry = usize::from(decoded_val);

            for idx in (0..allocated_len).rev() {
                if carry == 0 && digits_this_pass >= significant_digits {
                    break;
                }
                carry += 62 * usize::from(result[idx]);
                #[allow(clippy::cast_possible_truncation)]
                let byte_val = (carry % 256) as u8;
                result[idx] = byte_val;
                carry /= 256;
                digits_this_pass += 1;
            }

            significant_digits = significant_digits.max(digits_this_pass);
        }

        let start_idx = allocated_len.saturating_sub(significant_digits);
        result.drain(..start_idx);
        Ok(result)
    }

    /// Decode a base62 `&str`.
    pub fn decode_str(&self, s: &str) -> Result<Vec<u8>, Base62Error> {
        self.decode(s.as_bytes())
    }
}

/// Build an encoding from an alphabet known to be valid at compile time (the
/// const [`ENCODE_STD`]). Skips validation and therefore never fails or panics;
/// must not be exposed for arbitrary user input.
fn from_known_good_alphabet(alphabet: &[u8; 62]) -> Encoding {
    let mut encoding = Encoding {
        encode: *alphabet,
        decode_map: [0xFF; 256],
    };
    #[allow(clippy::cast_possible_truncation)]
    for (i, &byte) in alphabet.iter().enumerate() {
        encoding.decode_map[usize::from(byte)] = i as u8;
    }
    encoding
}

/// Shared standard-alphabet encoding. The 62-byte encode array and 256-byte
/// decode map are built once here instead of per call — Branca encode/decode
/// sits on the auth hot path.
static STD_ENCODING: LazyLock<Encoding> = LazyLock::new(Encoding::std);

/// Encode with the standard alphabet.
#[must_use]
pub fn encode(src: &[u8]) -> String {
    STD_ENCODING.encode_to_string(src)
}

/// Decode with the standard alphabet.
pub fn decode(s: &str) -> Result<Vec<u8>, Base62Error> {
    STD_ENCODING.decode_str(s)
}

#[cfg(test)]
#[path = "base62_tests.rs"]
mod tests;
