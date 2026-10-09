//! Bound-payload framing: typ, kid, and iat inside the encrypted body, and its size budget.

use crate::branca::{self};
use crate::error::TokenError;
use crate::keyring::{KeyId, KeyPurpose};

use super::*;

/// Bound cookie payload version byte (internal binary framing).
const PAYLOAD_V1: u8 = 1;

pub(super) fn max_body_bytes_for_parts<P: KeyPurpose>(typ: &str, kid: &str) -> usize {
    branca::MAX_PAYLOAD_BYTES
        .min(P::MAX_BODY_BYTES)
        .saturating_sub(bound_payload_overhead(typ, kid))
}

pub(super) fn max_cookie_token_bytes<P: KeyPurpose>(kid: &KeyId) -> usize {
    branca::max_token_chars_for_payload(
        bound_payload_overhead(P::TOKEN_TYPE, kid.as_str())
            .saturating_add(max_body_bytes::<P>(kid)),
    )
}

fn bound_payload_overhead(typ: &str, kid: &str) -> usize {
    1 + 4 + 1 + typ.len() + 1 + kid.len()
}

/// Decoded view over the internal bound-cookie payload framing.
pub(super) struct DecodedPayload<'a> {
    pub(super) iat: u32,
    pub(super) typ: &'a [u8],
    pub(super) kid: &'a [u8],
    pub(super) body: &'a [u8],
}

/// Encode the bound payload with a fixed binary framing. This payload is
/// internal and never parsed by a client, so it uses a compact length-prefixed
/// layout rather than JSON: no byte-array expansion and no self-describing
/// codec surface:
///
/// `v(1) || iat(4 BE) || typ_len(1) || typ || kid_len(1) || kid || body`
pub(super) fn encode_bound_payload<P: KeyPurpose>(
    typ: &str,
    kid: &str,
    iat: u32,
    body: &[u8],
) -> Result<Vec<u8>, TokenError> {
    if body.len() > max_body_bytes_for_parts::<P>(typ, kid) {
        return Err(TokenError::PayloadTooLarge);
    }

    let typ = typ.as_bytes();
    let kid = kid.as_bytes();
    // `typ` is a small crate constant and `kid` is <= 64 bytes via KeyId::parse.
    // The length prefixes are single bytes, so both must fit in a u8.
    if typ.len() > usize::from(u8::MAX) || kid.len() > usize::from(u8::MAX) {
        return Err(TokenError::Internal);
    }

    let mut out = Vec::with_capacity(1 + 4 + 1 + typ.len() + 1 + kid.len() + body.len());
    out.push(PAYLOAD_V1);
    out.extend_from_slice(&iat.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)] // bounded above
    out.push(typ.len() as u8);
    out.extend_from_slice(typ);
    #[allow(clippy::cast_possible_truncation)] // bounded above
    out.push(kid.len() as u8);
    out.extend_from_slice(kid);
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse the fixed binary framing. Every field is bounds-checked. Any short or
/// malformed buffer is a generic failure. The buffer is authenticated by the
/// AEAD before it reaches here, so this only guards against our own invariants.
pub(super) fn decode_bound_payload(buf: &[u8]) -> Result<DecodedPayload<'_>, TokenError> {
    if *buf.first().ok_or(TokenError::InvalidToken)? != PAYLOAD_V1 {
        return Err(TokenError::InvalidToken);
    }
    let iat_bytes = buf.get(1..5).ok_or(TokenError::InvalidToken)?;
    let iat = u32::from_be_bytes([iat_bytes[0], iat_bytes[1], iat_bytes[2], iat_bytes[3]]);
    let mut i = 5usize;

    let typ_len = usize::from(*buf.get(i).ok_or(TokenError::InvalidToken)?);
    i += 1;
    let typ = buf.get(i..i + typ_len).ok_or(TokenError::InvalidToken)?;
    i += typ_len;

    let kid_len = usize::from(*buf.get(i).ok_or(TokenError::InvalidToken)?);
    i += 1;
    let kid = buf.get(i..i + kid_len).ok_or(TokenError::InvalidToken)?;
    i += kid_len;

    let body = buf.get(i..).ok_or(TokenError::InvalidToken)?;
    Ok(DecodedPayload {
        iat,
        typ,
        kid,
        body,
    })
}
