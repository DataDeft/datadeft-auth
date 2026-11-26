//! Bounded delegation to the existing production Branca API.

use datadeft_auth_token_core::branca;
use rand_core::OsRng;
use rustler::{Atom, Binary, Env, OwnedBinary, Term};

rustler::atoms! { invalid_input, invalid_token, unavailable }

#[rustler::nif(schedule = "DirtyCpu")]
fn branca_encode<'a>(
    env: Env<'a>,
    payload: Term<'a>,
    key: Term<'a>,
    timestamp: Term<'a>,
) -> Result<Binary<'a>, Atom> {
    let (Ok(payload), Ok(key), Ok(timestamp)) = (
        payload.decode::<Binary<'a>>(),
        key.decode::<Binary<'a>>(),
        timestamp.decode::<u32>(),
    ) else {
        return Err(invalid_input());
    };
    if payload.len() > branca::MAX_PAYLOAD_BYTES || key.len() != branca::KEY_BYTES {
        return Err(invalid_input());
    }
    let token = branca::encode(payload.as_slice(), key.as_slice(), &mut OsRng, timestamp)
        .map_err(|_| unavailable())?;
    copy_binary(env, token.as_bytes())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn branca_decode<'a>(
    env: Env<'a>,
    token: Term<'a>,
    key: Term<'a>,
) -> Result<(u32, Binary<'a>, Binary<'a>), Atom> {
    let (Ok(token), Ok(key)) = (token.decode::<Binary<'a>>(), key.decode::<Binary<'a>>()) else {
        return Err(invalid_token());
    };
    if token.len() > branca::MAX_TOKEN_BYTES || key.len() != branca::KEY_BYTES {
        return Err(invalid_token());
    }
    let token = std::str::from_utf8(token.as_slice()).map_err(|_| invalid_token())?;
    let verified = branca::decode(token, key.as_slice()).map_err(|_| invalid_token())?;
    Ok((
        verified.timestamp(),
        copy_binary(env, verified.nonce())?,
        copy_binary(env, verified.payload())?,
    ))
}

fn copy_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Binary<'a>, Atom> {
    let mut binary = OwnedBinary::new(bytes.len()).ok_or_else(unavailable)?;
    binary.as_mut_slice().copy_from_slice(bytes);
    Ok(binary.release(env))
}
