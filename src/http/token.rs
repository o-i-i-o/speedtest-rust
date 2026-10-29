use crate::database::generate_uuid;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const ID_PREFIX: &str = "_session";
const TOKEN_SEPARATOR: char = '.';
///session lifetime in milliseconds; the old cookie advertised Max-Age=3600 but never checked it
///server-side, so signing the issue time and enforcing it here is the actual fix for staleness.
pub const TOKEN_TTL_MILLIS: i64 = 3600 * 1000;

///opaque, stateless bearer token: `{id}.{issued_at}.{hmac_sha256(secret, id + "." + issued_at)}`.
///the signing key comes from configuration (never a compiled-in constant) and the issue time is
///covered by the signature, so a leaked token expires and a forged one needs the secret.
pub fn make_token(secret: &str, now_millis: i64) -> String {
    let token_id = format!("{}{}", ID_PREFIX, generate_uuid());
    let signature = sign(secret, &token_id, now_millis);
    format!("{token_id}{TOKEN_SEPARATOR}{now_millis}{TOKEN_SEPARATOR}{signature}")
}

pub fn validate_token(secret: &str, token: &str, now_millis: i64) -> bool {
    let mut split = token.splitn(3, TOKEN_SEPARATOR);
    let (Some(token_id), Some(issued_str), Some(signature)) =
        (split.next(), split.next(), split.next())
    else {
        return false;
    };
    let Ok(issued_at) = issued_str.parse::<i64>() else {
        return false;
    };
    //reject future-dated and expired tokens. checked_sub, because `issued_at` is attacker-supplied
    //and parsed before verification: a bare subtraction of i64::MIN underflows and panics, which
    //(with overflow-checks on) is a pre-auth per-connection DoS against every deployment state
    let Some(age) = now_millis.checked_sub(issued_at) else {
        return false;
    };
    if !(0..=TOKEN_TTL_MILLIS).contains(&age) {
        return false;
    }
    fixed_time_eq(
        signature.as_bytes(),
        sign(secret, token_id, issued_at).as_bytes(),
    )
}

///HMAC-SHA256 rather than the previous `sha256(id.issued.secret)` concatenation: a standard MAC
///construction, immune to any length-extension-shape concerns should the field order ever move
///the secret to the front.
fn sign(secret: &str, token_id: &str, issued_at: i64) -> String {
    //HMAC accepts keys of any length, so the only error here would be an impossible >2^64 key
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("unable to create hmac");
    mac.update(format!("{token_id}{TOKEN_SEPARATOR}{issued_at}").as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            write!(&mut acc, "{b:02x}").expect("unable to write");
            acc
        })
}

///pull the bearer credential out of an `Authorization` header value, if the scheme matches.
pub fn extract_bearer(authorization: Option<&String>) -> Option<&str> {
    let authorization = authorization?;
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

///compare without leaking the match length through early exit; used for the signature so an
///attacker cannot probe how many leading bytes of a forgery are correct.
pub fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "unit-test-secret";

    #[test]
    fn token_round_trips_within_ttl() {
        let now = 1_700_000_000_000;
        let token = make_token(SECRET, now);
        assert!(validate_token(SECRET, &token, now));
        //still valid right up to the boundary
        assert!(validate_token(SECRET, &token, now + TOKEN_TTL_MILLIS));
    }

    #[test]
    fn token_expires_and_rejects_future_issue() {
        let now = 1_700_000_000_000;
        let token = make_token(SECRET, now);
        assert!(
            !validate_token(SECRET, &token, now + TOKEN_TTL_MILLIS + 1),
            "expired token must be rejected"
        );
        assert!(
            !validate_token(SECRET, &token, now - 1),
            "future-dated token must be rejected"
        );
    }

    #[test]
    fn token_requires_the_correct_secret_and_rejects_tampering() {
        let now = 1_700_000_000_000;
        let token = make_token(SECRET, now);
        //a different signing secret (the whole point of moving the key out of the source) fails
        assert!(!validate_token("other-secret", &token, now));
        //the previous design let anyone forge `{id}.{sha256(id+const)}`; the id is attacker-chosen,
        //so a hand-built token without the secret must never validate
        assert!(!validate_token(SECRET, "_sessionforged.123.deadbeef", now));
        assert!(!validate_token(SECRET, &format!("x.{token}"), now));
        assert!(!validate_token(SECRET, "noseparator", now));
    }

    #[test]
    fn extreme_issued_at_values_never_panic() {
        //regression: `issued_at` is attacker-controlled and parsed before verification; the bare
        //subtraction used to underflow and panic on i64::MIN (pre-auth connection DoS, and with
        //overflow-checks + panic=abort a full process crash)
        let now = 1_700_000_000_000;
        assert!(!validate_token(
            SECRET,
            &format!("_sessionx.{}.deadbeef", i64::MIN),
            now
        ));
        assert!(!validate_token(
            SECRET,
            &format!("_sessionx.{}.deadbeef", i64::MAX),
            now
        ));
        assert!(!validate_token(
            SECRET,
            "_sessionx.-9223372036854775808.deadbeef",
            now
        ));
    }

    #[test]
    fn bearer_is_only_accepted_for_the_bearer_scheme() {
        let bearer = String::from("Bearer abc.def");
        assert_eq!(extract_bearer(Some(&bearer)), Some("abc.def"));
        let lower = String::from("bearer abc.def");
        assert_eq!(extract_bearer(Some(&lower)), Some("abc.def"));
        assert_eq!(extract_bearer(Some(&String::from("Basic abc.def"))), None);
        assert_eq!(extract_bearer(Some(&String::from("Bearer"))), None);
        assert_eq!(extract_bearer(Some(&String::from("Bearer   "))), None);
        assert_eq!(extract_bearer(None), None);
    }
}
