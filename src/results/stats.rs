use crate::config::SERVER_CONFIG;
use crate::config::time::get_current_millis;
use crate::database::Database;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::token::{extract_bearer, fixed_time_eq, make_token, validate_token};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio::sync::Mutex as TokioMutex;

///access decision for the stats endpoints. Kept free of I/O and of the global config so the entire
///branch matrix can be unit tested without a database or a running server.
#[derive(PartialEq, Debug)]
pub enum StatsAccess {
    Disabled,      //no database: telemetry is off
    NotConfigured, //database on but no stats_password set -> nothing is served (restores the old SSR contract)
    Unauthorized,  //password set, caller has no valid token
    Authorized,    //password set and a valid token presented, or handled by the caller
}

///empty password used to mean "public"; that leaked every result to any anonymous request, so it
///now means "not configured". Public visibility would need an explicit opt-in, never a default.
pub fn gate_stats(database_none: bool, password_empty: bool, token_valid: bool) -> StatsAccess {
    if database_none {
        StatsAccess::Disabled
    } else if password_empty {
        StatsAccess::NotConfigured
    } else if token_valid {
        StatsAccess::Authorized
    } else {
        StatsAccess::Unauthorized
    }
}

///constant-time compare over the (already percent-decoded) form field, so online guessing of the
///stats password does not learn the matching prefix length from early-exit timing. An empty
///expected password is never a match: that state is gated to NotConfigured before this runs.
pub fn password_authorizes(input: Option<&String>, expected: &str) -> bool {
    !expected.is_empty() && password_matches(input, expected)
}

/*login rate limiting: the constant-time compare stops per-request timing leaks but does nothing
against throughput - an attacker can still try billions of passwords. Fixed window per address,
in-process (single source of truth on the current_thread default runtime; multi-process
setups should rate limit at the proxy). Every attempt reserves a slot atomically so a burst of
concurrent requests cannot slip past the budget before the counters update.*/
const LOGIN_WINDOW_MILLIS: i64 = 60 * 1000;
const LOGIN_MAX_ATTEMPTS: u32 = 10;
///hard ceiling on tracked addresses; opportunistic expired-window purge keeps the map from
///becoming a memory sink under IP-spoofed flood (headers are only trusted with trust_proxy,
///but the socket address of a real flood still lands here)
const LOGIN_TRACKED_MAX: usize = 4096;
static LOGIN_ATTEMPTS: OnceLock<Mutex<HashMap<String, (u32, i64)>>> = OnceLock::new();

///reserve one login attempt for `addr` in the current fixed window, returning false once the
///budget is spent. Check and increment happen under a SINGLE lock acquisition: the previous
///read-only `login_attempt_allowed` plus a separate `record_login_failure` was a check-then-act
///race that let a burst of concurrent requests all pass before any counter moved, defeating the
///limiter. Each attempt (even a successful one) reserves a slot, but a real admin uses far fewer
///than LOGIN_MAX_ATTEMPTS per minute; and without trust_proxy the key is the socket address, so
///one attacker's flood only drains their own bucket and can never lock out a different client.
fn register_login_attempt(addr: &str, now_millis: i64) -> bool {
    let table = LOGIN_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()));
    //a poisoned lock (a panic elsewhere while holding it) must not skip the limit: fail closed
    let mut table = table.lock().unwrap_or_else(|e| e.into_inner());
    if table.len() > LOGIN_TRACKED_MAX {
        table.retain(|_, (_, start)| now_millis - *start <= LOGIN_WINDOW_MILLIS);
    }
    let entry = table.entry(addr.to_string()).or_insert((0, now_millis));
    //the old window has lapsed: start a fresh one and let this attempt be its first
    if now_millis - entry.1 > LOGIN_WINDOW_MILLIS {
        *entry = (0, now_millis);
    }
    if entry.0 >= LOGIN_MAX_ATTEMPTS {
        return false;
    }
    entry.0 += 1;
    true
}

fn password_matches(input: Option<&String>, expected: &str) -> bool {
    let Some(input) = input else {
        return false;
    };
    fixed_time_eq(input.as_bytes(), expected.as_bytes())
}

fn presented_token_is_valid(request: &Request, secret: &str) -> bool {
    extract_bearer(request.headers.get("Authorization"))
        .is_some_and(|token| validate_token(secret, token, get_current_millis()))
}

///`POST {base_url}/stats/login`
///Body is the shared secret sent as `application/x-www-form-urlencoded` (`password=...`), the one
///content type the request body parser turns into `form_data`. A valid password yields a bearer
///token signed with `stats_secret` and carrying an issue time; the client replays it in
///`Authorization: Bearer <token>`. No token is minted while statistics are disabled or unconfigured.
///Every attempt is rate limited per address (429 once the window budget is spent).
pub async fn handle_stats_login(request: &Request) -> Response {
    let server_config = SERVER_CONFIG.get().unwrap();
    if server_config.database_type == "none" {
        return Response::res_200_json(&json!({ "statistics": false }).to_string());
    }
    if server_config.stats_password.is_empty() {
        return Response::res_200_json(
            &json!({ "statistics": true, "configured": false }).to_string(),
        );
    }
    //the limiter reserves a slot for every attempt before the compare, so a wrong-password flood
    //cannot out-parallel the budget; the compare is constant-time and never reveals proximity
    if !register_login_attempt(&request.remote_addr, get_current_millis()) {
        return Response::res_429_json(
            &json!({ "error": "too many failed login attempts, try again later" }).to_string(),
        );
    }
    if password_authorizes(
        request.form_data.get("password"),
        &server_config.stats_password,
    ) {
        let token = make_token(&server_config.stats_secret, get_current_millis());
        Response::res_200_json(&json!({ "token": token }).to_string())
    } else {
        Response::res_403_json(&json!({ "error": "wrong password" }).to_string())
    }
}

///`GET {base_url}/stats/data[?id=<uuid>]`
///Returns the last 100 results, or the single result matching `id`. Timestamps are handed back as
///raw epoch milliseconds; the front-end formats them.
pub async fn handle_stats_data(
    request: &Request,
    database: &mut Arc<TokioMutex<dyn Database + Send>>,
) -> Response {
    let server_config = SERVER_CONFIG.get().unwrap();
    //early states short-circuit before any token parsing: unauthenticated attackers must not be
    //able to reach the signature/TTL logic (let alone the database) while stats are off. The
    //Disabled/NotConfigured gates below stay for the full branch matrix and the unit tests.
    if server_config.database_type == "none" {
        return Response::res_200_json(&json!({ "statistics": false }).to_string());
    }
    if server_config.stats_password.is_empty() {
        return Response::res_200_json(
            &json!({ "statistics": true, "configured": false }).to_string(),
        );
    }
    let access = gate_stats(
        false,
        false,
        presented_token_is_valid(request, &server_config.stats_secret),
    );
    match access {
        StatsAccess::Disabled => {
            Response::res_200_json(&json!({ "statistics": false }).to_string())
        }
        StatsAccess::NotConfigured => {
            Response::res_200_json(&json!({ "statistics": true, "configured": false }).to_string())
        }
        StatsAccess::Unauthorized => {
            Response::res_401_json(&json!({ "error": "authentication required" }).to_string())
        }
        StatsAccess::Authorized => {
            //only authenticated requests reach the database
            let mut db = database.lock().await;
            //normalize the id: an absent or empty id, and the legacy "L100" sentinel, all mean last-100
            let id = request
                .query_params
                .get("id")
                .map(|s| s.as_str())
                .unwrap_or("L100");
            let telemetry_list = if id == "L100" || id.is_empty() {
                match db.fetch_last_100().await {
                    Ok(data) => data,
                    Err(_) => {
                        return Response::res_500();
                    }
                }
            } else {
                match db.fetch_by_uuid(id).await {
                    Ok(Some(data)) => vec![data],
                    Ok(None) => Vec::new(),
                    Err(_) => {
                        return Response::res_500();
                    }
                }
            };
            Response::res_200_json(
                &json!({ "authenticated": true, "results": telemetry_list }).to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_prefers_disabled_over_everything() {
        //no database wins even if a password is set and a token looks valid
        assert_eq!(gate_stats(true, false, true), StatsAccess::Disabled);
        assert_eq!(gate_stats(true, true, false), StatsAccess::Disabled);
    }

    #[test]
    fn empty_password_is_not_public_anymore() {
        //regression guard: with a database but no password nothing must be served
        assert_eq!(gate_stats(false, true, false), StatsAccess::NotConfigured);
        //a forged/valid token does not bypass the "not configured" state either
        assert_eq!(gate_stats(false, true, true), StatsAccess::NotConfigured);
    }

    #[test]
    fn protected_stats_require_a_valid_token() {
        assert_eq!(gate_stats(false, false, false), StatsAccess::Unauthorized);
        assert_eq!(gate_stats(false, false, true), StatsAccess::Authorized);
    }

    #[test]
    fn password_matches_is_exact_and_absent_aware() {
        let ok = Some(String::from("hunter2"));
        assert!(password_authorizes(ok.as_ref(), "hunter2"));
        assert!(!password_authorizes(
            Some(&String::from("hunter3")),
            "hunter2"
        ));
        //a longer shared prefix must not match a shorter input or leak via the empty case
        assert!(!password_authorizes(Some(&String::from("hunt")), "hunter2"));
        assert!(!password_authorizes(None, "hunter2"));
        //an empty expected password would already have been routed to NotConfigured, but keep the
        //helper honest: it must never authorize, with empty input or otherwise
        assert!(!password_authorizes(Some(&String::new()), ""));
        assert!(!password_authorizes(Some(&String::from("anything")), ""));
        assert!(!password_authorizes(Some(&String::new()), "hunter2"));
    }

    #[test]
    fn login_limiter_locks_after_the_budget_then_resets() {
        let base = 1_700_000_000_000;
        let addr = "198.51.100.7";
        //each attempt reserves one slot; the first LOGIN_MAX_ATTEMPTS in a window are allowed
        for i in 0..LOGIN_MAX_ATTEMPTS {
            assert!(
                register_login_attempt(addr, base),
                "attempt {i} within budget must be allowed"
            );
        }
        //budget spent: the next attempt inside the same window is refused...
        assert!(!register_login_attempt(
            addr,
            base + LOGIN_WINDOW_MILLIS - 1
        ));
        //...and the budget resets once the window rolls over
        assert!(register_login_attempt(addr, base + LOGIN_WINDOW_MILLIS + 1));
        //another address is unaffected by this one's lockout
        assert!(register_login_attempt("198.51.100.8", base));
    }
}
