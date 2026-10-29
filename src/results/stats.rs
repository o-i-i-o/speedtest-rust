use std::sync::Arc;
use serde_json::json;
use tokio::sync::Mutex;
use crate::config::SERVER_CONFIG;
use crate::config::time::get_current_millis;
use crate::database::Database;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::token::{extract_bearer, fixed_time_eq, make_token, validate_token};

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
pub fn gate_stats (database_none : bool, password_empty : bool, token_valid : bool) -> StatsAccess {
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
///stats password does not learn the matching prefix length from early-exit timing.
pub fn password_matches (input : Option<&String>, expected : &str) -> bool {
    let Some(input) = input else {
        return false;
    };
    fixed_time_eq(input.as_bytes(), expected.as_bytes())
}

fn presented_token_is_valid (request : &Request, secret : &str) -> bool {
    extract_bearer(request.headers.get("Authorization"))
        .is_some_and(|token| validate_token(secret, token, get_current_millis()))
}

///`POST {base_url}/stats/login`
///Body is the shared secret sent as `application/x-www-form-urlencoded` (`password=...`), the one
///content type the request body parser turns into `form_data`. A valid password yields a bearer
///token signed with `stats_secret` and carrying an issue time; the client replays it in
///`Authorization: Bearer <token>`. No token is minted while statistics are disabled or unconfigured.
pub async fn handle_stats_login (request : &Request) -> Response {
    let server_config = SERVER_CONFIG.get().unwrap();
    if server_config.database_type == "none" {
        return Response::res_200_json(&json!({ "statistics": false }).to_string());
    }
    if server_config.stats_password.is_empty() {
        return Response::res_200_json(&json!({ "statistics": true, "configured": false }).to_string());
    }
    if password_matches(request.form_data.get("password"), &server_config.stats_password) {
        let token = make_token(&server_config.stats_secret, get_current_millis());
        Response::res_200_json(&json!({ "token": token }).to_string())
    } else {
        Response::res_403_json(&json!({ "error": "wrong password" }).to_string())
    }
}

///`GET {base_url}/stats/data[?id=<uuid>]`
///Returns the last 100 results, or the single result matching `id`. Timestamps are handed back as
///raw epoch milliseconds; the front-end formats them.
pub async fn handle_stats_data (request : &Request,database : &mut Arc<Mutex<dyn Database + Send>>) -> Response {
    let server_config = SERVER_CONFIG.get().unwrap();
    //early states short-circuit before any token parsing: unauthenticated attackers must not be
    //able to reach the signature/TTL logic (let alone the database) while stats are off. The
    //Disabled/NotConfigured gates below stay for the full branch matrix and the unit tests.
    if server_config.database_type == "none" {
        return Response::res_200_json(&json!({ "statistics": false }).to_string());
    }
    if server_config.stats_password.is_empty() {
        return Response::res_200_json(&json!({ "statistics": true, "configured": false }).to_string());
    }
    let access = gate_stats(false, false, presented_token_is_valid(request,&server_config.stats_secret));
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
            let id = request.query_params.get("id").map(|s| s.as_str()).unwrap_or("L100");
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
            Response::res_200_json(&json!({ "authenticated": true, "results": telemetry_list }).to_string())
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
        assert!(password_matches(ok.as_ref(), "hunter2"));
        assert!(!password_matches(Some(&String::from("hunter3")), "hunter2"));
        //a longer shared prefix must not match a shorter input or leak via the empty case
        assert!(!password_matches(Some(&String::from("hunt")), "hunter2"));
        assert!(!password_matches(None, "hunter2"));
        //an empty expected password would already have been routed to NotConfigured, but keep the
        //helper honest: empty input must never match a non-empty secret
        assert!(!password_matches(Some(&String::new()), "hunter2"));
    }
}
