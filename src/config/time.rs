use chrono::{DateTime, Local};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn convert_time_local(time: i64) -> String {
    //a corrupt or hand-inserted telemetry row can carry an out-of-range timestamp; rendering a
    //result image must never panic the process over it
    match DateTime::from_timestamp_millis(time) {
        Some(dt) => {
            let local: DateTime<Local> = DateTime::from(dt);
            local.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        None => String::new(),
    }
}

pub fn current_formatted_time() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

#[allow(dead_code)]
pub fn convert_time_utc(time: i64) -> String {
    match DateTime::from_timestamp_millis(time) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => String::new(),
    }
}

pub fn get_current_millis() -> i64 {
    //a system clock set before the epoch is nonsensical but must not abort the process (panic=abort
    //in release): treat it as time 0, which the token TTL/skew checks reject just as safely
    let Ok(since_the_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    //checked math: a wildly wrong system clock must not wrap the i64 conversion
    let millis = since_the_epoch.as_secs().saturating_mul(1000)
        + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
    millis.min(i64::MAX as u64) as i64
}
