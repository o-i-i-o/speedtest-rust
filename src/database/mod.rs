use std::io::Error;
use std::sync::Arc;
use async_trait::async_trait;
use log::info;
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::config::SERVER_CONFIG;
use crate::database::memory::MemoryDB;
#[cfg(feature = "mysql")]
use crate::database::mysql::MySql;
use crate::database::none::NoneDB;
#[cfg(feature = "postgres")]
use crate::database::postgres::Postgres;
#[cfg(feature = "sqlite")]
use crate::database::sqlite::SQLite;
use crate::results::TelemetryData;

#[cfg(feature = "mysql")]
mod mysql;
mod none;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;
mod memory;

#[async_trait]
pub trait Database {
    async fn insert(&mut self,data : TelemetryData) -> std::io::Result<()>;
    async fn fetch_by_uuid(&mut self,uuid : &str) -> std::io::Result<Option<TelemetryData>>;
    async fn fetch_last_100(&mut self) -> std::io::Result<Vec<TelemetryData>>;
}

pub trait DBRawToStruct<T> {
    fn to_telemetry_struct (&self) -> Result<TelemetryData,T>;
}

pub fn generate_uuid () -> String {
    Uuid::new_v4().to_string()
}

///percent-encode one path or userinfo segment of a connection URL. Credentials straight from
///configs.toml are interpolated into `scheme://user:pass@host/db`, so a password carrying
///`@ : / ? # %` used to silently move the authority boundary (misparsed host, or the tail of
///the secret leaking into a logged error). Unreserved chars stay literal, everything else
///becomes %XX byte-by-byte, which is always valid UTF-8 once sqlx percent-decodes the URL
pub fn escape_db_component (component : &str) -> String {
    let mut out = String::with_capacity(component.len());
    for byte in component.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub async fn init () -> std::io::Result<Arc<Mutex<dyn Database + Send>>> {
    let config = SERVER_CONFIG.get().unwrap();
    match config.database_type.as_str() {
        #[cfg(feature = "mysql")]
        "mysql" => {
            Ok(MySql::init(&config.database_username,&config.database_password,&config.database_hostname,&config.database_name).await?)
        }
        #[cfg(feature = "postgres")]
        "postgres" => {
            Ok(Postgres::init(&config.database_username,&config.database_password,&config.database_hostname,&config.database_name).await?)
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            Ok(SQLite::init(&config.database_file).await?)
        }
        "memory" => {
            Ok(MemoryDB::init())
        }
        "none" => {
            info!("Database disabled");
            Ok(Arc::new(Mutex::new(NoneDB)))
        }
        _ => {
            Err(Error::other("Invalid database type."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::escape_db_component;

    #[test]
    fn credential_characters_that_would_break_the_connection_url_are_escaped() {
        //regression: p@ss:word/1?#% used to reparse as a different authority (and the `#` tail
        //dropped entirely), while error echoes could leak the raw secret into logs
        assert_eq!(escape_db_component("simple-User_1.0"), "simple-User_1.0");
        assert_eq!(escape_db_component("p@ss:word/1?#%"), "p%40ss%3Aword%2F1%3F%23%25");
        //non-ASCII secrets survive the round trip as their UTF-8 bytes, hex-escaped
        assert_eq!(escape_db_component("é"), "%C3%A9");
    }
}