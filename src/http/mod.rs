use crate::config::{DEF_ASSETS, SERVER_CONFIG};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tokio::net::TcpStream;

pub mod http_client;
pub mod http_server;
pub mod request;
pub mod response;
mod routes;
mod tcp_socket;
pub mod tls;
pub mod token;

#[derive(Debug)]
pub enum Method {
    Get,
    Post,
    Options,
}

pub trait MethodStr {
    fn to_method(&self) -> Method;
}

impl MethodStr for str {
    fn to_method(&self) -> Method {
        match self {
            "POST" => Method::Post,
            "OPTIONS" => Method::Options,
            _ => Method::Get,
        }
    }
}

pub async fn find_remote_ip_addr(conn: &mut TcpStream) -> String {
    //peer_addr can fail on a socket already closed by the client; that must end the task with a
    //placeholder, not a panic (panic=abort turns it into a process crash)
    match conn.peer_addr() {
        Ok(client_addr) => client_addr.ip().to_string().replace("::ffff:", ""),
        Err(_) => "unknown".to_string(),
    }
}

///request-supplied asset paths must not escape the assets directory.
///`..` components are rejected, NUL guards against truncation tricks and backslash matters on
///Windows builds where `..\` is an accepted separator; the URL is never percent-decoded here.
fn is_safe_asset_path(file_name: &str) -> bool {
    !file_name.contains('\0')
        && !file_name.contains('\\')
        && !file_name.split('/').any(|component| component == "..")
}

pub fn get_index_file_content(file_name: &str) -> Option<Vec<u8>> {
    if !is_safe_asset_path(file_name) {
        return None;
    }
    //normalize once here: empty path (root with query string) and missing leading slash
    let file_name = if file_name.is_empty() || file_name == "/" {
        "/index.html"
    } else {
        file_name
    };
    let file_name = if file_name.starts_with('/') {
        std::borrow::Cow::Borrowed(file_name)
    } else {
        std::borrow::Cow::Owned(format!("/{}", file_name))
    };
    let file_name = file_name.as_ref();
    if SERVER_CONFIG.get()?.assets_path.is_empty() {
        if file_name.contains("servers_list.js") {
            Some(generate_server_endpoint())
        } else {
            let file_name = &file_name[1..];
            let file = DEF_ASSETS.get_file(file_name)?;
            Some(Vec::from(file.contents()))
        }
    } else {
        let assets_dir = Path::new(SERVER_CONFIG.get()?.assets_path.as_str());
        let file_path = format!("{}{}", SERVER_CONFIG.get()?.assets_path, file_name);
        //canonicalizing resolves symlinks too, so a link out of the assets dir is rejected as well
        let assets_dir = assets_dir.canonicalize().ok()?;
        let real_file = Path::new(&file_path).canonicalize().ok()?;
        if !real_file.starts_with(&assets_dir) {
            return None;
        }
        if let Ok(mut file) = File::open(real_file) {
            let mut file_bytes = Vec::new();
            if file.read_to_end(&mut file_bytes).is_ok() {
                Some(file_bytes)
            } else {
                None
            }
        } else {
            None
        }
    }
}

fn generate_server_endpoint() -> Vec<u8> {
    let base_url = SERVER_CONFIG.get().unwrap().base_url.clone();
    let base_url = if base_url.is_empty() {
        "".to_string()
    } else {
        format!("{}/", &base_url[1..])
    };
    let endpoint = format!(
        r#"function get_servers() {{
        return [
            {{
                name : "Simple Server",
                server : window.location.origin,
                dlURL: "{base_url}garbage",
                ulURL: "{base_url}empty",
                pingURL: "{base_url}empty",
                getIpURL: "{base_url}getIP"
            }}
        ]
    }}"#
    );
    Vec::from(endpoint.as_bytes())
}

pub fn get_chunk_count(query_params: &HashMap<String, String>) -> i32 {
    //`ckSize` is a client-supplied query parameter on the always-open /garbage download route.
    //the old code only capped the upper end (`> 1024`) and let any other value through, then did
    //`chunks *= 2`: a negative input (e.g. -1073741825) overflows that doubling, which in the
    //release profile (overflow-checks off) wraps into a ~2.1-billion positive count and in debug
    //panics. handle_socket would then loop that many times writing a 512 KB garbage chunk -
    //a one-line, pre-auth CPU/bandwidth DoS. clamp both ends and double without ever overflowing
    let mut chunks = 4i32;
    if let Some(ck_size) = query_params.get("ckSize")
        && let Ok(parsed_ck_size) = ck_size.parse::<i32>()
    {
        chunks = parsed_ck_size.clamp(1, 1024);
    }
    chunks.saturating_mul(2)
}

#[macro_export]
macro_rules! make_route {
    ($a:expr) => {{
        let base_url = SERVER_CONFIG.get().unwrap().base_url.clone();
        format!("{}{}", base_url, $a)
    }};
}

#[cfg(test)]
mod tests {
    use super::get_chunk_count;
    use std::collections::HashMap;

    fn ck(raw: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("ckSize".to_string(), raw.to_string());
        m
    }

    #[test]
    fn chunk_count_is_always_a_bounded_loop_bound() {
        //no param / non-numeric falls back to the 4 -> 8 default
        assert_eq!(get_chunk_count(&HashMap::new()), 8);
        assert_eq!(get_chunk_count(&ck("banana")), 8);
        //normal in-range value doubles
        assert_eq!(get_chunk_count(&ck("10")), 20);
        //oversize clamps to 1024 -> 2048 (the biggest legit download)
        assert_eq!(get_chunk_count(&ck("100000")), 2048);
        //regression H2-1: negative / extreme inputs used to overflow `chunks *= 2`, wrapping to a
        //huge positive count in release (billions of garbage writes) or panicking in debug
        assert_eq!(get_chunk_count(&ck("-1073741825")), 2);
        assert_eq!(get_chunk_count(&ck("-1")), 2);
        assert_eq!(get_chunk_count(&ck(&i32::MIN.to_string())), 2);
        assert_eq!(get_chunk_count(&ck(&i32::MAX.to_string())), 2048);
        //whatever the client sends, the returned count stays inside a sane, non-negative band
        for raw in [
            "-2147483648",
            "-1073741825",
            "0",
            "1",
            "1024",
            "1025",
            "2000000000",
            "99999999999999999999",
        ] {
            let c = get_chunk_count(&ck(raw));
            assert!(
                (2..=2048).contains(&c),
                "ckSize={raw} produced out-of-bound chunk count {c}"
            );
        }
    }
}
