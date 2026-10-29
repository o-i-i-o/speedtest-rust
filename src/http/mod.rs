use std::collections::HashMap;
use tokio::net::TcpStream;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::config::{DEF_ASSETS, SERVER_CONFIG};

pub mod http_server;
mod routes;
pub mod request;
pub mod response;
pub mod cookie;
pub mod tls;
pub mod http_client;
mod tcp_socket;

#[derive(Debug)]
pub enum Method {
    Get,
    Post,
}

pub trait MethodStr {
    fn to_method(&self) -> Method;
}

impl MethodStr for str {
    fn to_method(&self) -> Method {
        match self {
            "GET" => Method::Get,
            "POST" => Method::Post,
            _ => Method::Get
        }
    }
}

pub async fn find_remote_ip_addr (conn: &mut TcpStream) -> String {
    let client_addr = conn.peer_addr().unwrap();
    client_addr.ip().to_string().replace("::ffff:","")
}

///request-supplied asset paths must not escape the assets directory.
///`..` components are rejected, NUL guards against truncation tricks and backslash matters on
///Windows builds where `..\` is an accepted separator; the URL is never percent-decoded here.
fn is_safe_asset_path(file_name : &str) -> bool {
    !file_name.contains('\0')
        && !file_name.contains('\\')
        && !file_name.split('/').any(|component| component == "..")
}

pub fn get_index_file_content(file_name : &str) -> Option<Vec<u8>> {
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
        let file_path = format!("{}{}",SERVER_CONFIG.get()?.assets_path,file_name);
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
        format!("{}/",&base_url[1..])
    };
    let endpoint = format!(r#"function get_servers() {{
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
    }}"#);
    Vec::from(endpoint.as_bytes())
}


pub fn get_chunk_count (query_params : &HashMap<String,String>) -> i32 {
    let mut chunks = 4;
    if let Some(ck_size) = query_params.get("ckSize") {
        if let Ok(parsed_ck_size) = ck_size.parse::<i32>() {
            if parsed_ck_size > 1024 {
                chunks = 1024
            } else {
                chunks = parsed_ck_size
            }
        }
    }
    chunks *= 2;
    chunks
}

#[macro_export]
macro_rules! make_route {
    ($a:expr) => {
        {
            let base_url = SERVER_CONFIG.get().unwrap().base_url.clone();
            format!("{}{}",base_url,$a)
        }
    };
}
