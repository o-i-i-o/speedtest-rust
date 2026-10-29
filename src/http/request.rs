use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;
use log::{trace, warn};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::time::timeout;
use case_insensitive_hashmap::CaseInsensitiveHashMap as CIHashMap;
use crate::config::{GARBAGE_DATA, SERVER_CONFIG};
use crate::http::{Method, MethodStr};
use crate::http::response::Response;

///idle read budgets: every socket wait is bounded so a stalled or malicious client cannot pin
///a connection task forever (slowloris). Generous for bulk uploads, tight for line reads.
const STATUS_LINE_TIMEOUT : Duration = Duration::from_secs(30);
const HEADER_LINE_TIMEOUT : Duration = Duration::from_secs(30);
const BODY_READ_TIMEOUT : Duration = Duration::from_secs(300);
///a single request/status line may not exceed this, bounding per-connection buffering
const MAX_LINE_LEN : usize = 64 * 1024;
///chunk-size lines are tiny; anything longer is not a chunked body
const MAX_CHUNK_LINE_LEN : usize = 128;

#[derive(Debug)]
pub struct Request {
    pub path: String,
    pub method: Method,
    pub remote_addr : String,
    pub query_params: HashMap<String, String>,
    pub headers: CIHashMap<String>,
    pub form_data : HashMap<String, String>
}

#[derive(Debug)]
enum BodyType {
    Fixed,
    Chunked,
    Form,
    FormUrlEncoded
}

///outcome of one bounded line read; `TooLarge` means the client sent a line beyond MAX_LINE_LEN
///without a newline, which must end the connection instead of buffering forever
enum LineRead {
    Value(String),
    TooLarge,
    Empty,
}

async fn read_line<R>(buf_reader : &mut BufReader<R>, limit : Duration, max_len : usize) -> LineRead
where
    R: AsyncReadExt + Unpin
{
    match timeout(limit, buf_reader.lines().next_line()).await {
        Ok(Ok(Some(line))) if line.len() <= max_len => LineRead::Value(line),
        Ok(Ok(Some(_))) => LineRead::TooLarge,
        //EOF, an I/O error or a decode failure all end the connection the same way
        Ok(_) => LineRead::Empty,
        Err(_) => LineRead::Empty,
    }
}

///exactly `want` bytes or give up: every read is bounded and a short return (EOF) fails the
///whole call, so callers never hang on a client that promised bytes it will not send
async fn read_exact_bounded<R>(buf_reader : &mut BufReader<R>, want : usize, limit : Duration) -> bool
where
    R: AsyncReadExt + Unpin
{
    let mut gathered = Vec::with_capacity(want);
    let mut scratch = [0u8; 8192];
    while gathered.len() < want {
        let take = (want - gathered.len()).min(scratch.len());
        match timeout(limit, buf_reader.read(&mut scratch[..take])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return false,
            Ok(Ok(n)) => gathered.extend_from_slice(&scratch[..n]),
        }
    }
    true
}

///drain and discard the body of a Content-Length request. `read` counts the bytes actually
///returned, so any Content-Length is safe (the old fixed-buffer `read_exact` loop demanded a
///full final buffer and hung or over-read into the pipelined next request)
async fn drain_fixed_body<R>(buf_reader : &mut BufReader<R>, body_size : u64)
where
    R: AsyncReadExt + Unpin
{
    let mut buffer = [0u8; 65536];
    let mut remaining = body_size as usize;
    while remaining > 0 {
        let want = remaining.min(buffer.len());
        match timeout(BODY_READ_TIMEOUT, buf_reader.read(&mut buffer[..want])).await {
            Ok(Ok(0)) => break,          //peer closed before sending it all
            Ok(Ok(n)) => remaining -= n, //count what we actually read
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

///spec-conformant `Transfer-Encoding: chunked` consumer: size line, data, trailing CRLF, repeat
///until the zero chunk, then swallow trailers up to the blank line so the pipelined next request
///starts at a clean boundary. The previous implementation blind-read 1024-byte blocks, which
///desynchronized the stream. Returns the byte count seen, or None on a broken/oversized stream;
///every wait is bounded, so a stalled sender cannot wedge the task
async fn consume_chunked_body<R>(buf_reader : &mut BufReader<R>) -> Option<u64>
where
    R: AsyncReadExt + Unpin
{
    let mut total = 0u64;
    loop {
        let line = match read_line(buf_reader, BODY_READ_TIMEOUT, MAX_CHUNK_LINE_LEN).await {
            LineRead::Value(line) => line,
            //oversized "size line": stop framing, but keep draining to the terminating 0 chunk
            //so a following pipelined request is not swallowed as body data
            LineRead::TooLarge => {
                loop {
                    match read_line(buf_reader, BODY_READ_TIMEOUT, MAX_CHUNK_LINE_LEN).await {
                        LineRead::Value(l) => if l.trim().is_empty() { return None },
                        LineRead::Empty | LineRead::TooLarge => return None,
                    }
                }
            }
            LineRead::Empty => return None,
        };
        //chunk-size lines may carry ;ext parameters after the hex length
        let size_str = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = u64::from_str_radix(size_str, 16) else {
            trace!("bad chunk size line : {size_str:?}");
            return None;
        };
        if size == 0 {
            //trailer headers, if any, run until the empty line (RFC 9112 §7.1.2.1); they are
            //ignored here, but they must be drained so keep-alive framing stays intact
            loop {
                match read_line(buf_reader, BODY_READ_TIMEOUT, MAX_LINE_LEN).await {
                    LineRead::Value(l) if l.is_empty() => return Some(total),
                    LineRead::Value(_) => {}
                    LineRead::Empty | LineRead::TooLarge => return None,
                }
            }
        }
        total = match total.checked_add(size) {
            Some(t) if t <= crate::config::MAX_CHUNKED_BODY_BYTES => t,
            //a chunked stream beyond the cap is a flood, not an upload: stop reading and drop
            //the connection rather than draining an attacker-chosen amount of bytes
            _ => {
                warn!("rejected oversized chunked request body (cap {} bytes)", crate::config::MAX_CHUNKED_BODY_BYTES);
                return None;
            }
        };
        //never buffer an attacker-sized chunk: drain it in capped pieces
        let mut remaining = size;
        let mut scratch = [0u8; 8192];
        while remaining > 0 {
            let take = remaining.min(scratch.len() as u64) as usize;
            match timeout(BODY_READ_TIMEOUT, buf_reader.read(&mut scratch[..take])).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => remaining -= n as u64,
            }
        }
        //the CRLF that terminates every chunk
        if !read_exact_bounded(buf_reader, 2, BODY_READ_TIMEOUT).await {
            return None;
        }
    }
}

pub async fn handle_socket<R,W,F>(remote_addr : &str,buf_reader: &mut BufReader<R>,buf_writer : &mut BufWriter<W>,result : F)
    where
R: AsyncReadExt + Unpin,
W: AsyncWriteExt + Unpin,
F: Send + Sync + Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>>
{
    'root_loop:loop {
        //read status line, bounded; a missing/unparsable line ends the connection
        let parsed_status = {
            match read_line(buf_reader, STATUS_LINE_TIMEOUT, MAX_LINE_LEN).await {
                LineRead::Value(status_line) => {
                    let status_lower = status_line.to_lowercase();
                    if check_is_status_line(status_lower) {
                        match parse_request_status_line(status_line) {
                            Some(parsed) => parsed,
                            //malformed request line (`GET HTTP/1.1`): end the connection, never panic
                            None => break 'root_loop,
                        }
                    } else {
                        break 'root_loop;
                    }
                }
                LineRead::TooLarge | LineRead::Empty => break 'root_loop,
            }
        };
        //read headers
        let parsed_headers = header_parser(buf_reader).await;
        //reject oversized or unparsable bodies before reading anything: an attacker-supplied
        //Content-Length must never reach with_capacity or an unbounded drain loop
        if let Some(reject) = check_body_limit(&parsed_headers) {
            write_simple(buf_writer, reject).await;
            break 'root_loop;
        }
        //honor `Expect: 100-continue` (RFC 9110 §10.1.1) by sending the interim 100 response
        //*before* reading the body. Without it, clients that use Expect (curl and many HTTP
        //libraries) wait out their continue-timeout (~1s for curl) on every upload request.
        if let Some(expect) = parsed_headers.get("Expect") {
            if expect.eq_ignore_ascii_case("100-continue")
                && buf_writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.is_ok()
            {
                let _ = buf_writer.flush().await;
            }
        }
        //read body content
        let body_form_data = {
            let (body_type,body_size) = check_has_body(&parsed_headers);
            match body_type {
                Some(body_type) => {
                    match body_type {
                        BodyType::Fixed => {
                            if let Some(body_size) = body_size {
                                drain_fixed_body(buf_reader, body_size).await;
                            }
                            None
                        }
                        BodyType::Chunked => {
                            if consume_chunked_body(buf_reader).await.is_none() {
                                //broken or oversized chunked stream: framing is lost, close
                                write_simple(buf_writer, "413 Payload Too Large").await;
                                break 'root_loop;
                            }
                            None
                        }
                        BodyType::Form => {
                            let form_boundary = parsed_headers
                                .get("Content-Type")
                                .and_then(|ct| get_content_boundary(ct));
                            match (form_boundary, body_size) {
                                (Some(form_boundary), Some(body_size)) => {
                                    let body = read_limited_body(buf_reader, body_size as usize).await;
                                    Some(parse_form_data(&form_boundary, &body))
                                }
                                _ => None,
                            }
                        }
                        BodyType::FormUrlEncoded => {
                            match body_size {
                                Some(body_size) => {
                                    let body = read_limited_body(buf_reader, body_size as usize).await;
                                    Some(parse_form_url_encoded(&body))
                                }
                                None => None,
                            }
                        }
                    }
                }
                None => None,
            }
        };
        //trust proxy
        let trust_proxy = SERVER_CONFIG.get().is_some_and(|c| c.trust_proxy);
        let remote_addr = trust_addr_proxy(&parsed_headers, remote_addr, trust_proxy);
        //gen request
        let response = result(Request {
            path: parsed_status.1,
            method: parsed_status.0,
            remote_addr,
            query_params: parsed_status.2,
            headers: parsed_headers,
            form_data : body_form_data.clone().unwrap_or(HashMap::new())
        }).await;
        if let Err(e) = buf_writer.write_all(&response.data).await {
            trace!("Error socket write : {e}")
        }
        if response.chunk_count > 0 {
            for _ in 0..response.chunk_count {
                if let Err(e) = buf_writer.write_all(GARBAGE_DATA.get().unwrap()).await {
                    trace!("Error socket write chunk : {e}")
                }
            }
            if let Err(e) = buf_writer.write_all(b"0\r\n\r\n").await {
                trace!("Error socket write eof : {e}")
            }
        }
        if let Err(e) = buf_writer.flush().await {
            trace!("Error socket flush : {e}")
        }
    }
}

//allow http 1.* & POST, GET, OPTIONS methods
fn check_is_status_line (line : String) -> bool {
    line.contains("http/1.") && (line.starts_with("get") || line.starts_with("options") || line.starts_with("post"))
}

///parse `METHOD SP PATH SP VERSION`; a request line without all three parts is a 400-worthy
///malformation, never an unwrap() panic (which aborts the whole process under panic=abort)
fn parse_request_status_line (line : String) -> Option<(Method,String,HashMap<String, String>)> {
    let mut split_status = line.split(' ');
    let (Some(method_str), Some(raw_path), Some(_version)) = (split_status.next(), split_status.next(), split_status.next()) else {
        return None;
    };
    let (path,query_params) = parse_raw_path(raw_path);
    Some((method_str.to_method(),path,query_params))
}

pub async fn header_parser<R>(buf_reader: &mut BufReader<R>) -> CIHashMap<String>
where
    R: AsyncReadExt + Unpin
{
    let mut headers_out = CIHashMap::new();
    'header_loop:loop {
        match read_line(buf_reader, HEADER_LINE_TIMEOUT, MAX_LINE_LEN).await {
            LineRead::Value(header_line) => {
                if header_line.is_empty() {
                    break 'header_loop;
                }
                let mut header_parts = header_line.splitn(2, ':');
                if let (Some(header_key),Some(header_val)) = (header_parts.next(),header_parts.next()) {
                    headers_out.insert(header_key.trim().to_string(),header_val.trim().to_string());
                }
            }
            //oversized header or EOF/timeout: stop parsing; the request is malformed at that point
            LineRead::TooLarge | LineRead::Empty => break 'header_loop,
        }
    }
    headers_out
}

///read at most `max` body bytes; the read loop is timeout-bounded and a peer that stops early
///just yields what arrived, instead of panicking the connection task
async fn read_limited_body<R>(buf_reader : &mut BufReader<R>, max : usize) -> Vec<u8>
where
    R: AsyncReadExt + Unpin
{
    let mut body = Vec::with_capacity(max.min(8192));
    let mut scratch = [0u8; 8192];
    while body.len() < max {
        let take = (max - body.len()).min(scratch.len());
        match timeout(BODY_READ_TIMEOUT, buf_reader.read(&mut scratch[..take])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => body.extend_from_slice(&scratch[..n]),
        }
    }
    body
}

///pre-read body validation. Returns Some(status) to answer and close the connection:
///- unparsable Content-Length (or duplicate headers collapsing to `42, 42`) would otherwise be
///  silently treated as 0 and desynchronize keep-alive framing
///- an oversized body must never be allocated or drained; form endpoints only need kilobytes,
///  uploads (Fixed) are capped by MAX_BODY_SIZE_BYTES, chunked streams by MAX_CHUNKED_BODY_BYTES
fn check_body_limit(headers : &CIHashMap<String>) -> Option<&'static str> {
    let content_len_raw = headers.get("Content-Length").map(|s| s.as_str());
    let body_type = headers.get("Content-Type").map(|content_type| {
        if content_type.starts_with("multipart/form-data;") {
            BodyType::Form
        } else if content_type.starts_with("application/x-www-form-urlencoded") {
            BodyType::FormUrlEncoded
        } else {
            BodyType::Fixed
        }
    });
    if let Some(raw) = content_len_raw {
        let Ok(content_len) = raw.parse::<u64>() else {
            return Some("400 Bad Request");
        };
        if content_len > 0 {
            let cap = match body_type {
                Some(BodyType::Form) | Some(BodyType::FormUrlEncoded) => crate::config::MAX_FORM_BODY_BYTES,
                _ => crate::config::MAX_BODY_SIZE_BYTES,
            };
            if content_len > cap {
                warn!("rejected oversized request body: {content_len} bytes");
                return Some("413 Payload Too Large");
            }
        }
    }
    None
}

fn check_has_body(headers : &CIHashMap<String>) -> (Option<BodyType>,Option<u64>) {
    let content_type_form = if let Some(content_type) = headers.get("Content-Type") {
        if content_type.starts_with("multipart/form-data;") {
            Some(BodyType::Form)
        } else if content_type.starts_with("application/x-www-form-urlencoded") {
            Some(BodyType::FormUrlEncoded)
        } else {
            None
        }
    } else {
        None
    };
    //check fixed body
    if let Some(content_len) = headers.get("Content-Length") {
        let content_len = content_len.parse::<u64>().unwrap_or(0);
        if content_len > 0 {
            let body_type = if let Some(content_type_form) = content_type_form {
                content_type_form
            } else {
                BodyType::Fixed
            };
            return (Some(body_type),Some(content_len))
        };
    };
    //check chunked body
    if let Some(transfer_encoding) = headers.get("Transfer-Encoding") {
        if transfer_encoding == "chunked" {
            return (Some(BodyType::Chunked),Some(0))
        }
    }
    (None,None)
}

///send a minimal error response and end the connection; used by pre-read rejections where no
///handler ran and the body was never consumed
async fn write_simple<W>(buf_writer : &mut BufWriter<W>, status : &str) -> ()
where
    W: AsyncWriteExt + Unpin
{
    let body = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n");
    let _ = buf_writer.write_all(body.as_bytes()).await;
    let _ = buf_writer.flush().await;
}

fn parse_raw_path(raw_path: &str) -> (String, HashMap<String, String>) {
    //strip query first, then normalize the path itself ("/" must survive trailing-slash removal).
    //the path is intentionally NOT percent-decoded: a literal `%2e%2e` is matched verbatim
    //against the embedded/disk asset index and resolves to nothing (404), while a real `..`
    //component is already caught by is_safe_asset_path. Decoding here would also turn `+` in a
    //path into a space, which is wrong (that mapping belongs to query/form bodies only)
    let path_part = raw_path.split('?').next().unwrap();
    let real_path = match clear_path_end_slash(path_part) {
        "" => "/",
        p => p,
    };
    let mut query_params = HashMap::new();
    if let Some(raw_query_params) = raw_path.split('?').nth(1) {
        let split_raw_query_params = raw_query_params.split('&');
        for part in split_raw_query_params {
            let mut split_part = part.split('=');
            if let (Some(query_key),Some(query_val)) = (split_part.next(),split_part.next())  {
                query_params.insert(query_key.to_string(), query_val.to_string());
            }
        }
    }
    (real_path.to_string(), query_params)
}

fn clear_path_end_slash(input: &str) -> &str {
    if let Some(strip) = input.strip_suffix('/') {
        strip
    } else {
        input
    }
}

///the proxy headers are only honored when `trust_proxy` is on: on a directly exposed deployment
///`X-Real-IP` is attacker-supplied and would otherwise forge telemetry IPs and reach the mmdb
///parser. Even then the value must parse as an IP, or the socket address stands
fn trust_addr_proxy(headers : &CIHashMap<String>,remote_addr : &str,trust_proxy : bool) -> String {
    if !trust_proxy {
        return remote_addr.to_string();
    }
    let candidate = headers.get("X-Real-IP")
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers.get("X-Forwarded-For")
                .and_then(|s| s.split(',').next())
                .map(|ip| ip.trim().to_string())
        });
    match candidate {
        Some(value) if IpAddr::from_str(&value).is_ok() => value,
        //without a valid parse, a forged header must not even skew the login rate limiter
        _ => remote_addr.to_string(),
    }
}

//form-data-parser
fn get_content_boundary(content_type : &str) -> Option<String> {
    let parts = content_type.split(';');
    let mut boundary = None;
    for part in parts {
        let part = part.trim();
        if part.starts_with("boundary=") {
            let mut boundary_str = part.splitn(2,'=');
            let boundary_result = boundary_str.nth(1);
            match boundary_result {
                None => {},
                Some(boundary_result) => {
                    //a quoted boundary (`boundary="abc"`) is legal per RFC 2045; strip the quotes
                    let boundary_result = boundary_result.trim().trim_matches('"');
                    if !boundary_result.is_empty() {
                        let mut boundary_p = "--".to_string();
                        boundary_p.push_str(boundary_result);
                        boundary = Some(boundary_p)
                    }
                }
            }
            break;
        }
    }
    boundary
}

fn parse_form_data(boundary : &str,body : &[u8]) -> HashMap<String,String> {
    let body_str = String::from_utf8_lossy(body);
    let mut form_data = HashMap::new();
    let form_parts = body_str.split(boundary);
    for form_part in form_parts {
        let form_part = form_part.trim();
        if !form_part.is_empty() && form_part != "--" {
            //a MIME part is `disposition[+other headers] CRLFCRLF body`. split on the FIRST
            //blank line so a body containing CRLF (telemetry `log`, long `extra`) survives whole;
            //the old splitn(2,"\r\n") kept only up to the first line and truncated every value.
            //operating on the lossy String (not byte slices) avoids a char-boundary panic
            let mut head_and_value = form_part.splitn(2,"\r\n\r\n");
            let headers = head_and_value.next().unwrap_or("");
            let Some(value) = head_and_value.next() else { continue };
            let value = value.replace("\r\n","");
            //parse key from the Content-Disposition header line
            let mut split_disposition = headers.splitn(2,';');
            if let Some(name_part) = split_disposition.nth(1) {
                if let Some(key) = name_part.split_once('=').map(|x|x.1) {
                    let key = key.replace('"',"");
                    form_data.insert(key,value);
                }
            }
        }
    }
    form_data
}

fn parse_form_url_encoded(body : &[u8]) -> HashMap<String,String> {
    let body_str = String::from_utf8_lossy(body);
    let split_parts = body_str.split('&');
    let mut form_data = HashMap::new();
    for part in split_parts {
        let mut split_key_value = part.splitn(2,'=');
        if let (Some(key),Some(value)) = (split_key_value.next(),split_key_value.next())  {
            //percent-decode both sides: the stats login form url-encodes the password, so a secret
            //containing a space, '+', '%' or a non-ASCII byte only matches once decoded here
            form_data.insert(percent_decode(key),percent_decode(value));
        }
    };
    form_data
}

///`application/x-www-form-urlencoded` decoder: '+' is a literal space, `%XX` is a byte; a stray
///or invalid percent sign is kept verbatim rather than dropping the field.
fn percent_decode(input : &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(byte) => { out.push(byte); i += 3; }
                    Err(_) => { out.push(b'%'); i += 1; }
                }
            }
            b => { out.push(b); i += 1; }
        }
    }
    //decoded bytes may split a UTF-8 sequence, so lossy keeps the value usable instead of failing
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn root_path_with_query_is_not_emptied() {
        // regression: "/?lang=zh" used to lose the root "/" and 404
        let (path, query) = parse_raw_path("/?lang=zh");
        assert_eq!(path, "/");
        assert_eq!(query.get("lang").map(|s| s.as_str()), Some("zh"));
        let (path, _) = parse_raw_path("/index.html?lang=zh");
        assert_eq!(path, "/index.html");
        let (path, _) = parse_raw_path("/backend/empty/");
        assert_eq!(path, "/backend/empty");
        let (path, _) = parse_raw_path("/locales/zh.json?v=1");
        assert_eq!(path, "/locales/zh.json");
    }

    #[test]
    fn encoded_traversal_never_becomes_a_real_path() {
        //the path is not percent-decoded: `%2e%2e` stays a literal token that matches no asset,
        //and a genuine `..` is rejected by the guard - both end in 404 without touching the fs
        let (path, _) = parse_raw_path("/%2F%2E%2E%2Fconfigs.toml");
        assert_eq!(path, "/%2F%2E%2E%2Fconfigs.toml");
        assert!(crate::http::is_safe_asset_path(&path), "encoded dots are not a real .. component");
        assert!(crate::http::get_index_file_content(&path).is_none(), "literal %2e%2e resolves to nothing");
        //a real traversal component is still refused
        let (path, _) = parse_raw_path("/locales/../../configs.toml");
        assert!(!crate::http::is_safe_asset_path(&path));
    }

    #[test]
    fn malformed_status_line_parses_to_none_instead_of_panicking() {
        //regression: `GET HTTP/1.1` (no path) used to hit split.next().unwrap() and, with
        //panic=abort in the release profile, take down the whole process
        assert!(parse_request_status_line(String::from("GET HTTP/1.1")).is_none());
        assert!(parse_request_status_line(String::from("GET")).is_none());
        assert!(parse_request_status_line(String::from("GET /empty HTTP/1.1")).is_some());
    }

    #[test]
    fn proxy_headers_need_trust_proxy_and_a_valid_ip() {
        let mut headers = CIHashMap::new();
        headers.insert("X-Real-IP".to_string(), "203.0.113.9".to_string());
        //direct deployments must keep the socket address, forged headers ignored
        assert_eq!(trust_addr_proxy(&headers, "10.0.0.1", false), "10.0.0.1");
        //behind a trusted proxy the header is used, but only when it parses as an IP:
        //an arbitrary string would crash the mmdb lookup and poison the stats limiter
        assert_eq!(trust_addr_proxy(&headers, "10.0.0.1", true), "203.0.113.9");
        let mut junk = CIHashMap::new();
        junk.insert("X-Real-IP".to_string(), "not-an-ip\nEVIL".to_string());
        assert_eq!(trust_addr_proxy(&junk, "10.0.0.1", true), "10.0.0.1");
        let mut xff = CIHashMap::new();
        xff.insert("X-Forwarded-For".to_string(), "203.0.113.42, 10.0.0.1".to_string());
        assert_eq!(trust_addr_proxy(&xff, "10.0.0.1", true), "203.0.113.42");
        assert_eq!(trust_addr_proxy(&xff, "10.0.0.1", false), "10.0.0.1");
    }

    #[test]
    fn body_limits_reject_before_reading() {
        let mut headers = CIHashMap::new();
        headers.insert("Content-Length".to_string(), "99999999999999999999".to_string());
        assert_eq!(check_body_limit(&headers), Some("400 Bad Request"));
        headers.insert("Content-Length".to_string(), u64::MAX.to_string());
        assert_eq!(check_body_limit(&headers), Some("413 Payload Too Large"));
        //telemetry/login forms only ever need kilobytes
        let mut form = CIHashMap::new();
        form.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
        form.insert("Content-Length".to_string(), (crate::config::MAX_FORM_BODY_BYTES + 1).to_string());
        assert_eq!(check_body_limit(&form), Some("413 Payload Too Large"));
        //duplicate Content-Length headers collapse to `42, 42` and must not be read as 0
        let mut dup = CIHashMap::new();
        dup.insert("Content-Length".to_string(), "42, 42".to_string());
        assert_eq!(check_body_limit(&dup), Some("400 Bad Request"));
        //a normal upload passes
        let mut ok = CIHashMap::new();
        ok.insert("Content-Length".to_string(), "1048576".to_string());
        assert_eq!(check_body_limit(&ok), None);
    }

    #[test]
    fn multipart_parts_keep_multiline_values_and_skip_all_headers() {
        //regression: the old splitn(2,"\r\n") parser treated the first header line as the whole
        //header block, truncating every value at its first CRLF and emptying the dictionary
        let boundary = String::from("--BOUNDARY");
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"log\"\r\n\r\nline1\r\nline2\r\n--BOUNDARY\r\nContent-Disposition: form-data; name=\"dl\"\r\n\r\n42\r\n--BOUNDARY--\r\n";
        let parsed = parse_form_data(&boundary, body);
        assert_eq!(parsed.get("log").map(|s| s.as_str()), Some("line1line2"));
        assert_eq!(parsed.get("dl").map(|s| s.as_str()), Some("42"));
        //a quoted boundary parameter is legal and used to produce a wrong delimiter
        let ct = String::from("multipart/form-data; boundary=\"XYZ\"");
        assert_eq!(get_content_boundary(&ct).as_deref(), Some("--XYZ"));
    }

    #[test]
    fn urlencoded_body_is_percent_decoded() {
        //the stats login form sends password=... percent-encoded; special characters in the secret
        //only match once decoded (regression: passwords with spaces/plus/percent never logged in)
        let decoded = parse_form_url_encoded(b"password=p%40ss%20w%2F100%25%20%2Bx");
        assert_eq!(decoded.get("password").map(|s| s.as_str()), Some("p@ss w/100% +x"));
        //'+' is a space in the urlencoded alphabet
        let plus = parse_form_url_encoded(b"a=x+y&b=100%25");
        assert_eq!(plus.get("a").map(|s| s.as_str()), Some("x y"));
        assert_eq!(plus.get("b").map(|s| s.as_str()), Some("100%"));
        //a stray, invalid percent escape is preserved rather than dropping the whole field
        assert_eq!(parse_form_url_encoded(b"k=100%%zz").get("k").map(|s| s.as_str()), Some("100%%zz"));
        assert_eq!(percent_decode("caf%C3%A9"), "café");
    }

    // Minimal router stub: every request gets a 200, so the tests exercise body consumption
    // and the Expect handshake in `handle_socket` rather than the real routes.
    fn ok_router(_req: Request) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        Box::pin(async { Response::res_200("") })
    }

    fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() { return 0; }
        let mut count = 0;
        let mut i = 0;
        while i + needle.len() <= haystack.len() {
            if &haystack[i..i + needle.len()] == needle {
                count += 1;
                i += needle.len();
            } else {
                i += 1;
            }
        }
        count
    }

    async fn drive(raw: Vec<u8>) -> Vec<u8> {
        let mut reader = BufReader::new(Cursor::new(raw));
        let mut writer = BufWriter::new(Vec::new());
        handle_socket("127.0.0.1", &mut reader, &mut writer, ok_router).await;
        writer.flush().await.unwrap();
        writer.into_inner()
    }

    /// A Content-Length that is NOT a multiple of the read-buffer size must consume *exactly*
    /// `Content-Length` body bytes — not over-read into a following pipelined request. The old
    /// `read_exact([0; 1024])` loop demanded a full final 1024-byte chunk, swallowing bytes of the
    /// next request (and, against a live peer that keeps the socket open, blocking forever — the
    /// upload "hang" WiFiMaster/ops worked around with 1024/2048 payload padding).
    #[tokio::test]
    async fn fixed_body_is_not_over_read_into_a_pipelined_request() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /empty HTTP/1.1\r\nContent-Length: 1500\r\n\r\n");
        raw.extend_from_slice(&vec![b'x'; 1500]); // 1500 % 1024 == 476
        raw.extend_from_slice(b"GET /empty HTTP/1.1\r\n\r\n");
        let out = drive(raw).await;
        assert_eq!(
            count_occurrences(&out, b"HTTP/1.1 200"), 2,
            "both the POST and the pipelined GET must be answered; the body must stop at Content-Length"
        );
    }

    /// `Expect: 100-continue` must get an interim `100 Continue` so the client sends its body
    /// immediately instead of waiting out its continue-timeout (~1s for curl) on every upload.
    #[tokio::test]
    async fn expect_100_continue_receives_interim_response() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /empty HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2048\r\n\r\n");
        raw.extend_from_slice(&vec![b'x'; 2048]);
        let out = drive(raw).await;
        assert!(
            count_occurrences(&out, b"100 Continue") >= 1,
            "server must send an interim `100 Continue` for `Expect: 100-continue`"
        );
        assert!(
            count_occurrences(&out, b"HTTP/1.1 200") >= 1,
            "the final 200 response must still follow the interim 100"
        );
    }

    ///a request line without a path must close the connection quietly; it used to panic on
    ///`split.next().unwrap()`, which with panic=abort is a one-line remote process kill
    #[tokio::test]
    async fn truncated_status_line_closes_without_panicking() {
        let raw = b"GET HTTP/1.1\r\n\r\n".to_vec();
        let out = drive(raw).await;
        assert!(out.is_empty(), "malformed request line must yield no response, got: {out:?}");
    }

    ///the chunked reader must consume the framing exactly: five bytes as `5\r\nxxxxx\r\n0\r\n\r\n`
    ///leaves the pipelined GET byte-for-byte aligned, answering both requests. The old blind
    ///1024-byte read_exact loop desynchronized the stream and hung or swallowed the next request
    #[tokio::test]
    async fn chunked_body_is_framed_and_pipelining_survives() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /empty HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        raw.extend_from_slice(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
        raw.extend_from_slice(b"GET /empty HTTP/1.1\r\n\r\n");
        let out = drive(raw).await;
        assert_eq!(
            count_occurrences(&out, b"HTTP/1.1 200"), 2,
            "chunked framing must end cleanly so the pipelined GET is still answered"
        );
    }

    #[tokio::test]
    async fn absurd_content_length_is_refused_before_reading() {
        let raw = b"POST /empty HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n".to_vec();
        let out = drive(raw).await;
        assert!(String::from_utf8_lossy(&out).contains("413 Payload Too Large"),
            "an oversized declared body must be refused, got: {out:?}");
    }

    #[tokio::test]
    async fn unparsable_content_length_is_refused() {
        let raw = b"POST /empty HTTP/1.1\r\nContent-Length: banana\r\n\r\n".to_vec();
        let out = drive(raw).await;
        assert!(String::from_utf8_lossy(&out).contains("400 Bad Request"),
            "a non-numeric Content-Length must not be silently read as zero, got: {out:?}");
    }

    #[tokio::test]
    async fn oversized_chunked_stream_is_cut_off() {
        //one declared chunk bigger than the cap: the reader must bail out instead of draining
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /empty HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        let big = format!("{:x}\r\n", crate::config::MAX_CHUNKED_BODY_BYTES + 1024);
        raw.extend_from_slice(big.as_bytes());
        let out = drive(raw).await;
        assert!(String::from_utf8_lossy(&out).contains("413"),
            "chunked streams past the cap must be rejected, got: {out:?}");
    }
}