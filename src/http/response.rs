use crate::http::get_index_file_content;
use sha2::{Digest, Sha256};
use std::fmt::Write;

///strong ETag over the served bytes: any edit to a page or locale file changes it
fn etag_of(bytes : &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut etag = String::from("\"");
    for byte in digest.iter().take(8) {
        write!(&mut etag, "{byte:02x}").expect("unable to write");
    }
    etag.push('"');
    etag
}

///accepts `If-None-Match: *`, a single tag and a comma separated list
fn etag_matches(if_none_match : Option<&str>, etag : &str) -> bool {
    let Some(header) = if_none_match else { return false };
    let header = header.trim();
    header == "*" || header.split(',').any(|candidate| candidate.trim() == etag)
}

#[derive(Debug)]
pub struct Response {
    pub data : Vec<u8>,
    pub chunk_count : i32
}

impl Response {

    pub fn res_404 () -> Self {
        let body = b"404 not found";
        let response_header = format!(
            "HTTP/1.1 404 Not Found\r\n\
            Content-Length: {}\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
            body.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(body);
        Response {data,chunk_count:0}
    }

    pub fn res_400 () -> Self {
        let body = b"400 bad request";
        let response_header = format!(
            "HTTP/1.1 400 Bad Request\r\n\
            Content-Length: {}\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
            body.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(body);
        Response {data,chunk_count:0}
    }

    pub fn res_200_img (img : &[u8]) -> Self {
        let response_header = format!(
            "HTTP/1.1 200 OK\r\n\
            Content-Length: {}\r\n\
            Content-Type: image/jpeg\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type\r\n\r\n",
            img.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(img);
        Response {data,chunk_count:0}
    }

    pub fn res_200_garbage (chunk_count : i32) -> Self {
        let response_header = "HTTP/1.1 200 OK\r\n\
            Content-Description: File Transfer\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=random.dat\r\n\
            Content-Transfer-Encoding: binary\r\n\
            Connection: keep-alive\r\n\
            Transfer-Encoding: chunked\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n".to_string();
        Response {
            data : response_header.as_bytes().to_vec(),
            chunk_count
        }
    }

    ///304 carries no body and no Content-Length (RFC 9110 §15.4.5): the blank line ends the response
    pub fn res_304 (etag : &str) -> Self {
        let response_header = format!(
            "HTTP/1.1 304 Not Modified\r\n\
            ETag: {}\r\n\
            Cache-Control: no-cache\r\n\
            Connection: keep-alive\r\n\
            Access-Control-Allow-Origin: *\r\n\r\n",
            etag
        );
        Response {data: response_header.as_bytes().to_vec(), chunk_count : 0}
    }

    pub fn res_200_fs(file_name : &str, if_none_match : Option<&str>) -> Self {
        //normalize before MIME lookup too: root ("" or "/") maps to index.html
        let file_name = if file_name.is_empty() || file_name == "/" { "/index.html" } else { file_name };
        if let Some(file_content) = get_index_file_content(file_name) {
            let etag = etag_of(&file_content);
            //revalidation makes edited pages/locale files visible on the next visit without version bumps
            if etag_matches(if_none_match, &etag) {
                return Self::res_304(&etag);
            }
            let content_type = match file_name {
                i if i.ends_with(".js") => {
                    "text/javascript"
                }
                i if i.ends_with(".json") => {
                    "application/json"
                }
                i if i.ends_with(".html") => {
                    "text/html"
                }
                i if i.ends_with(".ico") => {
                    "image/vnd.microsoft.icon"
                }
                i if i.ends_with(".css") => {
                    "text/css"
                }
                i if i.ends_with(".svg") => {
                    "image/svg+xml"
                }
                _ => {
                    ""
                }
            };
            let data = match content_type {
                i if i == "text/javascript" || i == "text/html" || i == "text/css" || i == "image/svg+xml" || i == "application/json" => {
                    //lossy instead of unwrap: a hand-edited locale file with bad bytes must not kill the connection task
                    let content = String::from_utf8_lossy(&file_content);
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                            Content-Type: {}\r\n\
                            Content-Length: {}\r\n\
                            ETag: {}\r\n\
                            Cache-Control: no-cache\r\n\
                            Connection: keep-alive\r\n\
                            Access-Control-Allow-Origin: *\r\n\
                            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n{}",
                        content_type,
                        content.len(),
                        etag,
                        content
                    ).as_bytes().to_vec()
                }
                "image/vnd.microsoft.icon" => {
                    let response_header = format!(
                        "HTTP/1.1 200 OK\r\n\
                            Content-Type: {}\r\n\
                            Content-Length: {}\r\n\
                            ETag: {}\r\n\
                            Cache-Control: no-cache\r\n\
                            Connection: keep-alive\r\n\
                            Access-Control-Allow-Origin: *\r\n\
                            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
                        content_type,
                        file_content.len(),
                        etag
                    );
                    let mut data = response_header.as_bytes().to_vec();
                    data.extend(file_content);
                    data
                }
                _ => {
                    return Self::res_404()
                }
            };
            Response {
                data,
                chunk_count : 0
            }
        } else {
            Self::res_404()
        }
    }

    pub fn res_200_json(content : &str)  -> Self {
        let response_header = format!(
            "HTTP/1.1 200 OK\r\n\
            Content-Length: {}\r\n\
            Content-Type: application/json; charset=utf-8\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type\r\n\r\n",
            content.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(content.as_bytes());
        Response {data,chunk_count:0}
    }

    pub fn res_200(content : &str) -> Self {
        let response_header = format!(
            "HTTP/1.1 200 OK\r\n\
            Content-Length: {}\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type\r\n\r\n{}",
            content.len(),
            content
        );
        Response {data : response_header.as_bytes().to_vec(),chunk_count : 0}
    }

    pub fn res_500() -> Self {
        let body = b"Internal Server Error";
        let response_header = format!(
            "HTTP/1.1 500 Internal Server Error\r\n\
            Content-Length: {}\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
            body.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(body);
        Response {data,chunk_count:0}
    }

    /*stats responses*/
    pub fn res_temporary_redirect_cookie(cookie_data : &str,location : &str) -> Self {
        let response_header = format!(
            "HTTP/1.1 307 Temporary Redirect\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Set-Cookie: {}\r\n\
            Location: {}\r\n\
            Content-Length: 0\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Credentials: true\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type, Authorization\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n\r\n",
            cookie_data,
            location
        );
        let data = response_header.as_bytes().to_vec();
        Response {data,chunk_count:0}
    }

    pub fn res_200_html(content : &str) -> Self {
        let response_header = format!(
            "HTTP/1.1 200 OK\r\n\
            Content-Length: {}\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Credentials: true\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type, Authorization\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n\r\n",
            content.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(content.as_bytes());
        Response {data,chunk_count:0}
    }

    pub fn res_403_html(content : &str) -> Self {
        let response_header = format!(
            "HTTP/1.1 403 Forbidden\r\n\
            Content-Length: {}\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0\r\n\
            Cache-Control: post-check=0, pre-check=0\r\n\
            Pragma: no-cache\r\n\
            Access-Control-Allow-Credentials: true\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Headers: Content-Encoding, Content-Type, Authorization\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n\r\n",
            content.len()
        );
        let mut data = response_header.as_bytes().to_vec();
        data.extend(content.as_bytes());
        Response {data,chunk_count:0}
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SERVER_CONFIG, ServerConfig};

    fn init_config() {
        SERVER_CONFIG.get_or_init(|| ServerConfig {
            bind_address: "0.0.0.0".to_string(),
            listen_port: 8080,
            worker_threads: serde_json::Value::from(1),
            base_url: "test".to_string(),
            ipinfo_api_key: "".to_string(),
            stats_password: "".to_string(),
            redact_ip_addresses: false,
            result_image_theme: "light".to_string(),
            assets_path: "".to_string(),
            database_type: "none".to_string(),
            database_hostname: None,
            database_name: None,
            database_username: None,
            database_password: None,
            database_file: None,
            enable_tls: false,
            tls_cert_file: "".to_string(),
            tls_key_file: "".to_string(),
        });
    }

    ///extracts every value of an HTML attribute, without pulling in a regex/HTML dependency.
    ///`attr` must include the opening quote (`data-i18n="`), which also keeps it from matching `data-i18n-html="`.
    fn attr_values(haystack: &str, attr: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = haystack;
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            let Some(end) = rest.find('"') else { break };
            out.push(rest[..end].to_string());
            rest = &rest[end + 1..];
        }
        out
    }

    ///extracts the dictionary keys the JS asks for at runtime via `name("key")`.
    ///`call` includes the opening quote, e.g. `t("`; the char before it must not be an identifier char.
    fn call_keys(haystack: &str, call: &str) -> Vec<String> {
        let quote = &call[call.len() - 1..];
        let mut out = Vec::new();
        let mut rest = haystack;
        while let Some(i) = rest.find(call) {
            let boundary_ok = rest[..i]
                .chars()
                .next_back()
                .map_or(true, |c| !(c.is_alphanumeric() || c == '_' || c == '$'));
            rest = &rest[i + call.len()..];
            let Some(end) = rest.find(quote) else { break };
            if boundary_ok { out.push(rest[..end].to_string()); }
            rest = &rest[end + 1..];
        }
        out
    }

    fn embedded_text(path: &str) -> String {
        let file = crate::config::DEF_ASSETS
            .get_file(path)
            .unwrap_or_else(|| panic!("{path} is not embedded, was it added under assets/?"));
        String::from_utf8_lossy(file.contents()).into_owned()
    }

    #[test]
    fn paths_escaping_the_assets_dir_are_refused() {
        //embedded lookups could never resolve `..` anyway, so the guard is checked on its own terms
        assert!(crate::http::is_safe_asset_path("/locales/zh.json"));
        assert!(crate::http::is_safe_asset_path("/a..b.json"), "dots inside a component are legitimate");
        assert!(!crate::http::is_safe_asset_path("/../configs.toml"));
        assert!(!crate::http::is_safe_asset_path("/locales/../../../src/main.rs"));
        assert!(!crate::http::is_safe_asset_path("/..\\..\\Cargo.toml"), "backslash is a separator on Windows");
        assert!(!crate::http::is_safe_asset_path("/index.html\0../etc/passwd"));
        assert!(crate::http::get_index_file_content("/../Cargo.toml").is_none());
    }

    #[test]
    fn fs_revalidates_with_etag_and_answers_304() {
        init_config();
        let fresh = String::from_utf8_lossy(&Response::res_200_fs("/locales/zh.json", None).data)
            .into_owned();
        assert!(fresh.contains("200 OK"), "locale file should be served: {fresh}");
        assert!(fresh.contains("Cache-Control: no-cache"), "static files must revalidate");
        let etag = fresh.lines()
            .find_map(|line| line.strip_prefix("ETag: "))
            .expect("a 200 static response must carry an ETag")
            .to_string();

        //same content -> 304 without a body
        let cached = Response::res_200_fs("/locales/zh.json", Some(&etag));
        let cached = String::from_utf8_lossy(&cached.data).into_owned();
        assert!(cached.contains("304 Not Modified"), "matching ETag must yield 304, got: {cached}");
        assert!(!cached.contains("\r\n\r\n{"), "304 must not carry a body");

        //wildcard and lists containing the tag both count as a match; an unrelated tag returns the body
        assert!(Response::res_200_fs("/locales/zh.json", Some("*"))
            .data.starts_with(b"HTTP/1.1 304 Not Modified"), "If-None-Match: * must yield 304");
        let tag_list = format!("\"{}\", {}", "0".repeat(16), etag);
        assert!(Response::res_200_fs("/locales/zh.json", Some(&tag_list))
            .data.starts_with(b"HTTP/1.1 304 Not Modified"), "a list containing the tag must yield 304");
        assert!(Response::res_200_fs("/locales/zh.json", Some("\"deadbeefdeadbeef\""))
            .data.starts_with(b"HTTP/1.1 200 OK"), "a stale tag must return the full file");
    }

    #[test]
    fn locale_files_stay_consistent_with_the_ui() {
        //guards the copy-paste contracts of the i18n layer: every key the page asks for must be
        //translated in every locale, dictionaries must not drift apart, and manifest entries must resolve.
        let html = embedded_text("index.html");
        let en: serde_json::Value = serde_json::from_str(&embedded_text("locales/en.json")).unwrap();
        let zh: serde_json::Value = serde_json::from_str(&embedded_text("locales/zh.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&embedded_text("locales/manifest.json")).unwrap();

        let mut used = attr_values(&html, "data-i18n=\"");
        used.extend(attr_values(&html, "data-i18n-html=\""));
        used.extend(call_keys(&html, "t(\""));
        used.extend(call_keys(&html, "t('"));
        used.extend(call_keys(&html, "setMessage(\""));
        used.sort();
        used.dedup();
        assert!(used.len() > 15, "expected the UI to reference many keys, found {}", used.len());

        for key in &used {
            for (lang, dict) in [("en", &en), ("zh", &zh)] {
                assert!(dict.get(key).and_then(|v| v.as_str()).is_some(), "{key} missing from {lang}.json");
            }
            //the inline en fallback renders before the fetch resolves and on every failure path
            assert!(html.contains(&format!("\"{key}\":")) || key.starts_with("policy."),
                "{key} absent from inline LOCALE_EN and not an html block");
        }

        let keys = |v: &serde_json::Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&en), keys(&zh), "en.json and zh.json key sets diverged");

        for entry in manifest["locales"].as_array().unwrap() {
            let code = entry["code"].as_str().unwrap();
            let path = format!("locales/{code}.json");
            assert!(crate::config::DEF_ASSETS.get_file(&path).is_some(), "manifest lists {code} but {path} is missing");
        }
    }

    #[test]
    fn fs_returns_correct_content_type_for_all_mime_types() {
        init_config();
        let cases = [
            ("/index.html",              "200 OK", "Content-Type: text/html"),
            ("/",                        "200 OK", "Content-Type: text/html"),
            ("",                         "200 OK", "Content-Type: text/html"), // /?lang=xx reaches fs as empty path
            ("/speedtest.js",            "200 OK", "Content-Type: text/javascript"),
            ("/servers_list.js",         "200 OK", "Content-Type: text/javascript"),
            ("/favicon.ico",             "200 OK", "Content-Type: image/vnd.microsoft.icon"),
            ("/locales/manifest.json",   "200 OK", "Content-Type: application/json"),
            ("/locales/en.json",         "200 OK", "Content-Type: application/json"),
            ("/locales/zh.json",         "200 OK", "Content-Type: application/json"),
            ("/unknown.xyz",             "404 Not Found", ""),
            ("/nonexistent.html",        "404 Not Found", ""),
        ];
        for (path, status, content_type) in &cases {
            let resp = Response::res_200_fs(path, None);
            let body = String::from_utf8_lossy(&resp.data);
            assert!(body.contains(status), "path={path}: expected status {status}");
            if !content_type.is_empty() {
                assert!(body.contains(content_type), "path={path}: expected Content-Type {content_type}");
            }
        }
    }
}
