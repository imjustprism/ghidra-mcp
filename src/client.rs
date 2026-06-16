use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("ghidra {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("auth token contains characters invalid in an HTTP header")]
    InvalidToken,
}

#[derive(Clone)]
pub struct GhidraHttp {
    base: Url,
    http: Client,
}

impl GhidraHttp {
    pub fn new(base: Url, timeout_secs: u64, token: Option<&str>) -> Result<Self, BridgeError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent(concat!("ghidra-mcp/", env!("CARGO_PKG_VERSION")));
        if let Some(token) = token.filter(|t| !t.is_empty()) {
            let mut headers = reqwest::header::HeaderMap::with_capacity(1);
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| BridgeError::InvalidToken)?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
        Ok(Self {
            base,
            http: builder.build()?,
        })
    }

    pub async fn get<Q: Serialize + ?Sized>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<String, BridgeError> {
        let url = self.base.join(path)?;
        Self::dispatch(self.http.get(url).query(query)).await
    }

    pub async fn post_form<F: Serialize + ?Sized>(
        &self,
        path: &str,
        form: &F,
    ) -> Result<String, BridgeError> {
        let url = self.base.join(path)?;
        Self::dispatch(self.http.post(url).form(form)).await
    }

    pub async fn post_raw(&self, path: &str, body: &str) -> Result<String, BridgeError> {
        let url = self.base.join(path)?;
        Self::dispatch(self.http.post(url).body(body.to_owned())).await
    }

    async fn dispatch(req: reqwest::RequestBuilder) -> Result<String, BridgeError> {
        let res = req.send().await?;
        let status = res.status();
        let body = res.text().await?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(BridgeError::Upstream {
                status: status.as_u16(),
                body: body.trim().into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn upstream_error_display_includes_status_and_body() {
        let e = BridgeError::Upstream {
            status: 404,
            body: "not found".into(),
        };
        assert_eq!(e.to_string(), "ghidra 404: not found");
    }

    #[test]
    fn url_error_display_is_prefixed() {
        let e = BridgeError::Url(url::ParseError::EmptyHost);
        assert!(e.to_string().starts_with("url: "));
    }

    async fn serve_once(status_line: &'static str, body: &'static str) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    #[tokio::test]
    async fn get_returns_body_on_success() {
        let base = serve_once("200 OK", "alpha\nbeta\n").await;
        let http = GhidraHttp::new(base, 5, None).unwrap();
        let out = http.get("methods", &[("offset", 0u32)]).await.unwrap();
        assert_eq!(out, "alpha\nbeta\n");
    }

    #[tokio::test]
    async fn get_maps_404_to_upstream_error() {
        let base = serve_once("404 Not Found", "missing").await;
        let http = GhidraHttp::new(base, 5, None).unwrap();
        let err = http.get("methods", &[(); 0]).await.unwrap_err();
        match err {
            BridgeError::Upstream { status, body } => {
                assert_eq!(status, 404);
                assert_eq!(body, "missing");
            }
            other => panic!("expected upstream error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_form_returns_body_on_success() {
        let base = serve_once("200 OK", "ok").await;
        let http = GhidraHttp::new(base, 5, None).unwrap();
        let out = http
            .post_form("renameFunction", &[("oldName", "a"), ("newName", "b")])
            .await
            .unwrap();
        assert_eq!(out, "ok");
    }

    #[tokio::test]
    async fn post_raw_returns_body_on_success() {
        let base = serve_once("200 OK", "void main(void){}").await;
        let http = GhidraHttp::new(base, 5, None).unwrap();
        let out = http.post_raw("decompile", "main").await.unwrap();
        assert_eq!(out, "void main(void){}");
    }
}
