//! Step 1 — OAuth2 authorization-code login against Certum's CAS IdP
//! (`cloudsign.webnotarius.pl`), driven entirely over HTTP.
//!
//! Flow:
//!   GET  /idp/oauth2.0/authorize            -> 302 to the login page
//!   GET  /idp/login?service=…               -> HTML with a hidden `execution`
//!   POST /idp/login?service=…               -> 302 … -> redirect_uri?code=…
//!   POST /idp/oauth2.0/accessToken          -> {"access_token": …}
//!
//! The OAuth *client* credentials below are application-level constants shipped
//! identically to every SimplySign Desktop user (a public client per RFC 8252);
//! they are not the account holder's secret.

use crate::client::is_certum_origin;
use anyhow::{bail, Context, Result};
use reqwest::Url;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const AUTHORIZE_URL: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize";
const LOGIN_URL: &str = "https://cloudsign.webnotarius.pl/idp/login";
const TOKEN_URL: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken";
const SCOPE: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/profile";
const REDIRECT_URI: &str = "https://cloudsign.webnotarius.pl/redirect";
const CLIENT_ID: &str = "44rvDKKEWY53a7xBeF5w";
const CLIENT_SECRET: &str = "BRSE2u2nY3p3m77QHTt8";

/// A bearer access token (valid ~30 min).
pub struct Token(pub Zeroizing<String>);

/// Log in with the account e-mail and a 6-digit OTP; returns the bearer token.
pub fn login(email: &str, otp_code: &str) -> Result<Token> {
    // Record every redirect target so we can recover the `?code=…` no matter
    // which hop in the chain carries it.
    let seen: Arc<Mutex<Vec<Url>>> = Arc::new(Mutex::new(Vec::new()));

    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .cookie_store(true)
        .redirect(redirect_policy(seen.clone(), is_certum_origin))
        .timeout(Duration::from_secs(30))
        .user_agent("ssign")
        .build()
        .context("building HTTP client")?;

    // 1. authorize -> land on the login page.
    let resp = client
        .get(AUTHORIZE_URL)
        .query(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", SCOPE),
            ("api_key", ""),
        ])
        .send()
        .context("authorize request")?;
    let login_url = resp.url().clone();
    if !is_certum_origin(&login_url) {
        bail!("login page is outside Certum's origin: {login_url}");
    }
    let html = resp.text().context("reading login page")?;

    let execution = extract_hidden(&html, "execution")
        .context("could not find the `execution` field on the login page")?;
    let service = login_url
        .query_pairs()
        .find(|(k, _)| k == "service")
        .map(|(_, v)| v.into_owned());

    // 2. submit credentials (password = the OTP).
    seen.lock().unwrap().clear();
    let mut post = client.post(LOGIN_URL);
    if let Some(s) = &service {
        post = post.query(&[("service", s.as_str())]);
    }
    let resp = post
        .form(&[
            ("username", email),
            ("password", otp_code),
            ("execution", execution.as_str()),
            ("_eventId", "submit"),
            ("geolocation", ""),
            ("submit", "LOGIN"),
            ("lt", ""),
        ])
        .send()
        .context("login POST")?;
    let final_url = resp.url().clone();
    if !is_certum_origin(&final_url) {
        bail!("login ended outside Certum's origin: {final_url}");
    }

    // 3. recover the authorization code from the redirect chain (or final URL).
    let code = seen
        .lock()
        .unwrap()
        .iter()
        .chain(std::iter::once(&final_url))
        .find_map(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.into_owned())
        })
        .context("no authorization code after login — wrong e-mail or OTP?")?;

    // 4. exchange the code for a bearer token (params go in the query string,
    //    body is empty — matching the desktop client).
    let resp = client
        .post(TOKEN_URL)
        .query(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("scope", SCOPE),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .context("accessToken request")?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .with_context(|| format!("accessToken response was not JSON (status {status})"))?;

    match body.get("access_token").and_then(|v| v.as_str()) {
        Some(tok) => Ok(Token(Zeroizing::new(tok.to_string()))),
        None => bail!("token exchange failed (status {status}): {body}"),
    }
}

/// Follow redirects only to `allowed` URLs, recording each hop so the
/// `?code=` can be recovered. Anything else fails the request: a 307/308 would
/// re-send the login form (e-mail and a valid code) to wherever it points.
fn redirect_policy(
    seen: Arc<Mutex<Vec<Url>>>,
    allowed: impl Fn(&Url) -> bool + Send + Sync + 'static,
) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if !allowed(attempt.url()) {
            return attempt.error("redirect outside Certum's origin");
        }
        seen.lock().unwrap().push(attempt.url().clone());
        if attempt.previous().len() > 20 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
}

/// Pull the value of a hidden `<input name="…" value="…">` out of the HTML.
fn extract_hidden(html: &str, name: &str) -> Option<String> {
    // Tolerate attribute order: match an <input> tag that mentions the name and
    // capture its value, whichever attribute comes first.
    let by_name_then_value = regex::Regex::new(&format!(
        r#"(?is)<input[^>]*\bname=["']{}["'][^>]*\bvalue=["']([^"']*)["']"#,
        regex::escape(name)
    ))
    .unwrap();
    let by_value_then_name = regex::Regex::new(&format!(
        r#"(?is)<input[^>]*\bvalue=["']([^"']*)["'][^>]*\bname=["']{}["']"#,
        regex::escape(name)
    ))
    .unwrap();
    by_name_then_value
        .captures(html)
        .or_else(|| by_value_then_name.captures(html))
        .map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serves one request with `status` and a `Location` header; returns the
    /// raw request it received.
    fn redirect_once(
        listener: TcpListener,
        status: &'static str,
        location: String,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            req
        })
    }

    fn client_allowing(
        origin: reqwest::Url,
        seen: Arc<Mutex<Vec<Url>>>,
    ) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .redirect(redirect_policy(seen, move |u| {
                u.origin() == origin.origin()
            }))
            .build()
            .unwrap()
    }

    fn post_login_form(
        client: &reqwest::blocking::Client,
        url: &str,
    ) -> reqwest::Result<reqwest::blocking::Response> {
        client
            .post(url)
            .form(&[("username", "me@example.com"), ("password", "123456")])
            .send()
    }

    #[test]
    fn a_cross_origin_307_or_308_never_receives_the_login_form() {
        for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
            let certum = TcpListener::bind("127.0.0.1:0").unwrap();
            let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
            elsewhere.set_nonblocking(true).unwrap();
            let certum_url = format!("http://{}/idp/login", certum.local_addr().unwrap());
            let steal = format!("http://{}/steal", elsewhere.local_addr().unwrap());
            let server = redirect_once(certum, status, steal);

            let seen = Arc::new(Mutex::new(Vec::new()));
            let client = client_allowing(certum_url.parse().unwrap(), seen.clone());
            assert!(
                post_login_form(&client, &certum_url).is_err(),
                "{status} was followed"
            );

            let first = String::from_utf8(server.join().unwrap()).unwrap();
            assert!(first.starts_with("POST /idp/login"));
            assert!(seen.lock().unwrap().is_empty());
            assert_eq!(
                elsewhere.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{status}: the other origin got a connection"
            );
        }
    }

    #[test]
    fn a_same_origin_redirect_is_still_followed() {
        let certum = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", certum.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let first = redirect_once(
                certum.try_clone().unwrap(),
                "302 Found",
                "/redirect?code=OC-1".into(),
            );
            first.join().unwrap();
            redirect_once(certum, "200 OK", String::new())
                .join()
                .unwrap()
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let client = client_allowing(base.parse().unwrap(), seen.clone());
        let resp = post_login_form(&client, &format!("{base}/idp/login")).unwrap();

        assert!(resp.status().is_success());
        assert!(String::from_utf8(server.join().unwrap())
            .unwrap()
            .starts_with("GET /redirect?code=OC-1"));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_login_policy_refuses_hosts_and_schemes_outside_certum() {
        for url in [
            "http://cloudsign.webnotarius.pl/redirect?code=x",
            "https://cloudsign.webnotarius.pl.evil.com/redirect?code=x",
            "https://x@evil.example/redirect?code=x",
            "https://cloudsign.webnotarius.pl:444/redirect?code=x",
        ] {
            assert!(!is_certum_origin(&url.parse().unwrap()), "{url}");
        }
        assert!(is_certum_origin(&REDIRECT_URI.parse().unwrap()));
        assert!(is_certum_origin(&LOGIN_URL.parse().unwrap()));
    }
}
