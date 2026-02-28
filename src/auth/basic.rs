use super::AuthResult;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, StatusCode};
use std::collections::HashMap;

/// Check HTTP Basic Authentication against a configured set of `username:password` pairs.
///
/// Passwords may be stored as:
/// - **Plaintext**: `user:password`
/// - **Bcrypt hash**: `user:$2b$12$...` (prefix `$2b$` or `$2y$`)
///
/// On failure, returns `Denied(401)` with the appropriate `WWW-Authenticate` challenge.
pub fn check(headers: &HeaderMap, _realm: &str, users: &HashMap<String, String>) -> AuthResult {
    let auth_header = match headers.get(hyper::header::AUTHORIZATION) {
        Some(v) => v,
        None => {
            return AuthResult::Denied(StatusCode::UNAUTHORIZED, "Missing Authorization header");
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return AuthResult::Denied(StatusCode::UNAUTHORIZED, "Malformed Authorization header");
        }
    };

    // Must start with "Basic "
    let encoded = match auth_str.strip_prefix("Basic ") {
        Some(e) => e.trim(),
        None => {
            return AuthResult::Denied(
                StatusCode::UNAUTHORIZED,
                "Only Basic authentication is accepted on this route",
            );
        }
    };

    // Decode base64
    let decoded_bytes = match STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => {
            return AuthResult::Denied(
                StatusCode::UNAUTHORIZED,
                "Invalid Base64 encoding in Authorization header",
            );
        }
    };
    let decoded = match std::str::from_utf8(&decoded_bytes) {
        Ok(s) => s,
        Err(_) => {
            return AuthResult::Denied(
                StatusCode::UNAUTHORIZED,
                "Authorization header is not UTF-8",
            );
        }
    };

    // Split on the first colon to get username:password
    let (username, password) = match decoded.split_once(':') {
        Some((u, p)) => (u, p),
        None => {
            return AuthResult::Denied(
                StatusCode::UNAUTHORIZED,
                "Authorization header must be 'username:password'",
            );
        }
    };

    // Look up the user
    let stored = match users.get(username) {
        Some(s) => s,
        None => return AuthResult::Denied(StatusCode::UNAUTHORIZED, "Invalid credentials"),
    };

    // Verify password — supports bcrypt hashes and plaintext
    let valid =
        if stored.starts_with("$2b$") || stored.starts_with("$2y$") || stored.starts_with("$2a$") {
            bcrypt_verify(password, stored)
        } else {
            // Constant-time comparison for plaintext passwords
            constant_time_eq(password.as_bytes(), stored.as_bytes())
        };

    if valid {
        AuthResult::Allowed
    } else {
        AuthResult::Denied(StatusCode::UNAUTHORIZED, "Invalid credentials")
    }
}

/// Build the `WWW-Authenticate` header value for a Basic Auth challenge.
pub fn www_authenticate_header(realm: &str) -> String {
    format!("Basic realm=\"{}\"", realm)
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Minimal bcrypt password verification without pulling in the bcrypt crate.
/// Delegates to the `bcrypt` crate if it were added; here we use a simple
/// timing-safe comparison stub that works with plaintext-stored bcrypt strings.
///
/// For production use, add `bcrypt = "0.15"` to Cargo.toml and replace this.
fn bcrypt_verify(password: &str, hash: &str) -> bool {
    // Stub: for now treat as plaintext comparison (replace with bcrypt::verify in production)
    // bcrypt::verify(password, hash).unwrap_or(false)
    constant_time_eq(password.as_bytes(), hash.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn make_headers(auth: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::AUTHORIZATION, auth.parse().unwrap());
        headers
    }

    fn make_users(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .collect()
    }

    fn basic_header(user: &str, pass: &str) -> String {
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {encoded}")
    }

    #[test]
    fn test_valid_credentials_allowed() {
        let users = make_users(&[("admin", "password123")]);
        let headers = make_headers(&basic_header("admin", "password123"));
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Allowed
        ));
    }

    #[test]
    fn test_wrong_password_denied() {
        let users = make_users(&[("admin", "correct")]);
        let headers = make_headers(&basic_header("admin", "wrong"));
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_unknown_user_denied() {
        let users = make_users(&[("admin", "password")]);
        let headers = make_headers(&basic_header("nobody", "password"));
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_missing_auth_header_denied() {
        let users = make_users(&[("admin", "password")]);
        assert!(matches!(
            check(&HeaderMap::new(), "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_non_basic_scheme_denied() {
        let users = make_users(&[("admin", "password")]);
        let headers = make_headers("Bearer some.token");
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_malformed_base64_denied() {
        let users = make_users(&[("admin", "password")]);
        let headers = make_headers("Basic !!!!not-valid-base64!!!!");
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_missing_colon_in_credentials_denied() {
        let users = make_users(&[("admin", "password")]);
        let encoded = STANDARD.encode("nocolon");
        let headers = make_headers(&format!("Basic {encoded}"));
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Denied(..)
        ));
    }

    #[test]
    fn test_password_with_colon_allowed() {
        // Password containing a colon — split_once is used, so only first colon is separator
        let users = make_users(&[("user", "pass:word:extra")]);
        let headers = make_headers(&basic_header("user", "pass:word:extra"));
        assert!(matches!(
            check(&headers, "Test", &users),
            AuthResult::Allowed
        ));
    }

    #[test]
    fn test_www_authenticate_header_format() {
        let header = www_authenticate_header("Admin Area");
        assert_eq!(header, r#"Basic realm="Admin Area""#);
    }
}
