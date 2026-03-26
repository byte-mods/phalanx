pub mod auth_request;
pub mod basic;
pub mod jwks;
pub mod jwt;
pub mod oauth;
pub mod oidc;

use hyper::StatusCode;

/// The result of an authentication check.
#[derive(Debug)]
pub enum AuthResult {
    /// Request is allowed to proceed.
    Allowed,
    /// Request is denied — return this HTTP status and message immediately.
    Denied(StatusCode, &'static str),
}
