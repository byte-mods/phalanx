pub mod basic;
pub mod jwt;
pub mod oauth;

use hyper::StatusCode;

/// The result of an authentication check.
#[derive(Debug)]
pub enum AuthResult {
    /// Request is allowed to proceed.
    Allowed,
    /// Request is denied — return this HTTP status and message immediately.
    Denied(StatusCode, &'static str),
}
