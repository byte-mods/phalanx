/// Authentication module providing pluggable auth strategies for the Phalanx proxy.
///
/// Each sub-module implements a different authentication mechanism:
/// - [`basic`] - HTTP Basic Authentication with bcrypt and plaintext password support
/// - [`jwt`] - JWT Bearer token validation with configurable algorithms
/// - [`jwks`] - Remote JWKS (JSON Web Key Set) fetching and caching for JWT verification
/// - [`oauth`] - OAuth 2.0 token introspection (RFC 7662) with caching
/// - [`oidc`] - OpenID Connect Relying Party flow with session management
/// - [`auth_request`] - Nginx-style subrequest authentication delegation
///
/// All strategies return an [`AuthResult`] to indicate whether the request should
/// proceed or be rejected.
pub mod auth_request;
pub mod basic;
pub mod jwks;
pub mod jwt;
pub mod oauth;
pub mod oidc;

use hyper::StatusCode;

/// The result of an authentication check.
///
/// Used as the common return type across all auth strategies so the proxy
/// core can handle allow/deny uniformly regardless of the auth method.
#[derive(Debug)]
pub enum AuthResult {
    /// Request is allowed to proceed to the upstream backend.
    Allowed,
    /// Request is denied -- the proxy should return this HTTP status code
    /// and static error message to the client immediately.
    Denied(StatusCode, &'static str),
}
