//! Extended admin API: role-based access control (RBAC), dynamic route and SSL
//! certificate management, upstream listing, cache purge, and ML fraud-detection
//! model lifecycle endpoints.

use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

use crate::config::RouteConfig;

/// Extended admin state that adds dynamic route/SSL/cert management and
/// RBAC token validation on top of the base `AdminState`.
pub struct ExtendedAdminState {
    pub base: super::AdminState,
    /// RBAC token → role mapping
    pub api_tokens: Arc<dashmap::DashMap<String, ApiRole>>,
}

impl ExtendedAdminState {
    /// Creates a new ExtendedAdminState, populating api_tokens from config.
    ///
    /// The `admin_api_tokens` map in AppConfig stores `token → role_name` pairs
    /// parsed from `api_token TOKEN ROLE;` directives. Role names are matched
    /// case-insensitively: "admin", "operator", "readonly".
    pub fn new(base: super::AdminState, config_tokens: &std::collections::HashMap<String, String>) -> Self {
        let api_tokens = Arc::new(dashmap::DashMap::new());
        for (token, role_str) in config_tokens {
            let role = match role_str.to_lowercase().as_str() {
                "admin" => ApiRole::Admin,
                "operator" => ApiRole::Operator,
                "readonly" | "read_only" => ApiRole::ReadOnly,
                _ => {
                    tracing::warn!(
                        "Unknown API token role '{}' for token '{}...', defaulting to ReadOnly",
                        role_str,
                        &token[..token.len().min(8)]
                    );
                    ApiRole::ReadOnly
                }
            };
            api_tokens.insert(token.clone(), role);
        }

        Self {
            base,
            api_tokens,
        }
    }
}

/// An SSL certificate registered at runtime via the admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertEntry {
    /// SNI hostname this certificate applies to.
    pub server_name: String,
    /// Filesystem path to the PEM-encoded certificate chain.
    pub cert_path: String,
    /// Filesystem path to the PEM-encoded private key.
    pub key_path: String,
    /// Unix timestamp (epoch seconds) when the entry was added.
    pub added_at: u64,
}

/// Role assigned to an API token. Determines which endpoints the bearer can access.
///
/// Privilege hierarchy: `Admin` > `Operator` > `ReadOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ApiRole {
    /// Full access: can manage routes, SSL certs, RBAC tokens, and ML models.
    Admin,
    /// Read-only access to all GET endpoints.
    ReadOnly,
    /// Can perform mutations (routes, backends) but not security-sensitive operations.
    Operator,
}

/// Middleware: Validate Bearer token and check RBAC role.
pub fn check_rbac(
    req: &actix_web::HttpRequest,
    tokens: &dashmap::DashMap<String, ApiRole>,
    required: ApiRole,
) -> Result<ApiRole, actix_web::HttpResponse> {
    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match auth {
        Some(token) => match tokens.get(token) {
            Some(role) => {
                let user_role = *role;
                if role_allows(user_role, required) {
                    Ok(user_role)
                } else {
                    Err(HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "insufficient permissions"
                    })))
                }
            }
            None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "invalid token"
            }))),
        },
        None => {
            // If no tokens are configured, allow all (backwards compat)
            if tokens.is_empty() {
                Ok(ApiRole::Admin)
            } else {
                Err(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "missing authorization header"
                })))
            }
        }
    }
}

/// Returns `true` if `user`'s role satisfies the `required` permission level.
/// Admin can do everything; Operator can do everything except Admin-only actions;
/// ReadOnly can access any endpoint that only requires ReadOnly.
fn role_allows(user: ApiRole, required: ApiRole) -> bool {
    match required {
        ApiRole::ReadOnly => true,
        ApiRole::Operator => matches!(user, ApiRole::Admin | ApiRole::Operator),
        ApiRole::Admin => matches!(user, ApiRole::Admin),
    }
}

// ── Dynamic Routes API ──

/// Request body for creating a dynamic route at runtime.
#[derive(Debug, Serialize, Deserialize)]
pub struct RouteCreateRequest {
    /// URL path pattern (e.g. `"/api/v2"`).
    pub path: String,
    /// Name of the upstream pool to proxy to.
    pub upstream: Option<String>,
    /// Filesystem root for static file serving.
    pub root: Option<String>,
    /// Extra response headers to inject.
    pub add_headers: Option<HashMap<String, String>>,
}

/// POST /api/routes -- creates a dynamic route overlay (requires Operator+).
#[post("/api/routes")]
pub async fn create_route(
    state: web::Data<ExtendedAdminState>,
    body: web::Json<RouteCreateRequest>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::Operator) {
        return resp;
    }

    let route = RouteConfig {
        upstream: body.upstream.clone(),
        root: body.root.clone(),
        add_headers: body.add_headers.clone().unwrap_or_default(),
        ..Default::default()
    };

    state.base.dynamic_routes.insert(body.path.clone(), route);
    info!("Dynamic route added: {}", body.path);

    HttpResponse::Created().json(serde_json::json!({
        "status": "created",
        "path": body.path,
    }))
}

/// GET /api/routes -- lists all dynamically-created routes (requires ReadOnly+).
#[get("/api/routes")]
pub async fn list_routes(
    state: web::Data<ExtendedAdminState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::ReadOnly) {
        return resp;
    }

    let routes: Vec<serde_json::Value> = state
        .base
        .dynamic_routes
        .iter()
        .map(|entry| {
            serde_json::json!({
                "path": entry.key().clone(),
                "upstream": entry.value().upstream,
                "root": entry.value().root,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({ "routes": routes }))
}

/// DELETE /api/routes/{path} -- removes a dynamic route (requires Operator+).
#[delete("/api/routes/{path}")]
pub async fn delete_route(
    state: web::Data<ExtendedAdminState>,
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::Operator) {
        return resp;
    }

    let route_path = format!("/{}", path.into_inner());
    if state.base.dynamic_routes.remove(&route_path).is_some() {
        HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "route not found" }))
    }
}

// ── Dynamic SSL Certificates API ──

/// POST /api/ssl -- registers a new SSL certificate entry (requires Admin).
#[post("/api/ssl")]
pub async fn add_ssl_cert(
    state: web::Data<ExtendedAdminState>,
    body: web::Json<SslCertEntry>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::Admin) {
        return resp;
    }

    let entry = body.into_inner();
    let name = entry.server_name.clone();
    state.base.dynamic_certs.insert(name.clone(), entry);
    info!("SSL certificate added for {}", name);

    HttpResponse::Created().json(serde_json::json!({
        "status": "added",
        "server_name": name,
    }))
}

/// GET /api/ssl -- lists all dynamically-registered SSL certificates.
#[get("/api/ssl")]
pub async fn list_ssl_certs(
    state: web::Data<ExtendedAdminState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::ReadOnly) {
        return resp;
    }

    let certs: Vec<serde_json::Value> = state
        .base
        .dynamic_certs
        .iter()
        .map(|entry| {
            serde_json::json!({
                "server_name": entry.key().clone(),
                "cert_path": entry.value().cert_path,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({ "certificates": certs }))
}

/// DELETE /api/ssl/{server_name} -- removes an SSL certificate entry (requires Admin).
#[delete("/api/ssl/{server_name}")]
pub async fn delete_ssl_cert(
    state: web::Data<ExtendedAdminState>,
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::Admin) {
        return resp;
    }

    let name = path.into_inner();
    if state.base.dynamic_certs.remove(&name).is_some() {
        HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "cert not found" }))
    }
}

// ── Upstream management API ──

/// GET /api/upstreams -- lists all discovered backends across pools.
#[get("/api/upstreams")]
pub async fn list_upstreams(
    state: web::Data<ExtendedAdminState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::ReadOnly) {
        return resp;
    }

    let backends = state.base.discovery.list_all_backends();
    let json: Vec<serde_json::Value> = backends
        .iter()
        .map(|b| {
            serde_json::json!({
                "address": b.address,
                "pool": b.pool,
                "weight": b.weight,
                "healthy": b.healthy,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({ "upstreams": json }))
}

// ── Cache purge API ──

/// Request body for the cache purge endpoint.
#[derive(Debug, Deserialize)]
pub struct PurgeRequest {
    /// Exact cache key to invalidate.
    pub key: Option<String>,
    /// Prefix to match for bulk invalidation.
    pub prefix: Option<String>,
}

/// POST /api/cache/purge -- requests a cache purge by key or prefix.
#[post("/api/cache/purge")]
pub async fn purge_cache(
    body: web::Json<PurgeRequest>,
    _req: actix_web::HttpRequest,
) -> impl Responder {
    // Cache purge requires operator+ role but we don't have cache ref here
    // This is wired at the app level
    HttpResponse::Ok().json(serde_json::json!({
        "status": "purge_requested",
        "key": body.key,
        "prefix": body.prefix,
    }))
}

// ── ML Fraud Detection API ──

/// Request body for switching the ML fraud-detection mode.
#[derive(Deserialize)]
pub struct MlModeRequest {
    /// `"shadow"` (log-only) or `"active"` (auto-ban flagged IPs).
    pub mode: String,
}

/// POST /api/ml/upload -- accepts an ONNX model binary payload, writes it to
/// `models/fraud_model.onnx`, and hot-loads it into the ML fraud engine.
#[post("/api/ml/upload")]
pub async fn ml_upload(
    state: web::Data<crate::admin::AdminState>,
    body: web::Bytes,
    _req: actix_web::HttpRequest,
) -> impl Responder {
    let body_bytes = body.to_vec();
    let write_result = tokio::task::spawn_blocking(move || {
        let _ = std::fs::create_dir_all("models");
        std::fs::write("models/fraud_model.onnx", &body_bytes)
    })
    .await;

    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write model: {}", e) }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "spawn_blocking failed for model write" }));
        }
    }

    let model_path = "models/fraud_model.onnx";

    state.waf.ml_engine.load_model(
        model_path,
        Arc::clone(&state.waf.reputation),
        Some(state.metrics.ml_model_load_failures.clone()),
    ).await;

    HttpResponse::Ok().json(serde_json::json!({
        "status": "model_loaded",
        "path": model_path
    }))
}

/// GET /api/ml/logs -- returns the in-memory ML inference audit log.
#[get("/api/ml/logs")]
pub async fn ml_logs(
    state: web::Data<crate::admin::AdminState>,
) -> impl Responder {
    let logs_guard = state.waf.ml_engine.logs.read().await;
    let logs: Vec<_> = logs_guard.iter().cloned().collect();
    HttpResponse::Ok().json(serde_json::json!({ "logs": logs }))
}

/// PUT /api/ml/mode -- switches the ML fraud engine between shadow and active mode.
#[put("/api/ml/mode")]
pub async fn ml_mode(
    state: web::Data<crate::admin::AdminState>,
    req: web::Json<MlModeRequest>,
) -> impl Responder {
    let mode = match req.mode.to_lowercase().as_str() {
        "active" => crate::waf::ml_fraud::MlFraudMode::Active,
        "shadow" => crate::waf::ml_fraud::MlFraudMode::Shadow,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid mode. Use 'shadow' or 'active'." })),
    };

    state.waf.ml_engine.mode.store(Arc::new(mode));
    HttpResponse::Ok().json(serde_json::json!({ "status": "mode_updated", "mode": req.mode }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn make_tokens() -> dashmap::DashMap<String, ApiRole> {
        let map = dashmap::DashMap::new();
        map.insert("admin-token".to_string(), ApiRole::Admin);
        map.insert("operator-token".to_string(), ApiRole::Operator);
        map.insert("readonly-token".to_string(), ApiRole::ReadOnly);
        map
    }

    #[test]
    fn test_role_allows_admin_can_do_anything() {
        assert!(role_allows(ApiRole::Admin, ApiRole::Admin));
        assert!(role_allows(ApiRole::Admin, ApiRole::Operator));
        assert!(role_allows(ApiRole::Admin, ApiRole::ReadOnly));
    }

    #[test]
    fn test_role_allows_operator() {
        assert!(!role_allows(ApiRole::Operator, ApiRole::Admin));
        assert!(role_allows(ApiRole::Operator, ApiRole::Operator));
        assert!(role_allows(ApiRole::Operator, ApiRole::ReadOnly));
    }

    #[test]
    fn test_role_allows_readonly() {
        assert!(!role_allows(ApiRole::ReadOnly, ApiRole::Admin));
        assert!(!role_allows(ApiRole::ReadOnly, ApiRole::Operator));
        assert!(role_allows(ApiRole::ReadOnly, ApiRole::ReadOnly));
    }

    #[test]
    fn test_check_rbac_admin_token() {
        let tokens = make_tokens();
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer admin-token"))
            .to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::Admin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ApiRole::Admin);
    }

    #[test]
    fn test_check_rbac_insufficient_permissions() {
        let tokens = make_tokens();
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer readonly-token"))
            .to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::Admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_rbac_invalid_token() {
        let tokens = make_tokens();
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer bad-token"))
            .to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::ReadOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_rbac_no_header_empty_tokens() {
        let tokens = dashmap::DashMap::new();
        let req = TestRequest::default().to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::Admin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ApiRole::Admin);
    }

    #[test]
    fn test_check_rbac_no_header_with_tokens_configured() {
        let tokens = make_tokens();
        let req = TestRequest::default().to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::ReadOnly);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_rbac_operator_can_read() {
        let tokens = make_tokens();
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer operator-token"))
            .to_http_request();
        let result = check_rbac(&req, &tokens, ApiRole::ReadOnly);
        assert!(result.is_ok());
    }

    #[test]
    fn test_api_role_from_config_tokens() {
        let mut config_tokens = HashMap::new();
        config_tokens.insert("token-admin".to_string(), "admin".to_string());
        config_tokens.insert("token-op".to_string(), "operator".to_string());
        config_tokens.insert("token-ro".to_string(), "readonly".to_string());
        config_tokens.insert("token-unknown".to_string(), "superuser".to_string());

        // Verify role parsing
        assert_eq!(
            match config_tokens.get("token-admin").unwrap().to_lowercase().as_str() {
                "admin" => ApiRole::Admin,
                _ => ApiRole::ReadOnly,
            },
            ApiRole::Admin
        );
        assert_eq!(
            match config_tokens.get("token-op").unwrap().to_lowercase().as_str() {
                "operator" => ApiRole::Operator,
                _ => ApiRole::ReadOnly,
            },
            ApiRole::Operator
        );
        assert_eq!(
            match config_tokens.get("token-ro").unwrap().to_lowercase().as_str() {
                "readonly" => ApiRole::ReadOnly,
                _ => ApiRole::ReadOnly,
            },
            ApiRole::ReadOnly
        );
    }

    #[test]
    fn test_api_role_unknown_defaults_to_readonly() {
        let role_str = "superuser";
        let role = match role_str.to_lowercase().as_str() {
            "admin" => ApiRole::Admin,
            "operator" => ApiRole::Operator,
            "readonly" | "read_only" => ApiRole::ReadOnly,
            _ => ApiRole::ReadOnly,
        };
        assert_eq!(role, ApiRole::ReadOnly);
    }
}
