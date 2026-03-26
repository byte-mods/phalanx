use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

use crate::config::{AppConfig, BackendConfig, RouteConfig, UpstreamPoolConfig};
use crate::discovery::DiscoveredBackend;

/// Extended admin state with dynamic route/SSL/cert management.
pub struct ExtendedAdminState {
    pub base: super::AdminState,
    /// Dynamically managed routes (overlay on top of config-file routes)
    pub dynamic_routes: Arc<dashmap::DashMap<String, RouteConfig>>,
    /// Dynamically managed SSL certificates
    pub dynamic_certs: Arc<dashmap::DashMap<String, SslCertEntry>>,
    /// RBAC token → role mapping
    pub api_tokens: Arc<dashmap::DashMap<String, ApiRole>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertEntry {
    pub server_name: String,
    pub cert_path: String,
    pub key_path: String,
    pub added_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ApiRole {
    Admin,
    ReadOnly,
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

fn role_allows(user: ApiRole, required: ApiRole) -> bool {
    match required {
        ApiRole::ReadOnly => true,
        ApiRole::Operator => matches!(user, ApiRole::Admin | ApiRole::Operator),
        ApiRole::Admin => matches!(user, ApiRole::Admin),
    }
}

// ── Dynamic Routes API ──

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteCreateRequest {
    pub path: String,
    pub upstream: Option<String>,
    pub root: Option<String>,
    pub add_headers: Option<HashMap<String, String>>,
}

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

    state.dynamic_routes.insert(body.path.clone(), route);
    info!("Dynamic route added: {}", body.path);

    HttpResponse::Created().json(serde_json::json!({
        "status": "created",
        "path": body.path,
    }))
}

#[get("/api/routes")]
pub async fn list_routes(
    state: web::Data<ExtendedAdminState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::ReadOnly) {
        return resp;
    }

    let routes: Vec<serde_json::Value> = state
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
    if state.dynamic_routes.remove(&route_path).is_some() {
        HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "route not found" }))
    }
}

// ── Dynamic SSL Certificates API ──

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
    state.dynamic_certs.insert(name.clone(), entry);
    info!("SSL certificate added for {}", name);

    HttpResponse::Created().json(serde_json::json!({
        "status": "added",
        "server_name": name,
    }))
}

#[get("/api/ssl")]
pub async fn list_ssl_certs(
    state: web::Data<ExtendedAdminState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Err(resp) = check_rbac(&req, &state.api_tokens, ApiRole::ReadOnly) {
        return resp;
    }

    let certs: Vec<serde_json::Value> = state
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
    if state.dynamic_certs.remove(&name).is_some() {
        HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "cert not found" }))
    }
}

// ── Upstream management API ──

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

#[derive(Debug, Deserialize)]
pub struct PurgeRequest {
    pub key: Option<String>,
    pub prefix: Option<String>,
}

#[post("/api/cache/purge")]
pub async fn purge_cache(
    body: web::Json<PurgeRequest>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    // Cache purge requires operator+ role but we don't have cache ref here
    // This is wired at the app level
    HttpResponse::Ok().json(serde_json::json!({
        "status": "purge_requested",
        "key": body.key,
        "prefix": body.prefix,
    }))
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
}
