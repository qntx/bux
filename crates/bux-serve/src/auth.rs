//! Bearer authentication. Only `GET /v1/health` is unauthenticated.

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::AppState;

/// Authenticated tenant (`ApiKey.id`).
#[derive(Clone, Debug)]
pub(crate) struct Tenant {
    pub id: String,
}

impl FromRequestParts<AppState> for Tenant {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(ApiError::unauthorized)
    }
}

pub(crate) async fn require_bearer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers()).ok_or_else(ApiError::unauthorized)?;
    let tenant = state
        .tenant_for_bearer(token)
        .ok_or_else(ApiError::unauthorized)?;
    req.extensions_mut().insert(Tenant {
        id: tenant.to_owned(),
    });
    Ok(next.run(req).await)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty() {
        Some(rest)
    } else {
        None
    }
}
