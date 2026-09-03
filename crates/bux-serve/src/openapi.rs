//! OpenAPI document from handler `#[utoipa::path]` annotations.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::exec::{ExecRequest, ExecResponse};
use crate::images::{ImageInfoBody, PullRequest};
use crate::router::{MeBody, MetricsBody};
use crate::sandboxes::{CreateRequest, SandboxBody};
use crate::state::Limits;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "bux",
        version = env!("CARGO_PKG_VERSION"),
        description = "Hosted agent sandbox HTTP API"
    ),
    modifiers(&BearerAuth),
    security(("bearer" = [])),
    paths(
        crate::router::health,
        crate::router::config,
        crate::router::me,
        crate::router::metrics,
        crate::sandboxes::list,
        crate::sandboxes::create,
        crate::sandboxes::get_one,
        crate::sandboxes::delete_one,
        crate::sandboxes::start_one,
        crate::logs::logs_one,
        crate::exec::exec_one,
        crate::files::get_file,
        crate::files::put_file,
        crate::images::list_images,
        crate::images::pull_image,
        crate::images::delete_image,
    ),
    components(schemas(
        Limits,
        MeBody,
        MetricsBody,
        CreateRequest,
        SandboxBody,
        ExecRequest,
        ExecResponse,
        PullRequest,
        ImageInfoBody,
    )),
    tags(
        (name = "Worker", description = "Health, config, identity, metrics"),
        (name = "Sandboxes", description = "Per-agent VM lifecycle and logs"),
        (name = "Exec", description = "Collect-only exec"),
        (name = "Files", description = "Single-file PUT/GET"),
        (name = "Images", description = "Worker-global OCI images"),
    )
)]
struct ApiDoc;

/// Serialize the OpenAPI document as pretty JSON.
///
/// # Panics
///
/// Panics if the generated document cannot be serialized (a utoipa bug).
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "OpenAPI types are always JSON-serializable"
)]
pub fn openapi_json() -> String {
    ApiDoc::openapi()
        .to_pretty_json()
        .expect("openapi serialize")
}
