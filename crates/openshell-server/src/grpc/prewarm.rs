// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform-authorized native single-use prewarm transport.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>.

use std::sync::Arc;

use openshell_core::proto::{PrewarmSlotRequest, PrewarmSlotResponse};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::auth::workspace_authz::require_platform_admin;

const MAX_JSON_BYTES: usize = 1024 * 1024;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
mod native;

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Prepare,
    Observe,
    Bind,
    Retire,
}

#[cfg(test)]
pub(super) async fn handle(
    state: &Arc<ServerState>,
    request: Request<PrewarmSlotRequest>,
) -> Result<Response<PrewarmSlotResponse>, Status> {
    handle_operation(state, request, Operation::Observe).await
}

pub(super) async fn handle_operation(
    state: &Arc<ServerState>,
    request: Request<PrewarmSlotRequest>,
    operation: Operation,
) -> Result<Response<PrewarmSlotResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    require_platform_admin(&state.admin_role, &principal)?;
    if request.get_ref().request_json.len() > MAX_JSON_BYTES {
        return Err(Status::resource_exhausted(
            "prewarm request exceeds the 1 MiB limit",
        ));
    }
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    if let Some(driver) = state.compute.prewarm_driver.as_ref()
        && (driver
            .prewarm_context()
            .1
            .prewarm
            .as_ref()
            .is_some_and(|config| config.enabled)
            || matches!(operation, Operation::Observe | Operation::Retire))
    {
        let evidence = native::execute(
            state,
            driver,
            &principal,
            operation,
            &request.get_ref().request_json,
        )
        .await?;
        let evidence_json = serde_json::to_string(&evidence)
            .map_err(|_| Status::internal("prewarm evidence encoding failed"))?;
        if evidence_json.len() > MAX_JSON_BYTES {
            return Err(Status::resource_exhausted(
                "prewarm evidence exceeds the 1 MiB limit",
            ));
        }
        return Ok(Response::new(PrewarmSlotResponse { evidence_json }));
    }
    let _ = operation;
    Err(Status::unimplemented(
        "native single-use prewarm resource lifecycle is not supported",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
    use crate::grpc::test_support::{authed_request, test_server_state};
    use openshell_core::proto::open_shell_server::OpenShell;
    use tonic::Code;

    #[tokio::test]
    async fn every_operation_fails_closed_without_touching_the_ordinary_lifecycle() {
        let state = test_server_state().await;
        let service = crate::grpc::OpenShellService::new(state.clone());
        let request = || {
            authed_request(PrewarmSlotRequest {
                request_json: r#"{"credentialWrites":[{"value":"never-echo-this"}]}"#.into(),
            })
        };
        let results = [
            service.prepare_prewarm_slot(request()).await,
            service.observe_prewarm_slot(request()).await,
            service.bind_prewarm_slot(request()).await,
            service.retire_prewarm_slot(request()).await,
        ];
        for result in results {
            let status = result.unwrap_err();
            assert_eq!(status.code(), Code::Unimplemented);
            assert!(!status.message().contains("never-echo-this"));
        }
        assert!(
            state
                .store
                .list_all_messages::<openshell_core::proto::Sandbox>(1, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn rejects_unauthorized_callers_before_inspecting_the_payload() {
        let state = test_server_state().await;
        let mut request = Request::new(PrewarmSlotRequest {
            request_json: "x".repeat(MAX_JSON_BYTES + 1),
        });
        request.extensions_mut().insert(Principal::Anonymous);
        assert_eq!(
            handle(&state, request).await.unwrap_err().code(),
            Code::Unauthenticated
        );

        let mut request = Request::new(PrewarmSlotRequest {
            request_json: String::new(),
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: uuid::Uuid::new_v4().to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "test".into(),
                },
                trust_domain: None,
            }));
        assert_eq!(
            handle(&state, request).await.unwrap_err().code(),
            Code::PermissionDenied
        );

        let mut request = authed_request(PrewarmSlotRequest {
            request_json: String::new(),
        });
        let principal = request.extensions_mut().get_mut::<Principal>().unwrap();
        if let Principal::User(user) = principal {
            user.identity.roles.clear();
        }
        let mut state = Arc::try_unwrap(state).unwrap();
        state.admin_role = "openshell-admin".into();
        assert_eq!(
            handle(&Arc::new(state), request).await.unwrap_err().code(),
            Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn bounds_utf8_bytes_without_echoing_or_parsing_the_payload() {
        let state = test_server_state().await;
        for (request_json, expected) in [
            ("é".repeat(MAX_JSON_BYTES / 2), Code::Unimplemented),
            (
                format!("{}x", "é".repeat(MAX_JSON_BYTES / 2)),
                Code::ResourceExhausted,
            ),
        ] {
            let request = authed_request(PrewarmSlotRequest { request_json });
            assert_eq!(handle(&state, request).await.unwrap_err().code(), expected);
        }
    }
}
