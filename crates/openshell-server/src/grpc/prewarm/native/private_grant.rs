// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Held-init delivery only. The public v2 gate remains closed until assistant
//! initialization and ordered sidecar release can honor the complete contract.

use super::{
    API_TIMEOUT, Backend, INIT_NAME, Phase, Slot, backend_error, conflict, immutable_image, pending,
};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{AttachParams, AttachedProcess};
use openshell_core::prewarm_grant::{
    DELIVER_SUBCOMMAND, GrantIdentity, GrantRequest, GrantRole, GrantStatus, MAX_CONTROL_BYTES,
    MAX_GRANT_BYTES, STATUS_SUBCOMMAND, grant_hash,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::future::Future;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tonic::Status;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContainerIdentity {
    container_id: String,
    image_id: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Delivery {
    identity: GrantIdentity,
    target: ContainerIdentity,
    grant_hash: String,
    acknowledged: bool,
}

fn uncertain() -> Status {
    Status::unavailable(
        "private grant delivery is indeterminate; observe the original delivery only, never replay",
    )
}

fn identity(backend: &Backend<'_>, slot: &Slot) -> Result<GrantIdentity, Status> {
    if backend.identity.schema_version != 2
        || slot.phase != Phase::Binding
        || !slot.tenant_configured
        || slot.intent_hash.is_none()
    {
        return Err(conflict());
    }
    let identity = GrantIdentity {
        slot_id: backend.identity.slot_id,
        generation: backend.identity.generation,
        pod_uid: slot
            .tickets
            .get("compute")
            .and_then(|ticket| ticket.uid.as_deref())
            .ok_or_else(conflict)?
            .parse()
            .map_err(|_| conflict())?,
        sandbox_id: backend.identity.workload_id,
        allocation_id: slot.allocation.as_ref().ok_or_else(conflict)?["id"]
            .as_str()
            .ok_or_else(conflict)?
            .parse()
            .map_err(|_| conflict())?,
    };
    identity.validate().map_err(|_| conflict())?;
    Ok(identity)
}

fn target(pod: &Pod, expected: &GrantIdentity, image: &str) -> Result<ContainerIdentity, Status> {
    if pod.metadata.uid.as_deref() != Some(expected.pod_uid.to_string().as_str())
        || pod.metadata.deletion_timestamp.is_some()
    {
        return Err(conflict());
    }
    let spec = pod.spec.as_ref().ok_or_else(conflict)?;
    let container = spec
        .init_containers
        .as_ref()
        .and_then(|containers| containers.iter().find(|c| c.name == INIT_NAME))
        .ok_or_else(conflict)?;
    let status = pod.status.as_ref().ok_or_else(pending)?;
    let running = status
        .init_container_statuses
        .as_ref()
        .and_then(|statuses| statuses.iter().find(|s| s.name == INIT_NAME))
        .ok_or_else(pending)?;
    let digest = image.rsplit_once("@sha256:").ok_or_else(conflict)?.1;
    let image_id = running
        .image_id
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .or_else(|| running.image_id.strip_prefix("sha256:"));
    if !immutable_image(image)
        || container.image.as_deref() != Some(image)
        || running.image != image
        || image_id != Some(digest)
        || running.container_id.as_ref().is_none_or(String::is_empty)
        || running.restart_count != 0
        || container
            .security_context
            .as_ref()
            .and_then(|context| context.run_as_user)
            != Some(0)
    {
        return Err(conflict());
    }
    if status.phase.as_deref() != Some("Pending")
        || running.state.as_ref().is_none_or(|s| s.running.is_none())
        || spec
            .ephemeral_containers
            .as_ref()
            .is_some_and(|containers| !containers.is_empty())
        || status
            .init_container_statuses
            .as_ref()
            .is_some_and(|statuses| {
                statuses.iter().any(|s| {
                    s.name != INIT_NAME && s.state.as_ref().is_some_and(|s| s.running.is_some())
                })
            })
        || status.container_statuses.as_ref().is_some_and(|statuses| {
            statuses
                .iter()
                .any(|s| s.state.as_ref().is_some_and(|s| s.running.is_some()))
        })
    {
        return Err(pending());
    }
    Ok(ContainerIdentity {
        container_id: running.container_id.clone().ok_or_else(conflict)?,
        image_id: running.image_id.clone(),
    })
}

async fn preflight(
    backend: &Backend<'_>,
    slot: &Slot,
    expected: &GrantIdentity,
) -> Result<ContainerIdentity, Status> {
    backend.check_resources(slot).await?;
    let pod = backend
        .api::<Pod>()
        .get(&backend.name)
        .await
        .map_err(backend_error)?;
    backend.check_labels(&pod.metadata, slot.allocation.as_ref())?;
    target(
        &pod,
        expected,
        slot.preparation["image"].as_str().ok_or_else(conflict)?,
    )
}

// kube 0.90 owns a spawned websocket pump: dropping AttachedProcess alone does
// not abort it. Close it on every error/cancellation as well as after the reply.
struct Helper(AttachedProcess);

impl Drop for Helper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn helper(backend: &Backend<'_>, observe_only: bool) -> Result<Helper, Status> {
    let binary = format!(
        "{}/openshell-sandbox",
        openshell_core::driver_utils::SUPERVISOR_CONTAINER_DIR
    );
    let command = if observe_only {
        STATUS_SUBCOMMAND
    } else {
        DELIVER_SUBCOMMAND
    };
    backend
        .api::<Pod>()
        .exec(
            &backend.name,
            [binary.as_str(), command],
            &AttachParams {
                container: Some(INIT_NAME.into()),
                stdin: true,
                stdout: true,
                stderr: false,
                tty: false,
                ..Default::default()
            },
        )
        .await
        .map(Helper)
        .map_err(|_| Status::unavailable("private grant helper is unavailable"))
}

async fn read_status(output: &mut (impl AsyncBufRead + Unpin)) -> Result<GrantStatus, Status> {
    let mut bytes = Vec::new();
    output
        .take(MAX_CONTROL_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| uncertain())?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES || bytes.last() != Some(&b'\n') {
        return Err(uncertain());
    }
    serde_json::from_slice(&bytes).map_err(|_| uncertain())
}

async fn send_request(
    input: &mut (impl AsyncWrite + Unpin),
    request: &GrantRequest,
) -> Result<(), Status> {
    let mut bytes = serde_json::to_vec(request).map_err(|_| conflict())?;
    bytes.push(b'\n');
    input.write_all(&bytes).await.map_err(|_| uncertain())?;
    input.flush().await.map_err(|_| uncertain())
}

fn check_status(status: &GrantStatus, request: &GrantRequest) -> Result<(), Status> {
    if status.identity != request.identity || status.role != GrantRole::Init {
        return Err(conflict());
    }
    Ok(())
}

async fn exchange<F, Fut>(
    input: &mut (impl AsyncWrite + Unpin),
    output: &mut (impl AsyncRead + Unpin),
    request: &GrantRequest,
    grant: &[u8],
    authorize: F,
) -> Result<(), Status>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), Status>>,
{
    let mut output = BufReader::new(output);
    send_request(input, request).await?;
    let status = read_status(&mut output).await?;
    check_status(&status, request)?;
    if status.issued || status.grant_hash.is_some() {
        return Err(uncertain());
    }
    authorize().await?;
    input.write_all(grant).await.map_err(|_| uncertain())?;
    input.write_all(b"\n").await.map_err(|_| uncertain())?;
    input.flush().await.map_err(|_| uncertain())?;
    let status = read_status(&mut output).await?;
    check_status(&status, request)?;
    if !status.issued || status.grant_hash != request.grant_hash {
        return Err(uncertain());
    }
    Ok(())
}

pub(super) async fn deliver(backend: &Backend<'_>, grant: &Value) -> Result<(), Status> {
    let result = tokio::time::timeout(API_TIMEOUT, async {
        let (_, slot) = backend.load().await?;
        let expected = identity(backend, &slot)?;
        let hash = grant_hash(grant);
        if slot.grant_hash.as_deref() != Some(hash.as_str()) {
            return Err(conflict());
        }
        if slot.init_delivery.is_some() {
            return settle_inner(backend).await;
        }
        let bytes = serde_json::to_vec(grant).map_err(|_| conflict())?;
        if bytes.len() as u64 > MAX_GRANT_BYTES {
            return Err(conflict());
        }
        let target = preflight(backend, &slot, &expected).await?;
        let mut helper = helper(backend, false).await?;
        let mut input = helper.0.stdin().ok_or_else(uncertain)?;
        let mut output = helper.0.stdout().ok_or_else(uncertain)?;
        let request = GrantRequest {
            identity: expected.clone(),
            role: GrantRole::Init,
            grant_hash: Some(hash.clone()),
        };
        let delivery = Delivery {
            identity: expected.clone(),
            target: target.clone(),
            grant_hash: hash,
            acknowledged: false,
        };
        exchange(&mut input, &mut output, &request, &bytes, || async {
            let (cm, mut slot) = backend.load().await?;
            if identity(backend, &slot)? != expected
                || slot.grant_hash.as_ref() != Some(&delivery.grant_hash)
                || slot.init_delivery.is_some()
                || preflight(backend, &slot, &expected).await? != target
            {
                return Err(conflict());
            }
            // This resource-version CAS is durable before any grant bytes leave
            // the gateway. A failed/uncertain CAS sends nothing.
            slot.init_delivery = Some(Box::new(delivery.clone()));
            backend.save(cm, &slot).await
        })
        .await?;
        acknowledge(backend, &delivery).await
    })
    .await
    .unwrap_or_else(|_| Err(uncertain()));
    quarantine_delivery(backend, result).await
}

async fn acknowledge(backend: &Backend<'_>, delivery: &Delivery) -> Result<(), Status> {
    let (cm, mut slot) = backend.load().await?;
    if identity(backend, &slot)? != delivery.identity
        || slot.grant_hash.as_ref() != Some(&delivery.grant_hash)
        || slot.init_delivery.as_ref().is_none_or(|ticket| {
            ticket.identity != delivery.identity
                || ticket.target != delivery.target
                || ticket.grant_hash != delivery.grant_hash
        })
    {
        return Err(conflict());
    }
    backend.check_resources(&slot).await?;
    slot.init_delivery
        .as_mut()
        .ok_or_else(conflict)?
        .acknowledged = true;
    slot.quarantined = false;
    backend.save(cm, &slot).await
}

fn terminated_proof(pod: &Pod, delivery: &Delivery) -> bool {
    if pod.metadata.uid.as_deref() != Some(delivery.identity.pod_uid.to_string().as_str())
        || pod.metadata.deletion_timestamp.is_some()
    {
        return false;
    }
    let Some(status) = pod
        .status
        .as_ref()
        .and_then(|s| s.init_container_statuses.as_ref())
        .and_then(|statuses| statuses.iter().find(|s| s.name == INIT_NAME))
    else {
        return false;
    };
    let Some(terminated) = status.state.as_ref().and_then(|s| s.terminated.as_ref()) else {
        return false;
    };
    let proof: Option<Value> = terminated
        .message
        .as_deref()
        .and_then(|message| serde_json::from_str(message).ok());
    status.restart_count == 0
        && status.image_id == delivery.target.image_id
        && terminated.container_id.as_deref() == Some(delivery.target.container_id.as_str())
        && terminated.exit_code == 0
        && proof
            == Some(json!({
                "version":1,"slotId":delivery.identity.slot_id,"generation":delivery.identity.generation,
                "podUid":delivery.identity.pod_uid,"sandboxId":delivery.identity.sandbox_id,
                "allocationId":delivery.identity.allocation_id,"grantHash":delivery.grant_hash,
            }))
}

async fn settle_inner(backend: &Backend<'_>) -> Result<(), Status> {
    let (_, slot) = backend.load().await?;
    let expected = identity(backend, &slot)?;
    let delivery = slot.init_delivery.as_ref().ok_or_else(uncertain)?;
    if delivery.identity != expected || slot.grant_hash.as_ref() != Some(&delivery.grant_hash) {
        return Err(conflict());
    }
    backend.check_resources(&slot).await?;
    let pod = backend
        .api::<Pod>()
        .get(&backend.name)
        .await
        .map_err(backend_error)?;
    if terminated_proof(&pod, delivery) {
        return if delivery.acknowledged && !slot.quarantined {
            Ok(())
        } else {
            acknowledge(backend, delivery).await
        };
    }
    if preflight(backend, &slot, &expected).await? != delivery.target {
        return Err(conflict());
    }
    if delivery.acknowledged {
        return if slot.quarantined {
            acknowledge(backend, delivery).await
        } else {
            Ok(())
        };
    }
    let mut helper = helper(backend, true).await?;
    let mut input = helper.0.stdin().ok_or_else(uncertain)?;
    let mut output = helper.0.stdout().ok_or_else(uncertain)?;
    let request = GrantRequest {
        identity: expected.clone(),
        role: GrantRole::Init,
        grant_hash: None,
    };
    send_request(&mut input, &request).await?;
    let status = read_status(&mut BufReader::new(&mut output)).await?;
    check_status(&status, &request)?;
    let (_, latest) = backend.load().await?;
    if identity(backend, &latest)? != expected
        || preflight(backend, &latest, &expected).await? != delivery.target
        || !status.issued
        || status.grant_hash.as_ref() != Some(&delivery.grant_hash)
    {
        return Err(uncertain());
    }
    acknowledge(backend, delivery).await
}

pub(super) async fn settle(backend: &Backend<'_>) -> Result<(), Status> {
    let result = tokio::time::timeout(API_TIMEOUT, settle_inner(backend))
        .await
        .unwrap_or_else(|_| Err(uncertain()));
    quarantine_delivery(backend, result).await
}

async fn quarantine_delivery(
    backend: &Backend<'_>,
    result: Result<(), Status>,
) -> Result<(), Status> {
    if result.is_err() {
        // A ticket, including an uncertain ticket write, is permanent. With no
        // ticket the nonsecret handshake may be retried; never replay payloads.
        let (cm, mut slot) = backend.load().await?;
        if slot.init_delivery.is_some() && !slot.quarantined {
            slot.quarantined = true;
            backend.save(cm, &slot).await?;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    fn request() -> GrantRequest {
        GrantRequest {
            identity: GrantIdentity {
                slot_id: Uuid::from_u128(1),
                generation: 1,
                pod_uid: Uuid::from_u128(2),
                sandbox_id: Uuid::from_u128(3),
                allocation_id: Uuid::from_u128(4),
            },
            role: GrantRole::Init,
            grant_hash: Some("a".repeat(64)),
        }
    }

    fn status(request: &GrantRequest, published: bool) -> GrantStatus {
        GrantStatus {
            identity: request.identity.clone(),
            role: request.role,
            issued: published,
            grant_hash: if published {
                request.grant_hash.clone()
            } else {
                None
            },
        }
    }

    fn pod(request: &GrantRequest) -> Value {
        let image = format!("registry.example/assistant@sha256:{}", "a".repeat(64));
        json!({
            "metadata":{"uid":request.identity.pod_uid},
            "spec":{"containers":[],
                "initContainers":[{"name":INIT_NAME,"image":image,
                    "securityContext":{"runAsUser":0}}]},
            "status":{"phase":"Pending","initContainerStatuses":[{
                "name":INIT_NAME,"image":image,"imageID":image,
                "containerID":"containerd://original","restartCount":0,"ready":false,
                "state":{"running":{}}}]}
        })
    }

    #[test]
    fn replaced_restarted_or_untrusted_init_cannot_receive_a_grant() {
        let request = request();
        let original = pod(&request);
        let image = original["spec"]["initContainers"][0]["image"]
            .as_str()
            .unwrap();
        let expected = target(
            &serde_json::from_value(original.clone()).unwrap(),
            &request.identity,
            image,
        )
        .unwrap();
        for (pointer, value) in [
            ("/metadata/uid", json!(Uuid::from_u128(9))),
            ("/status/phase", json!("Running")),
            (
                "/status/initContainerStatuses/0/image",
                json!("other-image"),
            ),
            (
                "/status/initContainerStatuses/0/imageID",
                json!("other-image-id"),
            ),
            ("/status/initContainerStatuses/0/restartCount", json!(1)),
            (
                "/status/initContainerStatuses/0/state",
                json!({"waiting":{}}),
            ),
            (
                "/spec/initContainers/0/securityContext/runAsUser",
                json!(1000),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                target(
                    &serde_json::from_value(changed).unwrap(),
                    &request.identity,
                    image,
                )
                .is_err(),
                "{pointer}"
            );
        }
        let mut deleting = original.clone();
        deleting["metadata"]["deletionTimestamp"] = json!("2026-10-29T09:00:00Z");
        assert!(
            target(
                &serde_json::from_value(deleting).unwrap(),
                &request.identity,
                image,
            )
            .is_err()
        );
        let mut restarted = original.clone();
        restarted["status"]["initContainerStatuses"][0]["containerID"] =
            json!("containerd://replacement");
        assert!(
            target(
                &serde_json::from_value(restarted).unwrap(),
                &request.identity,
                image,
            )
            .unwrap()
                != expected
        );
    }

    #[tokio::test]
    async fn secret_payload_follows_the_durable_authorization() {
        let request = request();
        let authorized = AtomicBool::new(false);
        let (client, remote) = tokio::io::duplex(8192);
        let (mut output, mut input) = tokio::io::split(client);
        let (remote_output, mut remote_input) = tokio::io::split(remote);
        let remote = async {
            let mut remote_output = BufReader::new(remote_output);
            let mut header = String::new();
            remote_output.read_line(&mut header).await.unwrap();
            assert!(!header.contains("credential-marker"));
            remote_input
                .write_all(
                    format!(
                        "{}\n",
                        serde_json::to_string(&status(&request, false)).unwrap()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut payload = String::new();
            remote_output.read_line(&mut payload).await.unwrap();
            assert!(authorized.load(Ordering::SeqCst));
            assert_eq!(payload, "{\"secret\":\"credential-marker\"}\n");
            remote_input
                .write_all(
                    format!(
                        "{}\n",
                        serde_json::to_string(&status(&request, true)).unwrap()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        };
        let caller = exchange(
            &mut input,
            &mut output,
            &request,
            br#"{"secret":"credential-marker"}"#,
            || async {
                authorized.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        let (result, ()) = tokio::join!(caller, remote);
        result.unwrap();
    }

    #[tokio::test]
    async fn conflicting_handshake_or_failed_ticket_sends_no_secret() {
        let request = request();
        for case in 0..4 {
            let mut reply = status(&request, false);
            match case {
                0 => reply.identity.pod_uid = Uuid::from_u128(9),
                1 => reply.issued = true,
                2 => reply.grant_hash = request.grant_hash.clone(),
                _ => {}
            }
            let response = format!("{}\n", serde_json::to_string(&reply).unwrap());
            let mut output = response.as_bytes();
            let mut input = Vec::new();
            let result = exchange(
                &mut input,
                &mut output,
                &request,
                b"credential-marker",
                || async { Err(Status::aborted("retained identity or ticket CAS changed")) },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(
                input,
                format!("{}\n", serde_json::to_string(&request).unwrap()).into_bytes()
            );
        }
    }

    #[tokio::test]
    async fn malformed_or_missing_ack_is_sanitized_and_indeterminate() {
        let request = request();
        for reply in [
            String::new(),
            "credential-marker\n".into(),
            "x".repeat(4097),
            serde_json::to_string(&status(&request, true)).unwrap(),
            format!(
                "{}\n",
                serde_json::to_string(&status(&request, false)).unwrap()
            ),
        ] {
            let response = format!(
                "{}\n{reply}",
                serde_json::to_string(&status(&request, false)).unwrap()
            );
            let result = exchange(
                &mut Vec::new(),
                &mut response.as_bytes(),
                &request,
                b"credential-marker",
                || async { Ok(()) },
            )
            .await;
            let error = result.unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable);
            assert!(!format!("{error:?}").contains("credential-marker"));
        }
    }

    #[test]
    fn completed_init_settles_only_its_original_identity_hash_and_container() {
        let request = request();
        let original = pod(&request);
        let delivery = Delivery {
            identity: request.identity.clone(),
            target: target(
                &serde_json::from_value(original.clone()).unwrap(),
                &request.identity,
                original["spec"]["initContainers"][0]["image"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
            grant_hash: request.grant_hash.clone().unwrap(),
            acknowledged: false,
        };
        let mut completed = original;
        completed["status"]["phase"] = json!("Running");
        completed["status"]["initContainerStatuses"][0]["state"] = json!({"terminated":{
            "exitCode":0,"containerID":delivery.target.container_id,
            "message":json!({"version":1,"slotId":delivery.identity.slot_id,
                "generation":delivery.identity.generation,"podUid":delivery.identity.pod_uid,
                "sandboxId":delivery.identity.sandbox_id,"allocationId":delivery.identity.allocation_id,
                "grantHash":delivery.grant_hash}).to_string()
        }});
        assert!(terminated_proof(
            &serde_json::from_value(completed.clone()).unwrap(),
            &delivery
        ));
        for pointer in [
            "/metadata/uid",
            "/status/initContainerStatuses/0/imageID",
            "/status/initContainerStatuses/0/state/terminated/containerID",
            "/status/initContainerStatuses/0/state/terminated/message",
        ] {
            let mut changed = completed.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("different");
            assert!(!terminated_proof(
                &serde_json::from_value(changed).unwrap(),
                &delivery
            ));
        }
    }
}
