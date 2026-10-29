// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One native resource set, not a capacity pool. Kubernetes CAS is the allocation
//! authority; the permanent database reservation fences creation of that authority.
//! An issued CREATE is never replayed, including after process or replica loss.

#![allow(clippy::result_large_err)]

mod private_grant;
#[cfg(test)]
mod resource_tests;
mod tenant;

use crate::persistence::ObjectType;
use k8s_openapi::api::core::v1::{ConfigMap, PersistentVolumeClaim, Pod, Secret};
use kube::api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Api, Client};
use openshell_core::proto::Sandbox;
use openshell_driver_kubernetes::{
    KubernetesComputeDriver,
    config::{KubernetesComputeConfig, SupervisorTopology, WorkspaceMode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use tonic::Status;
use uuid::Uuid;

use super::Operation;
use crate::{ServerState, auth::principal::Principal, persistence::WriteCondition};

const RECORD_TYPE: &str = "native_prewarm_slot_v1";
const DATA_KEY: &str = "slot.json";
const MANAGED: &str = "globster.dev/managed-by";
const MANAGED_VALUE: &str = "workload-gateway";
const WORKLOAD: &str = openshell_core::driver_utils::LABEL_PREWARM_WORKLOAD_ID;
const SLOT: &str = openshell_core::driver_utils::LABEL_PREWARM_SLOT_ID;
const GENERATION: &str = "globster.dev/prewarm-generation";
const ALLOCATION: &str = "globster.dev/prewarm-allocation-id";
const OWNER: &str = "globster.dev/organization-owner";
const PENDING: &str = openshell_core::driver_utils::ANNOTATION_BINDING_PENDING;
const INIT_NAME: &str = "openshell-held-init";
const GRANT: &str = "openshell.io/prewarm-grant";
const API_TIMEOUT: Duration = Duration::from_secs(30);
const ASSISTANT_SCHEMA_VERSION: u64 = 2;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    schema_version: u32,
    slot_id: Uuid,
    workload_id: Uuid,
    generation: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Ticket {
    issued: bool,
    uid: Option<String>,
    rejected: bool,
}

impl Ticket {
    fn may_issue(&self) -> Result<bool, Status> {
        if self.rejected {
            return Err(Status::failed_precondition(
                "prewarm CREATE was definitively rejected; slot may only be retired",
            ));
        }
        Ok(!self.issued)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Reservation {
    identity: Identity,
    preparation: Value,
    storage: Value,
    profile_hash: String,
    fence: Ticket,
    retire_requested: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Independent evidence and quarantine flags.
struct Slot {
    identity: Identity,
    preparation: Value,
    storage: Value,
    profile_hash: String,
    phase: Phase,
    api_version: String,
    tickets: BTreeMap<String, Ticket>,
    allocation: Option<Value>,
    intent_hash: Option<String>,
    grant_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init_delivery: Option<Box<private_grant::Delivery>>,
    initialized: bool,
    tenant_configured: bool,
    launch_released: bool,
    /// Durable diagnostic, never a successful observation state.
    quarantined: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    Preparing,
    Ready,
    Binding,
    Bound,
    Retiring,
    Retired,
}

struct Backend<'a> {
    state: &'a Arc<ServerState>,
    driver: &'a KubernetesComputeDriver,
    principal: &'a Principal,
    config: &'a KubernetesComputeConfig,
    client: Client,
    identity: Identity,
    name: String,
}

fn conflict() -> Status {
    Status::failed_precondition("prewarm identity, ownership or intent conflict")
}
fn pending() -> Status {
    Status::unavailable("prewarm provisioning is incomplete; retry the same identity")
}
fn quarantine() -> Status {
    Status::unavailable(
        "prewarm CREATE outcome is indeterminate; slot is durably quarantined, never recreated or falsely retired; retry observation to settle the original creation",
    )
}
fn backend_error(error: kube::Error) -> Status {
    match error {
        kube::Error::Api(error) if error.code == 409 => {
            Status::aborted("prewarm Kubernetes resource version changed; retry the same identity")
        }
        kube::Error::Api(error) if error.code == 403 => {
            Status::permission_denied("prewarm Kubernetes operation is not authorized")
        }
        kube::Error::Api(error) if error.code == 422 => {
            Status::failed_precondition("prewarm Kubernetes resource update was rejected")
        }
        _ => Status::unavailable("prewarm Kubernetes operation failed"),
    }
}

fn hash(value: &Value) -> String {
    format!("{:x}", Sha256::digest(canonical(value).as_bytes()))
}

/// Match gateway canonicalJson, including ECMAScript numbers and UTF-16 key order.
fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => ryu_js::Buffer::new()
            .format(n.as_f64().expect("finite JSON number"))
            .into(),
        Value::String(s) => serde_json::to_string(s).expect("JSON string"),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!("{}:{}", canonical(&json!(key)), canonical(&object[key])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn compatibility(preparation: &Value) -> String {
    let mut digest = Sha256::new();
    digest.update(b"globster/prewarm-preparation/v1\0");
    digest.update(canonical(preparation));
    format!("sha256:{digest:x}", digest = digest.finalize())
}

fn identity(input: &Value) -> Result<Identity, Status> {
    if input["schemaVersion"].as_u64() == Some(ASSISTANT_SCHEMA_VERSION) {
        return Err(Status::unimplemented(
            "native assistant prewarm v2 initialization and launch are not supported",
        ));
    }
    let result: Identity = serde_json::from_value(json!({
        "schemaVersion": input["schemaVersion"], "slotId": input["slotId"],
        "workloadId": input["workloadId"], "generation": input["generation"],
    }))
    .map_err(|_| Status::invalid_argument("invalid prewarm identity"))?;
    if result.schema_version != 1
        || result.slot_id.is_nil()
        || result.workload_id.is_nil()
        || result.generation == 0
        || result.generation > 9_007_199_254_740_991
    {
        return Err(Status::invalid_argument("invalid prewarm identity"));
    }
    Ok(result)
}

fn immutable_image(value: &str) -> bool {
    value.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn preparation_shape(value: &Value) -> Result<(), Status> {
    fn keys(value: &Value, expected: &[&str]) -> bool {
        value.as_object().is_some_and(|o| {
            o.len() == expected.len() && expected.iter().all(|k| o.contains_key(*k))
        })
    }
    fn quantity(value: &Value, suffixes: &[&str]) -> bool {
        value.as_str().is_some_and(|s| {
            s.len() <= 32
                && suffixes.iter().any(|suffix| {
                    s.strip_suffix(suffix).is_some_and(|digits| {
                        !digits.is_empty()
                            && digits.as_bytes()[0] != b'0'
                            && digits.bytes().all(|c| c.is_ascii_digit())
                    })
                })
        })
    }
    if !keys(
        value,
        &[
            "schemaVersion",
            "providerArtifact",
            "placementKey",
            "image",
            "recipe",
            "resources",
            "workspace",
        ],
    ) || value["schemaVersion"] != 1
        || !["providerArtifact", "placementKey", "image"]
            .iter()
            .all(|key| value[*key].as_str().is_some_and(|s| !s.is_empty()))
        || !keys(&value["recipe"], &["id", "digest", "image"])
        || !["id", "digest", "image"].iter().all(|key| {
            value["recipe"][*key]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        })
        || !keys(&value["resources"], &["cpu", "memory"])
        || !quantity(&value["resources"]["cpu"], &["m"])
        || !quantity(&value["resources"]["memory"], &["Mi", "Gi"])
        || !keys(&value["workspace"], &["capacity"])
        || !quantity(&value["workspace"]["capacity"], &["Mi", "Gi", "Ti"])
    {
        return Err(Status::invalid_argument(
            "invalid prewarm preparation contract",
        ));
    }
    Ok(())
}

fn validate_preparation(config: &KubernetesComputeConfig, input: &Value) -> Result<(), Status> {
    preparation_shape(&input["preparation"])?;
    let approved = config
        .prewarm
        .as_ref()
        .ok_or_else(|| Status::unimplemented("native prewarm is disabled"))?;
    if config.workspace_mode != WorkspaceMode::Shared
        || config.topology != SupervisorTopology::Combined
        || config.sandbox_uid != Some(1000)
        || config.sandbox_gid != Some(1000)
        || config.provider_spiffe_enabled()
    {
        return Err(Status::unimplemented(
            "held-init prewarm requires shared namespace, combined supervisor, explicit UID/GID 1000 and no SPIFFE provider mount",
        ));
    }
    let preparation = &input["preparation"];
    if preparation["schemaVersion"] != 1
        || preparation["providerArtifact"] != approved.provider_artifact
        || preparation["placementKey"] != approved.placement_key
        || preparation["image"] != approved.image
        || preparation["recipe"]["id"] != approved.recipe_id
        || preparation["recipe"]["digest"] != approved.recipe_digest
        || preparation["recipe"]["image"] != approved.recipe_image
        || !immutable_image(&approved.image)
        || !immutable_image(&approved.recipe_image)
        || !immutable_image(&config.supervisor_image)
    {
        return Err(Status::unimplemented(
            "prewarm artifact, recipe or placement is not explicitly approved and immutable",
        ));
    }
    if !preparation["workspace"]["capacity"].is_string()
        || !preparation["resources"].is_object()
        || preparation["resources"]
            .as_object()
            .is_some_and(|r| r.keys().any(|k| !["cpu", "memory"].contains(&k.as_str())))
    {
        return Err(Status::invalid_argument(
            "unsupported prewarm storage or compute resources",
        ));
    }
    Ok(())
}

fn profile_hash(config: &KubernetesComputeConfig) -> Result<String, Status> {
    let mut profile = serde_json::to_value(config).map_err(|_| conflict())?;
    // Approval is checked against the preparation separately. Disabling new
    // preparation must not prevent observation or retirement of existing slots.
    profile
        .as_object_mut()
        .ok_or_else(conflict)?
        .remove("prewarm");
    Ok(hash(&profile))
}

fn retained_identities(
    tickets: &BTreeMap<String, Ticket>,
    objects: [(&str, &Value); 3],
) -> Result<(), Status> {
    for (kind, object) in objects {
        let uid = tickets
            .get(kind)
            .and_then(|ticket| ticket.uid.as_deref())
            .ok_or_else(pending)?;
        if object["metadata"]["uid"].as_str() != Some(uid)
            || !object["metadata"]["deletionTimestamp"].is_null()
        {
            return Err(conflict());
        }
    }
    Ok(())
}

pub(super) async fn execute(
    state: &Arc<ServerState>,
    driver: &KubernetesComputeDriver,
    principal: &Principal,
    operation: Operation,
    request: &str,
) -> Result<Value, Status> {
    let input: Value = serde_json::from_str(request)
        .map_err(|_| Status::invalid_argument("invalid prewarm request document"))?;
    let identity = identity(&input)?;
    let (client, config) = driver.prewarm_context();
    let backend = Backend {
        state,
        driver,
        principal,
        config,
        client,
        name: format!("prewarm-{}", identity.workload_id),
        identity,
    };
    match operation {
        Operation::Prepare => backend.prepare(&input).await?,
        Operation::Observe => {}
        Operation::Bind => backend.bind(principal, &input).await?,
        Operation::Retire => backend.retire(&input).await?,
    }
    backend.observe().await
}

impl Backend<'_> {
    fn api<K>(&self) -> Api<K>
    where
        K: kube::Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>,
    {
        Api::namespaced(self.client.clone(), &self.config.namespace)
    }
    fn sandbox_api(&self, version: &str) -> Api<DynamicObject> {
        let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "agents.x-k8s.io",
            version,
            "Sandbox",
        ));
        Api::namespaced_with(self.client.clone(), &self.config.namespace, &ar)
    }
    fn pod_api(&self) -> Api<DynamicObject> {
        let ar = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "Pod"));
        Api::namespaced_with(self.client.clone(), &self.config.namespace, &ar)
    }
    fn labels(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (MANAGED.into(), MANAGED_VALUE.into()),
            (WORKLOAD.into(), self.identity.workload_id.to_string()),
            (SLOT.into(), self.identity.slot_id.to_string()),
            (GENERATION.into(), self.identity.generation.to_string()),
        ])
    }
    fn storage(&self) -> Value {
        let mut storage = json!({"namespace": self.config.namespace,
            "claimName": format!("globster-workspace-{}",self.identity.workload_id), "accessModes":["ReadWriteOnce"]});
        if !self.config.workspace_storage_class.is_empty() {
            storage["storageClassName"] = json!(self.config.workspace_storage_class);
        }
        storage
    }
    async fn reservation(&self) -> Result<(Reservation, u64), Status> {
        let record = self
            .state
            .store
            .get(
                RECORD_TYPE,
                &format!("{RECORD_TYPE}:{}", self.identity.workload_id),
            )
            .await
            .map_err(|_| Status::unavailable("prewarm reservation lookup failed"))?
            .ok_or_else(|| Status::not_found("prewarm slot does not exist"))?;
        let reservation: Reservation =
            serde_json::from_slice(&record.payload).map_err(|_| conflict())?;
        if reservation.identity != self.identity {
            return Err(conflict());
        }
        Ok((reservation, record.resource_version))
    }
    async fn save_reservation(
        &self,
        reservation: &Reservation,
        version: Option<u64>,
    ) -> Result<(), Status> {
        self.state
            .store
            .put_if(
                RECORD_TYPE,
                &format!("{RECORD_TYPE}:{}", self.identity.workload_id),
                &self.identity.slot_id.to_string(),
                "",
                &serde_json::to_vec(reservation).map_err(|_| conflict())?,
                None,
                version.map_or(
                    WriteCondition::MustCreate,
                    WriteCondition::MatchResourceVersion,
                ),
            )
            .await
            .map_err(|e| {
                if e.is_expected() {
                    Status::aborted("prewarm reservation changed; retry the same identity")
                } else {
                    Status::unavailable("prewarm reservation write failed")
                }
            })?;
        Ok(())
    }
    async fn reserve(&self, input: &Value, retiring: bool) -> Result<Reservation, Status> {
        preparation_shape(&input["preparation"])?;
        if !retiring {
            validate_preparation(self.config, input)?;
        }
        if !retiring
            && self
                .state
                .store
                .get_message::<Sandbox>(&self.identity.workload_id.to_string())
                .await
                .map_err(|_| conflict())?
                .is_some()
        {
            return Err(conflict());
        }
        let storage = self.storage();
        if !retiring && input["storage"] != storage {
            return Err(Status::unimplemented(
                "prewarm storage must match the configured native namespace and storage class",
            ));
        }
        match self.reservation().await {
            Ok((mut record, version)) => {
                if record.preparation != input["preparation"]
                    || record.storage != storage
                    || (!retiring && record.profile_hash != profile_hash(self.config)?)
                {
                    return Err(conflict());
                }
                if retiring && !record.retire_requested {
                    record.retire_requested = true;
                    self.save_reservation(&record, Some(version)).await?;
                }
                if !retiring && record.retire_requested {
                    return Err(conflict());
                }
                Ok(record)
            }
            Err(e) if e.code() == tonic::Code::NotFound => {
                let record = Reservation {
                    identity: self.identity.clone(),
                    preparation: input["preparation"].clone(),
                    storage,
                    profile_hash: profile_hash(self.config)?,
                    fence: Ticket::default(),
                    retire_requested: retiring,
                };
                self.save_reservation(&record, None).await?;
                Ok(record)
            }
            Err(e) => Err(e),
        }
    }
    async fn load(&self) -> Result<(ConfigMap, Slot), Status> {
        let (reservation, _) = self.reservation().await?;
        let cm = self
            .api::<ConfigMap>()
            .get_opt(&self.name)
            .await
            .map_err(backend_error)?
            .ok_or_else(|| {
                if reservation.fence.issued {
                    quarantine()
                } else {
                    pending()
                }
            })?;
        self.check_labels(&cm.metadata, None)?;
        if cm.metadata.deletion_timestamp.is_some() {
            return Err(conflict());
        }
        if reservation
            .fence
            .uid
            .as_ref()
            .is_some_and(|uid| cm.metadata.uid.as_ref() != Some(uid))
        {
            return Err(conflict());
        }
        let slot: Slot = serde_json::from_str(
            cm.data
                .as_ref()
                .and_then(|d| d.get(DATA_KEY))
                .ok_or_else(conflict)?,
        )
        .map_err(|_| conflict())?;
        if slot.identity != self.identity
            || slot.preparation != reservation.preparation
            || slot.storage != reservation.storage
            || slot.profile_hash != reservation.profile_hash
        {
            return Err(conflict());
        }
        Ok((cm, slot))
    }
    async fn save(&self, mut cm: ConfigMap, slot: &Slot) -> Result<(), Status> {
        cm.data = Some(BTreeMap::from([(
            DATA_KEY.into(),
            serde_json::to_string(slot).map_err(|_| conflict())?,
        )]));
        self.api::<ConfigMap>()
            .replace(&self.name, &PostParams::default(), &cm)
            .await
            .map_err(|e| match e {
                kube::Error::Api(a) if a.code == 409 => {
                    Status::aborted("prewarm resource fence changed; retry")
                }
                _ => Status::unavailable("prewarm resource fence update failed"),
            })?;
        Ok(())
    }
    fn check_labels(
        &self,
        meta: &kube::core::ObjectMeta,
        allocation: Option<&Value>,
    ) -> Result<(), Status> {
        let labels = meta.labels.as_ref().ok_or_else(conflict)?;
        if self.labels().iter().any(|(k, v)| labels.get(k) != Some(v)) {
            return Err(conflict());
        }
        match allocation {
            Some(a) => {
                if labels.get(ALLOCATION).map(String::as_str) != a["id"].as_str()
                    || labels.get(OWNER).map(String::as_str) != a["ownershipMarker"].as_str()
                {
                    return Err(conflict());
                }
            }
            None => {
                if labels.contains_key(ALLOCATION) || labels.contains_key(OWNER) {
                    return Err(conflict());
                }
            }
        }
        Ok(())
    }
    fn owner(&self, cm: &ConfigMap) -> Result<Value, Status> {
        Ok(
            json!({"apiVersion":"v1","kind":"ConfigMap","name":self.name,
            "uid":cm.metadata.uid.as_ref().ok_or_else(conflict)?,"controller":true,"blockOwnerDeletion":true}),
        )
    }
    async fn ensure_fence(&self) -> Result<(), Status> {
        let (mut reservation, version) = self.reservation().await?;
        if self
            .api::<ConfigMap>()
            .get_opt(&self.name)
            .await
            .map_err(backend_error)?
            .is_some()
        {
            if !reservation.fence.issued || reservation.fence.rejected {
                return Err(conflict());
            }
            let (cm, _) = self.load().await?;
            if reservation.fence.uid.is_none() {
                reservation.fence.uid = cm.metadata.uid;
                self.save_reservation(&reservation, Some(version)).await?;
            }
            return Ok(());
        }
        if reservation.fence.rejected {
            return Err(Status::failed_precondition(
                "prewarm authority CREATE was definitively rejected; retire this identity",
            ));
        }
        if reservation.fence.issued {
            return Err(quarantine());
        }
        if reservation.retire_requested {
            return Ok(());
        }
        let rendered = self.neutral_sandbox(&reservation.preparation).await?;
        let api_version = rendered
            .types
            .as_ref()
            .ok_or_else(conflict)?
            .api_version
            .rsplit('/')
            .next()
            .ok_or_else(conflict)?
            .to_owned();
        reservation.fence.issued = true;
        self.save_reservation(&reservation, Some(version)).await?;
        let slot = Slot {
            identity: self.identity.clone(),
            preparation: reservation.preparation,
            storage: reservation.storage,
            profile_hash: reservation.profile_hash,
            phase: Phase::Preparing,
            api_version,
            tickets: BTreeMap::new(),
            allocation: None,
            intent_hash: None,
            grant_hash: None,
            init_delivery: None,
            initialized: false,
            tenant_configured: false,
            launch_released: false,
            quarantined: false,
        };
        let cm: ConfigMap =
            serde_json::from_value(json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{
            "name":self.name,"namespace":self.config.namespace,"labels":self.labels()},
            "data":{(DATA_KEY):serde_json::to_string(&slot).map_err(|_|conflict())?}}))
            .map_err(|_| conflict())?;
        let created = tokio::time::timeout(
            API_TIMEOUT,
            self.api::<ConfigMap>().create(&PostParams::default(), &cm),
        )
        .await;
        match created {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(kube::Error::Api(error)))
                if [400, 401, 403, 404, 405, 415, 422].contains(&error.code) =>
            {
                let (mut reservation, version) = self.reservation().await?;
                reservation.fence.rejected = true;
                self.save_reservation(&reservation, Some(version)).await?;
                Err(Status::failed_precondition(
                    "prewarm authority CREATE was definitively rejected; retire this identity",
                ))
            }
            _ => Err(quarantine()),
        }
    }
    async fn neutral_sandbox(&self, preparation: &Value) -> Result<DynamicObject, Status> {
        let sandbox = tenant::sandbox_request(self, &json!({}), &preparation["resources"], None)?;
        let public = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: self.identity.workload_id.to_string(),
                name: tenant::runtime_name(self.identity.workload_id),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: sandbox.spec,
            ..Default::default()
        };
        let driver =
            crate::compute::driver_sandbox_from_public(&public, "kubernetes").map_err(|s| *s)?;
        self.driver
            .render_sandbox(&driver)
            .await
            .map_err(|_| Status::failed_precondition("prewarm ordinary pod rendering failed"))
    }
    async fn prepare(&self, input: &Value) -> Result<(), Status> {
        self.reserve(input, false).await?;
        self.ensure_fence().await?;
        let (cm, slot) = self.load().await?;
        if slot.phase == Phase::Ready {
            return Ok(());
        }
        if slot.phase != Phase::Preparing {
            return Err(conflict());
        }
        let owner = self.owner(&cm)?;
        let mut rendered = self.neutral_sandbox(&slot.preparation).await?;
        let pod_template = self.held_template(&rendered.data["spec"]["podTemplate"], &slot)?;
        rendered.metadata.name = Some(self.name.clone());
        rendered.metadata.labels = Some(self.labels());
        rendered.metadata.annotations = Some(BTreeMap::from([(
            "agents.x-k8s.io/pod-name".into(),
            self.name.clone(),
        )]));
        rendered.metadata.owner_references =
            Some(serde_json::from_value(json!([owner.clone()])).map_err(|_| conflict())?);
        rendered.data["spec"]["podTemplate"] = pod_template.clone();
        if slot.api_version == "v1beta1" {
            rendered.data["spec"]["operatingMode"] = json!("Suspended");
        } else {
            rendered.data["spec"]["replicas"] = json!(0);
        }
        self.create_once(
            "sandbox",
            serde_json::to_value(rendered).map_err(|_| conflict())?,
        )
        .await?;
        let mut pvc = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{
            "name":slot.storage["claimName"],"namespace":self.config.namespace,"labels":self.labels(),"ownerReferences":[owner.clone()]},
            "spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":slot.preparation["workspace"]["capacity"]}}}});
        if let Some(class) = slot.storage.get("storageClassName") {
            pvc["spec"]["storageClassName"] = class.clone();
        }
        self.create_once("storage", pvc).await?;
        self.create_once(
            "compute",
            json!({"apiVersion":"v1","kind":"Pod","metadata":{
            "name":self.name,"namespace":self.config.namespace,"labels":self.labels(),
            "annotations":pod_template["metadata"]["annotations"],"ownerReferences":[owner]},
            "spec":pod_template["spec"]}),
        )
        .await?;
        let (cm, mut slot) = self.load().await?;
        if slot.phase != Phase::Preparing {
            return Err(conflict());
        }
        if self.held_running().await? {
            slot.phase = Phase::Ready;
            self.save(cm, &slot).await?;
        }
        Ok(())
    }
    fn held_template(&self, template: &Value, slot: &Slot) -> Result<Value, Status> {
        let mut result = template.clone();
        let spec = result["spec"].as_object_mut().ok_or_else(conflict)?;
        let volumes = spec
            .get_mut("volumes")
            .and_then(Value::as_array_mut)
            .ok_or_else(conflict)?;
        volumes.extend([
            json!({"name":"prewarm-state","emptyDir":{}}),
            json!({"name":"prewarm-init","secret":{"secretName":format!("{}-init",self.name),"optional":true,"defaultMode":256}}),
            json!({"name":"prewarm-launch","secret":{"secretName":format!("{}-launch",self.name),"optional":true,"defaultMode":256}}),
            json!({"name":"prewarm-recipe","image":{"reference":slot.preparation["recipe"]["image"],"pullPolicy":"IfNotPresent"}}),
        ]);
        let agent = spec
            .get_mut("containers")
            .and_then(Value::as_array_mut)
            .and_then(|c| c.first_mut())
            .ok_or_else(conflict)?;
        let old_command = agent["command"].as_array().cloned().ok_or_else(|| {
            Status::unimplemented("prewarm requires the native sideloaded supervisor command")
        })?;
        let binary = old_command
            .first()
            .and_then(Value::as_str)
            .ok_or_else(conflict)?
            .to_owned();
        let mut supervisor_args: Vec<Value> = old_command.into_iter().skip(1).collect();
        supervisor_args.extend(agent["args"].as_array().cloned().unwrap_or_default());
        let common = vec![
            json!("await-binding"),
            json!("--slot-id"),
            json!(self.identity.slot_id),
            json!("--generation"),
            json!(self.identity.generation.to_string()),
            json!("--sandbox-id"),
            json!(self.identity.workload_id),
            json!("--pod-uid"),
            json!("$(OPENSHELL_PREWARM_POD_UID)"),
            json!("--require-workspace-initialization"),
        ];
        let mut init_args = common.clone();
        init_args.extend([
            json!("--grant"),
            json!("/run/openshell-prewarm-init/grant.json"),
            json!("--initialize-only"),
        ]);
        let mut main_args = common;
        main_args.extend([
            json!("--grant"),
            json!("/run/openshell-prewarm-launch/grant.json"),
            json!("--"),
        ]);
        main_args.extend(supervisor_args);
        agent["command"] = json!([binary]);
        agent["args"] = json!(main_args);
        let pod_uid = json!({"name":"OPENSHELL_PREWARM_POD_UID","valueFrom":{"fieldRef":{"fieldPath":"metadata.uid"}}});
        agent["env"]
            .as_array_mut()
            .ok_or_else(conflict)?
            .push(pod_uid.clone());
        let mounts = agent["volumeMounts"].as_array_mut().ok_or_else(conflict)?;
        mounts.extend([json!({"name":"prewarm-state","mountPath":"/run/openshell-binding-state"}),
            json!({"name":"prewarm-launch","mountPath":"/run/openshell-prewarm-launch","readOnly":true}),
            json!({"name":"prewarm-recipe","mountPath":"/recipe","subPath":"recipe","readOnly":true})]);
        // The idle process sees only its executable, recipe, blank claim and
        // private binding state. Ordinary SA/mTLS/proxy mounts remain main-only.
        let init_mounts: Vec<Value> = mounts.iter().filter(|m| {
            let name=m["name"].as_str().unwrap_or_default();
            name=="prewarm-state" || name=="prewarm-recipe" || name=="globster-workspace"
                && m["mountPath"]=="/workspace" || name.contains("supervisor")
        }).cloned().chain(std::iter::once(json!({"name":"prewarm-init","mountPath":"/run/openshell-prewarm-init","readOnly":true}))).collect();
        let init = json!({"name":INIT_NAME,"image":slot.preparation["image"],"imagePullPolicy":self.config.image_pull_policy,
            "command":[binary],"args":init_args,"env":[pod_uid],"resources":agent["resources"],
            "securityContext":{"runAsUser":0,"runAsGroup":0},"volumeMounts":init_mounts,
            "terminationMessagePolicy":"File"});
        spec.entry("initContainers")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(conflict)?
            .push(init);
        Ok(result)
    }
    async fn held_running(&self) -> Result<bool, Status> {
        let Some(pod) = self
            .api::<Pod>()
            .get_opt(&self.name)
            .await
            .map_err(backend_error)?
        else {
            return Ok(false);
        };
        if pod.metadata.deletion_timestamp.is_some() {
            return Ok(false);
        }
        let running = pod
            .status
            .and_then(|s| s.init_container_statuses)
            .is_some_and(|statuses| {
                statuses.iter().any(|s| {
                    s.name == INIT_NAME && s.state.as_ref().is_some_and(|s| s.running.is_some())
                })
            });
        if !running {
            return Ok(false);
        }
        let uid = pod.metadata.uid.ok_or_else(conflict)?;
        let expected = format!(
            "OpenShell held-init ready slot={} generation={} pod={} sandbox={}",
            self.identity.slot_id, self.identity.generation, uid, self.identity.workload_id
        );
        let logs = self
            .api::<Pod>()
            .logs(
                &self.name,
                &kube::api::LogParams {
                    container: Some(INIT_NAME.into()),
                    tail_lines: Some(10),
                    limit_bytes: Some(4096),
                    ..Default::default()
                },
            )
            .await
            .map_err(backend_error)?;
        Ok(logs.lines().any(|line| line == expected))
    }
    async fn check_resources(&self, slot: &Slot) -> Result<(), Status> {
        let pod = self.object("compute", slot).await?.ok_or_else(pending)?;
        let pvc = self.object("storage", slot).await?.ok_or_else(pending)?;
        let sandbox = self.object("sandbox", slot).await?.ok_or_else(pending)?;
        retained_identities(
            &slot.tickets,
            [("compute", &pod), ("storage", &pvc), ("sandbox", &sandbox)],
        )?;
        let volumes = pod["spec"]["volumes"].as_array().ok_or_else(conflict)?;
        let claims: Vec<_> = volumes
            .iter()
            .filter(|volume| volume.get("persistentVolumeClaim").is_some())
            .collect();
        let containers = pod["spec"]["containers"].as_array().ok_or_else(conflict)?;
        let init = pod["spec"]["initContainers"]
            .as_array()
            .ok_or_else(conflict)?;
        if claims.len() != 1
            || claims[0]["name"] != "globster-workspace"
            || claims[0]["persistentVolumeClaim"]["claimName"] != slot.storage["claimName"]
            || claims[0]["persistentVolumeClaim"]["readOnly"] == true
            || pvc["spec"]["accessModes"] != json!(["ReadWriteOnce"])
            || !volumes.iter().any(|volume| {
                volume["name"] == "prewarm-recipe"
                    && volume["image"]["reference"] == slot.preparation["recipe"]["image"]
            })
            || slot
                .storage
                .get("storageClassName")
                .is_some_and(|class| pvc["spec"]["storageClassName"] != *class)
            || containers.len() != 1
            || containers[0]["image"] != slot.preparation["image"]
            || containers[0]["args"][0] != "await-binding"
            || containers[0].get("lifecycle").is_some()
            || !init.iter().any(|container| {
                container["name"] == INIT_NAME
                    && container["image"] == slot.preparation["image"]
                    && container["args"]
                        .as_array()
                        .is_some_and(|args| args.contains(&json!("--initialize-only")))
            })
            || init.iter().any(|container| {
                container["name"] != INIT_NAME
                    && container["volumeMounts"].as_array().is_some_and(|mounts| {
                        mounts
                            .iter()
                            .any(|mount| mount["name"] == "globster-workspace")
                    })
            })
        {
            return Err(Status::failed_precondition(
                "retained-pod layout must have the approved gated image and one exclusive RWO claim/writer",
            ));
        }
        Ok(())
    }
    async fn object(&self, kind: &str, slot: &Slot) -> Result<Option<Value>, Status> {
        let value = match kind {
            "sandbox" => self
                .sandbox_api(&slot.api_version)
                .get_opt(&self.name)
                .await
                .map_err(backend_error)?
                .map(|v| serde_json::to_value(v).expect("Kubernetes object")),
            "compute" => self
                .pod_api()
                .get_opt(&self.name)
                .await
                .map_err(backend_error)?
                .map(|v| serde_json::to_value(v).expect("Kubernetes object")),
            "storage" => self
                .api::<PersistentVolumeClaim>()
                .get_opt(slot.storage["claimName"].as_str().ok_or_else(conflict)?)
                .await
                .map_err(backend_error)?
                .map(|v| serde_json::to_value(v).expect("Kubernetes object")),
            "init" | "launch" => self
                .api::<Secret>()
                .get_opt(&format!("{}-{kind}", self.name))
                .await
                .map_err(backend_error)?
                .map(|v| serde_json::to_value(v).expect("Kubernetes object")),
            _ => return Err(conflict()),
        };
        Ok(value)
    }
    async fn create_once(&self, kind: &str, value: Value) -> Result<(), Status> {
        let object: DynamicObject = serde_json::from_value(value).map_err(|_| conflict())?;
        let types = object.types.as_ref().ok_or_else(conflict)?;
        let (group, version) = types
            .api_version
            .split_once('/')
            .unwrap_or(("", types.api_version.as_str()));
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, &types.kind));
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.config.namespace, &resource);
        let (cm, mut slot) = self.load().await?;
        if !matches!(slot.phase, Phase::Preparing | Phase::Binding) {
            return Err(conflict());
        }
        let ticket = slot.tickets.entry(kind.into()).or_default();
        if !ticket.may_issue()? {
            let object = self.object(kind, &slot).await?;
            return self.settle(kind, object).await;
        }
        ticket.issued = true;
        self.save(cm, &slot).await?;
        // Exactly one HTTP write. kube's ordinary client does not install a
        // write-retrying middleware. Never retry this call after any transport error.
        let created =
            tokio::time::timeout(API_TIMEOUT, api.create(&PostParams::default(), &object)).await;
        match created {
            Ok(Ok(object)) => self.settle(kind, Some(json!(object))).await,
            Ok(Err(kube::Error::Api(error)))
                if [400, 401, 403, 404, 405, 415, 422].contains(&error.code) =>
            {
                let (cm, mut slot) = self.load().await?;
                slot.tickets.get_mut(kind).ok_or_else(conflict)?.rejected = true;
                self.save(cm, &slot).await?;
                Err(Status::failed_precondition(
                    "prewarm CREATE was definitively rejected; fix platform configuration and retire this slot, never replay its CREATE",
                ))
            }
            _ => {
                let (cm, mut slot) = self.load().await?;
                slot.quarantined = true;
                self.save(cm, &slot).await?;
                Err(quarantine())
            }
        }
    }
    async fn settle(&self, kind: &str, object: Option<Value>) -> Result<(), Status> {
        let (cm, mut slot) = self.load().await?;
        let Some(object) = object else {
            if slot.tickets.get(kind).is_some_and(|t| t.uid.is_some()) {
                return Err(conflict());
            }
            slot.quarantined = true;
            self.save(cm, &slot).await?;
            return Err(quarantine());
        };
        let meta: kube::core::ObjectMeta =
            serde_json::from_value(object["metadata"].clone()).map_err(|_| conflict())?;
        // Binding may already have stamped allocation ownership on Pod/PVC.
        let expected = if matches!(kind, "compute" | "storage")
            && meta
                .labels
                .as_ref()
                .is_some_and(|l| l.contains_key(ALLOCATION))
        {
            slot.allocation.as_ref()
        } else {
            None
        };
        self.check_labels(&meta, expected)?;
        let ticket = slot.tickets.get_mut(kind).ok_or_else(conflict)?;
        let uid = meta.uid.ok_or_else(conflict)?;
        if !ticket.issued || ticket.uid.as_ref().is_some_and(|old| old != &uid) {
            return Err(conflict());
        }
        if ticket.uid.as_ref() == Some(&uid) {
            return Ok(());
        }
        ticket.uid = Some(uid);
        slot.quarantined = false;
        self.save(cm, &slot).await
    }
    fn receipt(slot: &Slot) -> Result<Value, Status> {
        Ok(
            json!({"sandboxUid":slot.tickets.get("sandbox").and_then(|t|t.uid.as_ref()).ok_or_else(pending)?,
            "computeUid":slot.tickets.get("compute").and_then(|t|t.uid.as_ref()).ok_or_else(pending)?,
            "storageUid":slot.tickets.get("storage").and_then(|t|t.uid.as_ref()).ok_or_else(pending)?}),
        )
    }
    async fn bind(&self, principal: &Principal, input: &Value) -> Result<(), Status> {
        let (_, slot) = self.load().await?;
        if !matches!(slot.phase, Phase::Ready | Phase::Binding | Phase::Bound) {
            return Err(conflict());
        }
        self.check_profile(&slot)?;
        self.check_resources(&slot).await?;
        if slot.phase == Phase::Ready && !self.held_running().await? {
            return Err(Status::failed_precondition(
                "prepared held-init runtime is no longer ready; native retirement is required, never restart or recycle it",
            ));
        }
        tenant::validate(self, &slot, input)?;
        if Self::receipt(&slot)? != input["resourceReceipt"] {
            return Err(conflict());
        }
        let intent_hash = hash(input);
        if matches!(slot.phase, Phase::Binding | Phase::Bound) {
            if slot.intent_hash.as_deref() != Some(&intent_hash) {
                return Err(conflict());
            }
            if slot.phase == Phase::Bound {
                return self.finalize_bound().await;
            }
        } else {
            if slot.phase != Phase::Ready || !self.held_running().await? {
                return Err(conflict());
            }
            let (cm, mut latest) = self.load().await?;
            if latest.phase != Phase::Ready {
                return Err(Status::aborted("prewarm allocation fence changed; retry"));
            }
            // The resource-side single-assignment linearization point. Retirement
            // and every different allocation permanently lose this CAS.
            latest.phase = Phase::Binding;
            latest.intent_hash = Some(intent_hash.clone());
            latest.grant_hash = Some(format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&self.bound_grant(&latest, input)?)
                        .map_err(|_| conflict())?
                )
            ));
            latest.allocation = Some(
                json!({"id":input["allocationId"],"organizationId":input["organization"]["organizationId"],
                "workspaceName":input["organization"]["workspaceName"],"ownershipMarker":input["organization"]["ownershipMarker"],
                "desiredRevision":input["request"]["desired"]["revision"],"fingerprint":input["request"]["desired"]["fingerprints"]["overall"],
                "fingerprints":input["request"]["desired"]["fingerprints"],"bindings":input["request"]["desired"]["secretBindings"]}),
            );
            self.save(cm, &latest).await?;
        }
        let (_, slot) = self.load().await?;
        self.check_resources(&slot).await?;
        self.stamp("storage").await?;
        self.stamp("compute").await?;
        tenant::configure(self, principal, input).await?;
        if self.identity.schema_version == 2 {
            let (cm, mut slot) = self.load().await?;
            if slot.phase != Phase::Binding || slot.intent_hash.as_deref() != Some(&intent_hash) {
                return Err(conflict());
            }
            slot.tenant_configured = true;
            self.save(cm, &slot).await?;
        }
        let (_, slot) = self.load().await?;
        if slot.phase != Phase::Binding || slot.intent_hash.as_deref() != Some(&intent_hash) {
            return Err(conflict());
        }
        let grant = self.bound_grant(&slot, input)?;
        self.check_resources(&slot).await?;
        self.grant("init", &grant).await?;
        self.resume_binding().await
    }
    fn bound_grant(&self, slot: &Slot, input: &Value) -> Result<Value, Status> {
        let receipt = Self::receipt(slot)?;
        let mut initialization = json!({"recipe_id":slot.preparation["recipe"]["id"],"recipe_digest":slot.preparation["recipe"]["digest"]});
        if let Some(configuration) = input["request"]["desired"].get("initialConfiguration") {
            initialization["initial_configuration_json"] = json!(canonical(configuration));
        }
        Ok(
            json!({"version":1,"slot_id":self.identity.slot_id,"generation":self.identity.generation,
            "pod_uid":receipt["computeUid"],"sandbox_id":self.identity.workload_id,"allocation_id":input["allocationId"],
            "main_process":{"version":1,"command":input["launch"]["command"],"tty":false},
            "environment":input["launch"]["environment"],"workspace_initialization":initialization}),
        )
    }
    async fn resume_binding(&self) -> Result<(), Status> {
        let (cm, mut slot) = self.load().await?;
        if slot.phase == Phase::Bound {
            return self.finalize_bound().await;
        }
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        self.check_profile(&slot)?;
        self.check_resources(&slot).await?;
        if self.identity.schema_version == 2 {
            Box::pin(private_grant::settle(self)).await?;
            return Err(Status::unimplemented(
                "native assistant initialization and ordered sidecar release are not supported",
            ));
        }
        let Some(ticket) = slot.tickets.get("init") else {
            return Ok(());
        };
        if ticket.uid.is_none() {
            return Err(quarantine());
        }
        let secret = self
            .api::<Secret>()
            .get(&format!("{}-init", self.name))
            .await
            .map_err(backend_error)?;
        if secret.metadata.uid.as_ref() != ticket.uid.as_ref() {
            return Err(conflict());
        }
        let bytes = &secret
            .data
            .as_ref()
            .and_then(|data| data.get("grant.json"))
            .ok_or_else(conflict)?
            .0;
        if bytes.len() > super::MAX_JSON_BYTES {
            return Err(conflict());
        }
        let grant: Value = serde_json::from_slice(bytes).map_err(|_| conflict())?;
        let grant_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&grant).map_err(|_| conflict())?)
        );
        if slot.grant_hash.as_deref() != Some(&grant_hash) {
            return Err(conflict());
        }
        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&self.identity.workload_id.to_string())
            .await
            .map_err(|_| conflict())?
            .ok_or_else(conflict)?;
        let allocation = slot.allocation.as_ref().ok_or_else(conflict)?;
        let meta = sandbox.metadata.as_ref().ok_or_else(conflict)?;
        if meta.labels.get(ALLOCATION).map(String::as_str) != allocation["id"].as_str()
            || meta.workspace != allocation["workspaceName"]
            || meta
                .annotations
                .get("globster.dev/spec-hash")
                .map(String::as_str)
                != allocation["fingerprint"].as_str()
            || slot
                .tickets
                .iter()
                .any(|(name, ticket)| name.starts_with("provider:") && ticket.uid.is_none())
        {
            return Err(conflict());
        }
        if !slot.tenant_configured {
            slot.tenant_configured = true;
            self.save(cm, &slot).await?;
        }
        let receipt = Self::receipt(&slot)?;
        let pod = self
            .api::<Pod>()
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if pod.metadata.uid.as_deref() != receipt["computeUid"].as_str() {
            return Err(conflict());
        }
        let terminated = pod
            .status
            .as_ref()
            .and_then(|s| s.init_container_statuses.as_ref())
            .and_then(|statuses| statuses.iter().find(|s| s.name == INIT_NAME))
            .and_then(|s| s.state.as_ref())
            .and_then(|s| s.terminated.as_ref());
        let Some(terminated) = terminated else {
            return Ok(());
        };
        if terminated.exit_code != 0 {
            return Err(Status::failed_precondition(
                "retained-pod single-writer initialization failed; supervisor remains unreleased",
            ));
        }
        let proof: Value = serde_json::from_str(terminated.message.as_deref().unwrap_or_default())
            .map_err(|_| conflict())?;
        // Gate hashes a serde_json Value, whose object key order matches this
        // serialization. Configuration itself remains the gateway canonical bytes.
        if proof
            != json!({"version":1,"slotId":self.identity.slot_id,"generation":self.identity.generation,
            "podUid":receipt["computeUid"],"sandboxId":self.identity.workload_id,
            "allocationId":allocation["id"],"grantHash":grant_hash})
        {
            return Err(conflict());
        }
        let (cm, mut slot) = self.load().await?;
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        slot.initialized = true;
        self.save(cm, &slot).await?;
        if !tenant::bindings_ready(self, &slot).await? {
            return Err(Status::failed_precondition(
                "ordinary provider configuration changed or expired before launch; supervisor remains unreleased",
            ));
        }
        self.adopt(&sandbox).await?;
        self.grant("launch", &grant).await?;
        let (cm, mut slot) = self.load().await?;
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        // No outstanding CREATE may survive into a completed binding.
        if slot
            .tickets
            .values()
            .any(|ticket| ticket.issued && ticket.uid.is_none())
        {
            return Err(quarantine());
        }
        slot.launch_released = true;
        slot.phase = Phase::Bound;
        self.save(cm, &slot).await?;
        self.finalize_bound().await
    }
    fn check_profile(&self, slot: &Slot) -> Result<(), Status> {
        validate_preparation(self.config, &json!({"preparation":slot.preparation}))?;
        if slot.profile_hash != profile_hash(self.config)? {
            return Err(Status::failed_precondition(
                "prepared native driver profile changed; original profile is required, never adapt retained resources in place",
            ));
        }
        Ok(())
    }
    async fn finalize_bound(&self) -> Result<(), Status> {
        use prost::Message;
        // Until the private launch grant exists, ordinary lifecycle/exec calls
        // cannot race this initial handoff.
        let id = self.identity.workload_id.to_string();
        let record = self
            .state
            .store
            .get(Sandbox::object_type(), &id)
            .await
            .map_err(|_| conflict())?
            .ok_or_else(conflict)?;
        let sandbox = Sandbox::decode(record.payload.as_slice()).map_err(|_| conflict())?;
        if sandbox
            .metadata
            .as_ref()
            .and_then(|m| m.annotations.get(PENDING))
            .map(String::as_str)
            != Some("true")
        {
            return Ok(());
        }
        let (_, slot) = self.load().await?;
        if slot.phase != Phase::Bound {
            return Err(conflict());
        }
        self.check_profile(&slot)?;
        let pod = self
            .api::<Pod>()
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if pod.metadata.uid.as_deref() != slot.tickets["compute"].uid.as_deref() {
            return Err(conflict());
        }
        let driver =
            crate::compute::driver_sandbox_from_public(&sandbox, "kubernetes").map_err(|s| *s)?;
        let ordinary = self
            .driver
            .render_sandbox(&driver)
            .await
            .map_err(|_| conflict())?;
        let mut cr = self
            .sandbox_api(&slot.api_version)
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if cr.metadata.uid.as_deref() != slot.tickets["sandbox"].uid.as_deref() {
            return Err(conflict());
        }
        cr.data["spec"]["podTemplate"] = ordinary.data["spec"]["podTemplate"].clone();
        self.sandbox_api(&slot.api_version)
            .replace(&self.name, &PostParams::default(), &cr)
            .await
            .map_err(backend_error)?;
        self.state
            .store
            .update_message_cas::<Sandbox, _>(&id, record.resource_version, |sandbox| {
                if let Some(meta) = sandbox.metadata.as_mut() {
                    meta.annotations.remove(PENDING);
                }
            })
            .await
            .map_err(|_| Status::aborted("bound sandbox metadata changed; retry"))?;
        Ok(())
    }
    async fn stamp(&self, kind: &str) -> Result<(), Status> {
        let (_, slot) = self.load().await?;
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        let allocation = slot.allocation.as_ref().ok_or_else(conflict)?;
        let object = self.object(kind, &slot).await?.ok_or_else(conflict)?;
        if object["metadata"]["uid"].as_str()
            != slot.tickets.get(kind).and_then(|t| t.uid.as_deref())
        {
            return Err(conflict());
        }
        let meta: kube::core::ObjectMeta =
            serde_json::from_value(object["metadata"].clone()).map_err(|_| conflict())?;
        let stamped = meta
            .labels
            .as_ref()
            .is_some_and(|l| l.contains_key(ALLOCATION));
        self.check_labels(&meta, if stamped { Some(allocation) } else { None })?;
        // Preserve newer Kubernetes fields (notably image volumes) that the
        // typed client's older Pod schema cannot round-trip.
        let patch = json!({"metadata":{"uid":meta.uid,"resourceVersion":meta.resource_version,
            "labels":{(ALLOCATION):allocation["id"],(OWNER):allocation["ownershipMarker"]},
            "annotations":{(openshell_core::driver_utils::ANNOTATION_BOUND_WORKSPACE):allocation["workspaceName"]}}});
        match kind {
            "compute" => {
                self.api::<Pod>()
                    .patch(&self.name, &PatchParams::default(), &Patch::Merge(&patch))
                    .await
                    .map_err(backend_error)?;
            }
            "storage" => {
                self.api::<PersistentVolumeClaim>()
                    .patch(
                        slot.storage["claimName"].as_str().ok_or_else(conflict)?,
                        &PatchParams::default(),
                        &Patch::Merge(&patch),
                    )
                    .await
                    .map_err(backend_error)?;
            }
            _ => return Err(conflict()),
        }
        Ok(())
    }
    async fn grant(&self, kind: &str, grant: &Value) -> Result<(), Status> {
        if self.identity.schema_version == 2 {
            return match kind {
                "init" => Box::pin(private_grant::deliver(self, grant)).await,
                _ => Err(Status::unimplemented(
                    "native assistant sidecar release is not supported",
                )),
            };
        }
        let (cm, slot) = self.load().await?;
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        let mut labels = self.labels();
        // Grant resources remain platform-owned. Tenant markers are on the
        // actual compute/storage and ordinary native records, not these secrets.
        labels.insert(GRANT.into(), kind.into());
        self.create_once(
            kind,
            json!({"apiVersion":"v1","kind":"Secret","metadata":{
            "name":format!("{}-{kind}",self.name),"namespace":self.config.namespace,"labels":labels,
            "ownerReferences":[self.owner(&cm)?]},"immutable":true,
            "stringData":{"grant.json":serde_json::to_string(grant).map_err(|_|conflict())?}}),
        )
        .await?;
        let mut pod = self
            .api::<Pod>()
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if pod.metadata.uid.as_deref()
            != slot
                .tickets
                .get("compute")
                .and_then(|ticket| ticket.uid.as_deref())
        {
            return Err(conflict());
        }
        // Trigger projected-secret refresh without changing container environment
        // or waiting for kubelet's periodic volume reconciliation.
        let publication = format!(
            "{kind}:{}",
            slot.grant_hash.as_deref().ok_or_else(conflict)?
        );
        let annotations = pod.metadata.annotations.get_or_insert_with(BTreeMap::new);
        if annotations.get(GRANT) != Some(&publication) {
            annotations.insert(GRANT.into(), publication);
            let patch = json!({"metadata":{"uid":pod.metadata.uid,"resourceVersion":pod.metadata.resource_version,
                "annotations":{(GRANT):annotations[GRANT]}}});
            self.api::<Pod>()
                .patch(&self.name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
                .map_err(backend_error)?;
        }
        Ok(())
    }
    async fn adopt(&self, sandbox: &Sandbox) -> Result<(), Status> {
        let (_, slot) = self.load().await?;
        if slot.phase != Phase::Binding || !slot.initialized || !slot.tenant_configured {
            return Err(conflict());
        }
        let driver =
            crate::compute::driver_sandbox_from_public(sandbox, "kubernetes").map_err(|s| *s)?;
        let ordinary = self.driver.render_sandbox(&driver).await.map_err(|_| {
            Status::failed_precondition("ordinary retained sandbox rendering failed")
        })?;
        let mut cr = self
            .sandbox_api(&slot.api_version)
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if cr.metadata.uid.as_deref() != slot.tickets["sandbox"].uid.as_deref() {
            return Err(conflict());
        }
        // Keep the held, original-Pod-bound startup template until publication.
        // If the pod disappears mid-bind, a controller-created replacement cannot
        // consume the original UID-bound grants and is never reported as warm.
        cr.metadata.labels = ordinary.metadata.labels;
        cr.metadata.annotations = ordinary.metadata.annotations;
        cr.metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert("agents.x-k8s.io/pod-name".into(), self.name.clone());
        if slot.api_version == "v1beta1" {
            cr.data["spec"]["operatingMode"] = json!("Running");
        } else {
            cr.data["spec"]["replicas"] = json!(1);
        }
        let cr = self
            .sandbox_api(&slot.api_version)
            .replace(&self.name, &PostParams::default(), &cr)
            .await
            .map_err(backend_error)?;
        let mut pod = self
            .api::<Pod>()
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if pod.metadata.uid.as_deref() != slot.tickets["compute"].uid.as_deref() {
            return Err(conflict());
        }
        pod.metadata.owner_references=Some(serde_json::from_value(json!([{"apiVersion":format!("agents.x-k8s.io/{}",slot.api_version),
            "kind":"Sandbox","name":self.name,"uid":cr.metadata.uid,"controller":true,"blockOwnerDeletion":true}])).map_err(|_|conflict())?);
        let patch = json!({"metadata":{"uid":pod.metadata.uid,"resourceVersion":pod.metadata.resource_version,
            "ownerReferences":pod.metadata.owner_references}});
        self.api::<Pod>()
            .patch(&self.name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(backend_error)?;
        Ok(())
    }
    async fn result(&self, slot: &Slot) -> Result<Value, Status> {
        use crate::policy_store::PolicyStoreExt;
        let allocation = slot.allocation.as_ref().ok_or_else(conflict)?;
        let id = self.identity.workload_id.to_string();
        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&id)
            .await
            .map_err(|_| conflict())?
            .ok_or_else(conflict)?;
        let current = sandbox
            .metadata
            .as_ref()
            .and_then(|m| m.annotations.get("globster.dev/spec-hash"))
            .map(String::as_str)
            == allocation["fingerprint"].as_str();
        let latest = self
            .state
            .store
            .get_latest_policy(&id)
            .await
            .map_err(|_| conflict())?;
        let actual_policy = super::super::policy::current_base_policy_for_sandbox(
            self.state.store.as_ref(),
            &sandbox,
        )
        .await?;
        let policy_matches = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.policy.as_ref())
            .is_some_and(|expected| expected.network_policies == actual_policy.network_policies);
        let policy_loaded = policy_matches
            && latest
                .as_ref()
                .is_some_and(|policy| policy.status == "loaded");
        let connected = self.state.supervisor_sessions.has_session(&id);
        let bindings_ready = tenant::bindings_ready(self, slot).await?;
        let converged = current && policy_loaded && connected && bindings_ready;
        let components:Vec<_>=[("compute","compute"),("policy","policy"),("secret-bindings","secretBindings")].iter().map(|(component,key)|json!({
            "component":component,"action":"create","state":if converged {"converged"}else{"pending"},
            "desiredFingerprint":allocation["fingerprints"][*key],"observedFingerprint":if converged {allocation["fingerprints"][*key].clone()}else{Value::Null}
        })).collect();
        let healthy = if converged {
            self.runtime_healthy().await
        } else {
            false
        };
        let pod = self
            .api::<Pod>()
            .get(&self.name)
            .await
            .map_err(backend_error)?;
        if pod.metadata.uid.as_deref() != slot.tickets["compute"].uid.as_deref() {
            return Err(conflict());
        }
        let mut status = json!({"organizationId":allocation["organizationId"],
            "state":if healthy {"ready"}else{"starting"},"nativeSupervisorConnected":connected,
            "nativePolicyLoaded":policy_loaded,"runtimeHealthVerified":healthy});
        if healthy {
            status["runtimeEndpoint"] = json!(format!(
                "/v1/organizations/{}/workloads/{}/runtime",
                allocation["organizationId"].as_str().ok_or_else(conflict)?,
                self.identity.workload_id
            ));
        }
        Ok(
            json!({"schemaVersion":1,"desiredRevision":allocation["desiredRevision"],
            "observedRevision":if converged {allocation["desiredRevision"].clone()}else{Value::Null},
            "converged":converged,"ready":healthy,"computeReplaced":false,"processRefreshRequired":false,
            "components":components,"status":status}),
        )
    }
    async fn runtime_healthy(&self) -> bool {
        use futures::StreamExt;
        use openshell_core::proto::{ExecSandboxRequest, ExposeServiceRequest, exec_sandbox_event};
        let check = async {
            // Reuse ordinary authenticated SSH/exec and the agent's actual boot
            // probe inside its namespace; PodReady alone is not workload readiness.
            let request=ExecSandboxRequest{sandbox_id:self.identity.workload_id.to_string(),
                command:vec!["/app/.venv/bin/python".into(),"-I".into(),"-c".into(),
                    "import json,urllib.request,sys; r=urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:9000/health/ready',timeout=3); sys.exit(0 if r.status==200 and json.loads(r.read(4096))=={'status':'ready'} else 1)".into()],
                environment:HashMap::from_iter(["LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","BASH_ENV","ENV","GCONV_PATH"]
                    .map(|key|(key.into(),String::new()))),
                timeout_seconds:5,..Default::default()};
            let response = super::super::sandbox::handle_exec_sandbox(
                self.state,
                tenant::authed(self.principal, request),
            )
            .await
            .ok()?;
            let mut stream = response.into_inner();
            let mut success = false;
            while let Some(event) = stream.next().await {
                if let Some(exec_sandbox_event::Payload::Exit(exit)) = event.ok()?.payload {
                    success = exit.exit_code == 0;
                    break;
                }
            }
            if !success {
                return None;
            }
            let (_, slot) = self.load().await.ok()?;
            let allocation = slot.allocation.as_ref()?;
            let request = ExposeServiceRequest {
                sandbox: tenant::runtime_name(self.identity.workload_id),
                service: "globster-runtime".into(),
                target_port: 9000,
                domain: false,
                workspace: allocation["workspaceName"].as_str()?.into(),
            };
            super::super::service::handle_expose_service(
                self.state,
                tenant::authed(self.principal, request),
            )
            .await
            .ok()?;
            Some(())
        };
        tokio::time::timeout(Duration::from_secs(10), check)
            .await
            .ok()
            .flatten()
            .is_some()
    }
    async fn retire(&self, input: &Value) -> Result<(), Status> {
        if let Some(receipt) = input.get("resourceReceipt").filter(|v| !v.is_null()) {
            let (_, slot) = self.load().await?;
            if Self::receipt(&slot)? != *receipt {
                return Err(conflict());
            }
        }
        let reservation = self.reserve(input, true).await?;
        if !reservation.fence.issued {
            return Ok(());
        }
        if reservation.fence.rejected {
            if self
                .api::<ConfigMap>()
                .get_opt(&self.name)
                .await
                .map_err(backend_error)?
                .is_some()
            {
                return Err(conflict());
            }
            return Ok(());
        }
        // The original authority CREATE can itself be indeterminate.
        self.ensure_fence().await?;
        let (cm, mut slot) = self.load().await?;
        if matches!(slot.phase, Phase::Binding | Phase::Bound) {
            return Err(conflict());
        }
        if let Some(receipt) = input.get("resourceReceipt").filter(|v| !v.is_null())
            && Self::receipt(&slot)? != *receipt
        {
            return Err(conflict());
        }
        if slot.phase == Phase::Retired {
            return Ok(());
        }
        slot.phase = Phase::Retiring;
        self.save(cm, &slot).await?;
        let (_, slot) = self.load().await?;
        for kind in ["sandbox", "compute", "storage"] {
            if slot
                .tickets
                .get(kind)
                .is_some_and(|t| t.issued && t.uid.is_none() && !t.rejected)
            {
                self.settle(kind, self.object(kind, &slot).await?).await?;
            }
        }
        // Remove the controller before its pod: it must never recreate compute
        // after an absence check. A settled one-shot ticket forbids native replay.
        let sandbox_absent = self.delete_exact("sandbox").await?;
        let pod_absent = self.delete_exact("compute").await?;
        if !sandbox_absent || !pod_absent {
            return Ok(());
        }
        if !self.delete_exact("storage").await? {
            return Ok(());
        }
        let (cm, mut slot) = self.load().await?;
        if slot.phase != Phase::Retiring {
            return Err(conflict());
        }
        slot.phase = Phase::Retired;
        self.save(cm, &slot).await
    }
    async fn delete_exact(&self, kind: &str) -> Result<bool, Status> {
        let (_, slot) = self.load().await?;
        if slot.phase != Phase::Retiring {
            return Err(conflict());
        }
        let Some(object) = self.object(kind, &slot).await? else {
            return Ok(true);
        };
        let ticket = slot.tickets.get(kind).ok_or_else(conflict)?;
        if object["metadata"]["uid"].as_str() != ticket.uid.as_deref() {
            return Err(conflict());
        }
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: ticket.uid.clone(),
                resource_version: object["metadata"]["resourceVersion"]
                    .as_str()
                    .map(str::to_owned),
            }),
            ..Default::default()
        };
        let result = match kind {
            "sandbox" => self
                .sandbox_api(&slot.api_version)
                .delete(&self.name, &params)
                .await
                .map(|_| ()),
            "compute" => self
                .api::<Pod>()
                .delete(&self.name, &params)
                .await
                .map(|_| ()),
            "storage" => self
                .api::<PersistentVolumeClaim>()
                .delete(
                    slot.storage["claimName"].as_str().ok_or_else(conflict)?,
                    &params,
                )
                .await
                .map(|_| ()),
            _ => return Err(conflict()),
        };
        match result {
            Ok(()) => {}
            Err(kube::Error::Api(a)) if a.code == 404 => {}
            Err(e) => return Err(backend_error(e)),
        }
        Ok(self.object(kind, &slot).await?.is_none())
    }
    async fn observe(&self) -> Result<Value, Status> {
        let (reservation, _) = self.reservation().await?;
        if reservation.retire_requested && (!reservation.fence.issued || reservation.fence.rejected)
        {
            if self
                .api::<ConfigMap>()
                .get_opt(&self.name)
                .await
                .map_err(backend_error)?
                .is_some()
            {
                return Err(conflict());
            }
            return Ok(self.evidence_without_resources(&reservation, "retired"));
        }
        if !reservation.fence.issued {
            return Ok(self.evidence_without_resources(&reservation, "preparing"));
        }
        self.ensure_fence().await?;
        let (cm, mut slot) = self.load().await?;
        for kind in ["sandbox", "storage", "compute", "init", "launch"] {
            if slot
                .tickets
                .get(kind)
                .is_some_and(|t| t.issued && t.uid.is_none() && !t.rejected)
            {
                self.settle(kind, self.object(kind, &slot).await?).await?;
            }
        }
        if slot.phase == Phase::Preparing && self.held_running().await? {
            slot.phase = Phase::Ready;
            self.save(cm, &slot).await?;
        }
        let (_, slot) = self.load().await?;
        if slot.phase == Phase::Ready && !self.held_running().await? {
            let (cm, mut current) = self.load().await?;
            if current.phase == Phase::Ready {
                // Permanently fence lost/expired readiness, while retaining
                // truthful receipts so the owner can invoke normal retirement.
                current.phase = Phase::Retiring;
                self.save(cm, &current).await?;
            }
        }
        let (_, slot) = self.load().await?;
        if !matches!(slot.phase, Phase::Retiring | Phase::Retired) {
            self.check_resources(&slot).await?;
        }
        if slot.phase == Phase::Retired && Self::receipt(&slot).is_err() {
            if self.object("compute", &slot).await?.is_some()
                || self.object("storage", &slot).await?.is_some()
            {
                return Err(conflict());
            }
            return Ok(self.evidence_without_resources(&reservation, "retired"));
        }
        if slot.phase == Phase::Binding {
            self.stamp("storage").await?;
            self.stamp("compute").await?;
            self.resume_binding().await?;
        }
        if slot.phase == Phase::Bound {
            self.finalize_bound().await?;
        }
        let (_, slot) = self.load().await?;
        let receipt = Self::receipt(&slot)?;
        let mut compute_absent = false;
        let mut storage_absent = false;
        if !matches!(slot.phase, Phase::Retiring | Phase::Retired) {
            let sandbox = self.object("sandbox", &slot).await?.ok_or_else(conflict)?;
            if sandbox["metadata"]["uid"] != receipt["sandboxUid"]
                || !sandbox["metadata"]["deletionTimestamp"].is_null()
            {
                return Err(conflict());
            }
        }
        for (kind, field) in [("compute", "computeUid"), ("storage", "storageUid")] {
            match self.object(kind, &slot).await? {
                Some(object) => {
                    if object["metadata"]["uid"] != receipt[field] {
                        return Err(conflict());
                    }
                    // During binding, stamping both resources is resumable.
                    if slot.phase != Phase::Binding {
                        self.check_labels(
                            &serde_json::from_value(object["metadata"].clone())
                                .map_err(|_| conflict())?,
                            slot.allocation.as_ref(),
                        )?;
                    }
                }
                None => {
                    if kind == "compute" {
                        compute_absent = true;
                    } else {
                        storage_absent = true;
                    }
                }
            }
        }
        if !matches!(slot.phase, Phase::Retiring | Phase::Retired)
            && (compute_absent || storage_absent)
        {
            return Err(conflict());
        }
        let observation = json!({"schemaVersion":1,"slotId":slot.identity.slot_id,"workloadId":slot.identity.workload_id,
            "generation":slot.identity.generation,"preparation":slot.preparation,"compatibilityKey":compatibility(&slot.preparation),
            "state":match slot.phase {Phase::Preparing=>"preparing",Phase::Ready=>"idle_ready",Phase::Binding=>"binding",
                Phase::Bound=>"bound",Phase::Retiring=>"retiring",Phase::Retired=>"retired"},
            "resourceReceipt":receipt,"launchReleased":slot.launch_released,
            "allocation":slot.allocation.as_ref().map(|a|json!({"id":a["id"],"organizationId":a["organizationId"],"desiredRevision":a["desiredRevision"],"fingerprint":a["fingerprint"]})),
            "result": if slot.phase==Phase::Bound {self.result(&slot).await?} else {Value::Null}});
        Ok(
            json!({"schemaVersion":1,"observation":observation,"resources":{"namespace":self.config.namespace,
            "podName":self.name,"claimName":slot.storage["claimName"],"receipt":receipt},
            "fenced":true,"tenantConfigured":slot.tenant_configured,"singleWriterInitialized":slot.initialized,
            "computeAbsent":compute_absent,"storageAbsent":storage_absent}),
        )
    }
    fn evidence_without_resources(&self, reservation: &Reservation, phase: &str) -> Value {
        json!({"schemaVersion":1,"observation":{"schemaVersion":1,"slotId":self.identity.slot_id,
            "workloadId":self.identity.workload_id,"generation":self.identity.generation,
            "preparation":reservation.preparation,"compatibilityKey":compatibility(&reservation.preparation),
            "state":phase,"resourceReceipt":null,"launchReleased":false,"allocation":null,"result":null},
            "resources":null,"fenced":true,"tenantConfigured":false,"singleWriterInitialized":false,"computeAbsent":true,"storageAbsent":true})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assistant_v2_is_unsupported_before_inspecting_identity_or_tenant_input() {
        let error = identity(&json!({"schemaVersion":2,
            "request":{"credentialWrites":[{"value":"never-echo-this"}]}}))
        .err()
        .unwrap();
        assert_eq!(error.code(), tonic::Code::Unimplemented);
        assert!(!error.message().contains("never-echo-this"));
    }

    #[test]
    fn settled_assistant_v2_preparation_is_not_a_legacy_recipe() {
        // Gateway #250, bec528d52f978204f4acedd78a811823dae8e1a8:
        // docs/prewarm-native-contract.md and test/prewarm-slots.test.ts.
        let preparation = json!({
            "schemaVersion":2,"runtime":"assistant",
            "providerArtifact":format!("registry.example/openshell@sha256:{}","a".repeat(64)),
            "placementKey":"test/canadacentral/standard",
            "image":format!("registry.example/assistant@sha256:{}","b".repeat(64)),
            "serviceVersion":"1.2.3",
            "resources":{"cpu":"250m","memory":"512Mi"},"workspace":{"capacity":"1Gi"}
        });
        let mut digest = Sha256::new();
        digest.update(b"globster/prewarm-preparation/v2\0");
        digest.update(canonical(&preparation));
        assert_eq!(
            format!("sha256:{:x}", digest.finalize()),
            "sha256:a2e775a7361d99388a7b6a3ec2684adc4a70ba43875f0d4bd100aa5fc0910cdf"
        );
        assert!(preparation_shape(&preparation).is_err());
        let input = json!({"schemaVersion":2,"slotId":"11111111-1111-4111-8111-111111111111",
            "workloadId":"22222222-2222-4222-8222-222222222222","generation":1,
            "preparation":preparation});
        assert_eq!(
            identity(&input).err().unwrap().code(),
            tonic::Code::Unimplemented
        );
    }

    #[test]
    fn retained_resource_checks_reject_replacements_and_terminating_resources() {
        let tickets = ["compute", "storage", "sandbox"].map(|kind| {
            (
                kind.to_owned(),
                Ticket {
                    issued: true,
                    uid: Some(format!("original-{kind}")),
                    rejected: false,
                },
            )
        });
        let tickets = BTreeMap::from(tickets);
        let original = ["compute", "storage", "sandbox"]
            .map(|kind| json!({"metadata":{"uid":format!("original-{kind}")}}));
        let check = |objects: &[Value; 3]| {
            retained_identities(
                &tickets,
                [
                    ("compute", &objects[0]),
                    ("storage", &objects[1]),
                    ("sandbox", &objects[2]),
                ],
            )
        };
        check(&original).unwrap();
        for index in 0..original.len() {
            let mut replaced = original.clone();
            replaced[index]["metadata"]["uid"] = json!("replacement");
            assert_eq!(
                check(&replaced).unwrap_err().code(),
                tonic::Code::FailedPrecondition
            );
            let mut terminating = original.clone();
            terminating[index]["metadata"]["deletionTimestamp"] = json!("2026-10-25T11:00:00Z");
            assert!(check(&terminating).is_err());
        }
    }

    #[test]
    fn prepared_profile_changes_are_not_in_place_compatibility() {
        let original = KubernetesComputeConfig::default();
        let expected = profile_hash(&original).unwrap();
        for value in [
            json!({"topology":"sidecar"}),
            json!({"supervisor_image":format!("registry.example/supervisor@sha256:{}","a".repeat(64))}),
            json!({"process_bootstrap":["/usr/local/bin/assistant-computer-bootstrap"]}),
            json!({"workspace_storage_class":"different-storage"}),
        ] {
            let config = serde_json::from_value::<KubernetesComputeConfig>(value).unwrap();
            assert_ne!(profile_hash(&config).unwrap(), expected);
        }
        let mut disabled = serde_json::to_value(&original).unwrap();
        disabled["prewarm"] = json!({"enabled":false,"provider_artifact":"fixture",
            "placement_key":"fixture","image":"fixture","recipe_id":"fixture",
            "recipe_digest":"fixture","recipe_image":"fixture"});
        let disabled = serde_json::from_value::<KubernetesComputeConfig>(disabled).unwrap();
        assert_eq!(profile_hash(&disabled).unwrap(), expected);
    }

    #[test]
    fn unsupported_sidecar_identity_and_spiffe_profiles_fail_closed() {
        let preparation = json!({"preparation":{
            "schemaVersion":1,"providerArtifact":"not-an-artifact-approval","placementKey":"local-fixture",
            "image":format!("registry.example/agent@sha256:{}","a".repeat(64)),
            "recipe":{"id":"fixture","digest":format!("sha256:{}","b".repeat(64)),
                "image":format!("registry.example/recipe@sha256:{}","c".repeat(64))},
            "resources":{"cpu":"1000m","memory":"512Mi"},"workspace":{"capacity":"1Gi"}}});
        let mut profile = json!({
            "sandbox_uid":1000,"sandbox_gid":1000,
            "supervisor_image":format!("registry.example/supervisor@sha256:{}","d".repeat(64)),
            "prewarm":{"enabled":true,"provider_artifact":"not-an-artifact-approval",
                "placement_key":"local-fixture","image":preparation["preparation"]["image"],
                "recipe_id":"fixture","recipe_digest":preparation["preparation"]["recipe"]["digest"],
                "recipe_image":preparation["preparation"]["recipe"]["image"]}
        });
        let config = serde_json::from_value::<KubernetesComputeConfig>(profile.clone()).unwrap();
        validate_preparation(&config, &preparation).unwrap();
        for (field, value) in [
            ("topology", json!("sidecar")),
            ("workspace_mode", json!("managed")),
            ("sandbox_uid", json!(2000)),
            ("sandbox_gid", json!(2000)),
            ("sandbox_uid", Value::Null),
            ("sandbox_gid", Value::Null),
            (
                "provider_spiffe_workload_api_socket_path",
                json!("/spiffe/agent.sock"),
            ),
        ] {
            let previous = profile[field].clone();
            profile[field] = value;
            let config =
                serde_json::from_value::<KubernetesComputeConfig>(profile.clone()).unwrap();
            assert_eq!(
                validate_preparation(&config, &preparation)
                    .unwrap_err()
                    .code(),
                tonic::Code::Unimplemented
            );
            if previous.is_null() {
                profile.as_object_mut().unwrap().remove(field);
            } else {
                profile[field] = previous;
            }
        }
    }

    #[test]
    fn canonical_matches_ecmascript_numbers_and_utf16_keys() {
        assert_eq!(
            canonical(&json!({"z":1.0,"a":[1e21,1e-7,1e-6,-0.0]})),
            r#"{"a":[1e+21,1e-7,0.000001,0],"z":1}"#
        );
        assert_eq!(
            canonical(&json!({"\u{10000}":1,"\u{e000}":2})),
            "{\"\u{10000}\":1,\"\u{e000}\":2}"
        );
    }
    #[test]
    fn issued_or_rejected_creations_are_never_replayed() {
        assert!(Ticket::default().may_issue().unwrap());
        for uid in [None, Some("original-resource-uid".into())] {
            assert!(
                !Ticket {
                    issued: true,
                    uid,
                    rejected: false
                }
                .may_issue()
                .unwrap()
            );
        }
        assert!(
            Ticket {
                issued: true,
                uid: None,
                rejected: true
            }
            .may_issue()
            .is_err()
        );
    }
}
