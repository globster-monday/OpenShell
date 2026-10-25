// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translation into ordinary `OpenShell` workspace/provider/policy contracts.
//! Credentials go through the normal credential driver, never tenant pod env.

use super::{
    ALLOCATION, BTreeMap, Backend, Digest, HashMap, MANAGED, MANAGED_VALUE, OWNER, PENDING, Phase,
    Principal, Sandbox, Sha256, Slot, Status, Uuid, Value, canonical, conflict, json, quarantine,
};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateWorkspaceRequest, Provider, Workspace,
};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use tonic::Request;

fn proto<T: Message + Default>(name: &str, value: Value) -> Result<T, Status> {
    let pool =
        DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET).map_err(|_| conflict())?;
    let descriptor = pool.get_message_by_name(name).ok_or_else(conflict)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| conflict())?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let message = DynamicMessage::deserialize(descriptor, &mut deserializer)
        .map_err(|_| Status::invalid_argument("invalid ordinary prewarm configuration"))?;
    T::decode(message.encode_to_vec().as_slice()).map_err(|_| conflict())
}

pub(super) fn authed<T>(principal: &Principal, value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.extensions_mut().insert(principal.clone());
    request
}

pub(super) fn compact(bytes: &[u8]) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in bytes.iter().take(10) {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(alphabet[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    result
}

pub(super) fn runtime_name(id: Uuid) -> String {
    format!("gs-{}", compact(&Sha256::digest(id.to_string())))
}

fn fingerprint(component: &str, value: &Value) -> String {
    let mut digest = Sha256::new();
    digest.update(format!("globster/agent-runtime/{component}/v1\0"));
    digest.update(canonical(value));
    format!("sha256:{:x}", digest.finalize())
}

fn normalized_policy(value: &Value) -> Result<Value, Status> {
    if value["schemaVersion"] != 1
        || value["defaultAction"] != "deny"
        || value["revision"].as_u64().is_none()
    {
        return Err(conflict());
    }
    let mut rules = value["rules"].as_array().cloned().ok_or_else(conflict)?;
    for rule in &mut rules {
        if let Some(host) = rule["host"].as_str() {
            rule["host"] = json!(host.trim().trim_end_matches('.').to_ascii_lowercase());
        }
        for field in ["ports", "methods", "paths", "executables"] {
            if let Some(array) = rule.get_mut(field).and_then(Value::as_array_mut) {
                array.sort_by(|a, b| match (a.as_u64(), b.as_u64()) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    _ => a
                        .as_str()
                        .unwrap_or_default()
                        .encode_utf16()
                        .cmp(b.as_str().unwrap_or_default().encode_utf16()),
                });
            }
        }
    }
    rules.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or_default()
            .encode_utf16()
            .cmp(b["id"].as_str().unwrap_or_default().encode_utf16())
    });
    if rules.windows(2).any(|r| r[0]["id"] == r[1]["id"]) {
        return Err(conflict());
    }
    Ok(json!({"schemaVersion":1,"revision":value["revision"],"defaultAction":"deny","rules":rules}))
}

fn translated_rule(rule: &Value) -> Result<Value, Status> {
    let (protocol, tls) = match rule["protocol"].as_str().ok_or_else(conflict)? {
        "tcp" => ("", "passthrough"),
        "http" => ("rest", "none"),
        "https" => ("rest", "terminate"),
        "websocket" => ("websocket", "none"),
        "websocket-secure" => ("websocket", "terminate"),
        "graphql" => ("graphql", "terminate"),
        "json-rpc" => ("json-rpc", "terminate"),
        "mcp" => ("mcp", "terminate"),
        _ => return Err(conflict()),
    };
    let mut l7 = Vec::new();
    if let Some(methods) = rule.get("methods") {
        for method in methods.as_array().ok_or_else(conflict)? {
            for path in rule["paths"].as_array().ok_or_else(conflict)? {
                l7.push(json!({"allow":{"method":method,"path":path}}));
            }
        }
    }
    let paths = if rule.get("methods").is_none() {
        rule.get("paths")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![json!("")])
    } else {
        vec![json!("")]
    };
    let endpoints:Vec<_>=paths.into_iter().map(|path|json!({"host":rule["host"],"port":0,"ports":rule["ports"],
        "protocol":protocol,"tls":tls,"enforcement":"enforce","access":"","rules":l7,"allowedIps":[],"path":path})).collect();
    let binaries: Vec<_> = rule["executables"]
        .as_array()
        .ok_or_else(conflict)?
        .iter()
        .map(|path| json!({"path":path}))
        .collect();
    Ok(json!({"name":rule["id"],"endpoints":endpoints,"binaries":binaries}))
}

fn ordered(value: &Value, keys: &[&str]) -> String {
    format!(
        "{{{}}}",
        keys.iter()
            .filter(|key| value.get(**key).is_some())
            .map(|key| format!("{}:{}", canonical(&json!(key)), canonical(&value[*key])))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn effective_policy(input: &Value) -> Result<Value, Status> {
    let desired = &input["request"]["desired"]["policy"];
    let mut rules = normalized_policy(desired)?["rules"]
        .as_array()
        .cloned()
        .ok_or_else(conflict)?;
    for (key, rule) in input["launch"]["networkPolicies"]
        .as_object()
        .ok_or_else(conflict)?
    {
        let id = key.strip_prefix("globster__").ok_or_else(conflict)?;
        if rules.iter().any(|r| r["id"] == id) {
            continue;
        }
        let endpoints = rule["endpoints"].as_array().ok_or_else(conflict)?;
        let first = endpoints.first().ok_or_else(conflict)?;
        let protocol = match (first["protocol"].as_str(), first["tls"].as_str()) {
            (Some(""), _) => "tcp",
            (Some("rest"), Some("none")) => "http",
            (Some("rest"), _) => "https",
            (Some("websocket"), Some("none")) => "websocket",
            (Some("websocket"), _) => "websocket-secure",
            (Some("graphql"), _) => "graphql",
            (Some("json-rpc"), _) => "json-rpc",
            (Some("mcp"), _) => "mcp",
            _ => return Err(conflict()),
        };
        let mut methods = Vec::new();
        let mut paths = Vec::new();
        for endpoint in endpoints {
            if endpoint["host"] != first["host"]
                || endpoint["ports"] != first["ports"]
                || endpoint["protocol"] != first["protocol"]
                || endpoint["tls"] != first["tls"]
            {
                return Err(conflict());
            }
            if endpoint["path"].as_str().is_some_and(|p| !p.is_empty()) {
                paths.push(endpoint["path"].clone());
            }
            for l7 in endpoint["rules"].as_array().ok_or_else(conflict)? {
                methods.push(l7["allow"]["method"].clone());
                paths.push(l7["allow"]["path"].clone());
            }
        }
        methods.sort_by_key(canonical);
        methods.dedup();
        paths.sort_by_key(canonical);
        paths.dedup();
        let binaries: Vec<_> = rule["binaries"]
            .as_array()
            .ok_or_else(conflict)?
            .iter()
            .map(|b| b["path"].clone())
            .collect();
        let mut value = json!({"id":id,"host":first["host"],"ports":first["ports"],"protocol":protocol,"executables":binaries});
        if !methods.is_empty() {
            value["methods"] = json!(methods);
        }
        if !paths.is_empty() {
            value["paths"] = json!(paths);
        }
        if translated_rule(&value)? != *rule {
            return Err(conflict());
        }
        rules.push(value);
    }
    normalized_policy(
        &json!({"schemaVersion":1,"revision":desired["revision"],"defaultAction":"deny","rules":rules}),
    )
}

fn normal_metadata_hashes(input: &Value, workload: Uuid) -> Result<(String, String), Status> {
    let policy = effective_policy(input)?;
    let rules = policy["rules"]
        .as_array()
        .ok_or_else(conflict)?
        .iter()
        .map(|rule| {
            ordered(
                rule,
                &[
                    "id",
                    "host",
                    "ports",
                    "protocol",
                    "methods",
                    "paths",
                    "executables",
                ],
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let serialized = format!(
        "{{\"schemaVersion\":1,\"revision\":{},\"defaultAction\":\"deny\",\"rules\":[{}]}}",
        policy["revision"], rules
    );
    let effective = format!("sha256:{:x}", Sha256::digest(serialized));
    let org = input["organization"]["organizationId"]
        .as_str()
        .ok_or_else(conflict)?;
    let policy_hash = format!(
        "sha256:{:x}",
        Sha256::digest(format!(
            "globster/organization-workload-policy/v1\0{org}\0{workload}\0{effective}"
        ))
    );
    let mut bindings = input["request"]["desired"]["secretBindings"]
        .as_array()
        .cloned()
        .ok_or_else(conflict)?;
    bindings.sort_by_key(|b| b["id"].as_str().unwrap_or_default().to_owned());
    for binding in &mut bindings {
        binding["credentialNames"]
            .as_array_mut()
            .ok_or_else(conflict)?
            .sort_by_key(canonical);
    }
    let serialized = format!(
        "[{}]",
        bindings
            .iter()
            .map(|b| ordered(
                b,
                &[
                    "schemaVersion",
                    "id",
                    "profile",
                    "secretRef",
                    "credentialNames"
                ]
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let bindings_hash = format!("sha256:{:x}", Sha256::digest(serialized));
    Ok((
        policy_hash,
        format!(
            "sha256:{:x}",
            Sha256::digest(format!(
                "globster/organization-workload-secret-bindings/v1\0{org}\0{workload}\0{bindings_hash}"
            ))
        ),
    ))
}

pub(super) fn fingerprints(desired: &Value) -> Result<Value, Status> {
    let mut compute = json!({"powerState":desired["powerState"],"image":desired["image"],
        "workspace":desired["workspace"],"resources":desired["resources"]});
    for field in [
        "runtime",
        "recipe",
        "computeRestartGeneration",
        "initialConfiguration",
        "environment",
    ] {
        if let Some(value) = desired.get(field) {
            compute[field] = value.clone();
        }
    }
    let mut bindings = desired["secretBindings"]
        .as_array()
        .cloned()
        .ok_or_else(conflict)?;
    for binding in &mut bindings {
        // The consumer uses localeCompare here, unlike policy/canonical JSON.
        // Restrict to its portable DNS-label alphabet rather than claim a
        // different fingerprint for locale-sensitive identifiers.
        if !binding["id"].as_str().is_some_and(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        }) {
            return Err(Status::unimplemented(
                "native prewarm requires lower-case alphanumeric/hyphen secret-binding IDs",
            ));
        }
        binding["credentialNames"]
            .as_array_mut()
            .ok_or_else(conflict)?
            .sort_by_key(canonical);
    }
    bindings.sort_by_key(|b| b["id"].as_str().unwrap_or_default().to_owned());
    if bindings.windows(2).any(|b| b[0]["id"] == b[1]["id"]) {
        return Err(conflict());
    }
    let mut result = json!({"compute":fingerprint("compute",&compute),
        "policy":fingerprint("policy",&normalized_policy(&desired["policy"])?),
        "secretBindings":fingerprint("secret-bindings",&json!(bindings))});
    result["overall"] = json!(fingerprint("overall", &result));
    Ok(result)
}

fn organization(value: &Value) -> Result<(), Status> {
    let id = value["organizationId"].as_str().ok_or_else(conflict)?;
    if id.is_empty()
        || id.len() > 128
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
    {
        return Err(conflict());
    }
    let marker = Sha256::digest(format!("globster/organization-owner/v1\0{id}"));
    if value["ownershipMarker"] != format!("{marker:x}")[..32] {
        return Err(conflict());
    }
    let digest = Sha256::digest(format!("globster/workspace/v1\0{id}"));
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut name = String::from("gw-");
    let mut accumulator = 0u32;
    let mut bits = 0;
    for byte in digest.iter().take(10) {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            name.push(alphabet[((accumulator >> bits) & 31) as usize] as char);
        }
        accumulator &= (1 << bits) - 1;
    }
    if value["workspaceName"] != name {
        return Err(conflict());
    }
    Ok(())
}

pub(super) fn validate(backend: &Backend<'_>, slot: &Slot, input: &Value) -> Result<(), Status> {
    organization(&input["organization"])?;
    let allocation = input["allocationId"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(conflict)?;
    let desired = &input["request"]["desired"];
    if allocation.is_nil()
        || input["allocationId"] != allocation.to_string()
        || input["request"]["schemaVersion"] != 1
        || desired["schemaVersion"] != 1
        || desired["revision"]
            .as_u64()
            .is_none_or(|r| r == 0 || r > 9_007_199_254_740_991)
        || desired["image"] != slot.preparation["image"]
        || desired["recipe"] != slot.preparation["recipe"]
        || desired["resources"] != slot.preparation["resources"]
        || desired["workspace"] != slot.preparation["workspace"]
        || desired.get("computeRestartGeneration").is_some()
        || desired
            .get("runtime")
            .is_some_and(|runtime| runtime != "agent")
    {
        return Err(conflict());
    }
    if desired["powerState"] != "running" {
        return Err(Status::unimplemented(
            "initial native prewarm binding supports running workloads only",
        ));
    }
    if fingerprints(desired)? != desired["fingerprints"] {
        return Err(Status::invalid_argument(
            "prewarm desired fingerprints do not match the actual intent",
        ));
    }
    let launch = &input["launch"];
    let id = backend.identity.workload_id.to_string();
    if launch["command"]
        != json!([
            "/app/.venv/bin/python",
            "-m",
            "agent_harness",
            "serve",
            "--headless",
            "--host",
            "0.0.0.0",
            "--port",
            "9000"
        ])
        || launch["workspaceMountPath"] != "/workspace"
        || launch["persistenceMountPath"] != "/sandbox/persist"
        || launch["persistenceSubPath"] != format!("{id}/.globster-openshell-persist")
        || launch["platformPolicyRevision"].as_u64().is_none()
    {
        return Err(conflict());
    }
    let mut environment = desired
        .get("environment")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !environment.is_object() {
        return Err(conflict());
    }
    for (key, value) in [
        ("AGENT_DATA_DIR", "/workspace".to_owned()),
        ("AGENT_ID", id.clone()),
        (
            "GLOBSTER_ORGANIZATION_ID",
            input["organization"]["organizationId"]
                .as_str()
                .ok_or_else(conflict)?
                .into(),
        ),
        ("AGENT_STORAGE_ROOT", format!("/workspace/{id}/workspace")),
        (
            "AGENT_HOST_CREDENTIAL_REFERENCE_TEMPLATE",
            "openshell:resolve:env:{credential}".into(),
        ),
        ("HOME", "/workspace".into()),
    ] {
        environment[key] = json!(value);
    }
    if launch["environment"] != environment {
        return Err(conflict());
    }
    // Validate the full policy through the ordinary native policy machinery.
    // Requested rules cannot be silently removed by the platform translation.
    let supplied = launch["networkPolicies"].as_object().ok_or_else(conflict)?;
    let caller_policy = normalized_policy(&desired["policy"])?;
    for rule in caller_policy["rules"].as_array().ok_or_else(conflict)? {
        let id = rule["id"].as_str().ok_or_else(conflict)?;
        if supplied.get(&format!("globster__{id}")) != Some(&translated_rule(rule)?) {
            return Err(conflict());
        }
    }
    if supplied.keys().any(|key| {
        !key.starts_with("globster__platform-")
            && !desired["policy"]["rules"].as_array().is_some_and(|rules| {
                rules.iter().any(|rule| {
                    rule["id"]
                        .as_str()
                        .is_some_and(|id| key == &format!("globster__{id}"))
                })
            })
    }) {
        return Err(conflict());
    }
    effective_policy(input)?;
    Ok(())
}

pub(super) fn sandbox_request(
    backend: &Backend<'_>,
    input: &Value,
    resources: &Value,
    providers: Option<Vec<String>>,
) -> Result<CreateSandboxRequest, Status> {
    let bound = providers.is_some();
    let mut labels = backend.labels();
    let mut annotations = BTreeMap::<String, String>::new();
    let (command, environment, workspace) = if bound {
        labels.insert(
            OWNER.into(),
            input["organization"]["ownershipMarker"]
                .as_str()
                .ok_or_else(conflict)?
                .into(),
        );
        labels.insert(
            ALLOCATION.into(),
            input["allocationId"].as_str().ok_or_else(conflict)?.into(),
        );
        let desired = &input["request"]["desired"];
        let (policy_hash, bindings_hash) =
            normal_metadata_hashes(input, backend.identity.workload_id)?;
        for (key, value) in [
            (
                "globster.dev/desired-revision",
                desired["revision"].to_string(),
            ),
            (
                "globster.dev/spec-hash",
                desired["fingerprints"]["overall"]
                    .as_str()
                    .ok_or_else(conflict)?
                    .into(),
            ),
            (
                "globster.dev/idempotency-key",
                input["allocationId"].as_str().ok_or_else(conflict)?.into(),
            ),
            ("globster.dev/power-state", "running".into()),
            (
                "globster.dev/compute-fingerprint",
                desired["fingerprints"]["compute"]
                    .as_str()
                    .ok_or_else(conflict)?
                    .into(),
            ),
            (
                "globster.dev/policy-fingerprint",
                desired["fingerprints"]["policy"]
                    .as_str()
                    .ok_or_else(conflict)?
                    .into(),
            ),
            (
                "globster.dev/secret-bindings-fingerprint",
                desired["fingerprints"]["secretBindings"]
                    .as_str()
                    .ok_or_else(conflict)?
                    .into(),
            ),
            (
                "globster.dev/policy-revision",
                desired["policy"]["revision"].to_string(),
            ),
            (
                "globster.dev/platform-policy-revision",
                input["launch"]["platformPolicyRevision"].to_string(),
            ),
            ("globster.dev/policy-hash", policy_hash),
            ("globster.dev/secret-binding-hash", bindings_hash),
            ("globster.dev/secret-binding-revision", "1".into()),
            (
                "globster.dev/secret-binding-idempotency-key",
                input["allocationId"].as_str().ok_or_else(conflict)?.into(),
            ),
            (PENDING, "true".into()),
        ] {
            annotations.insert(key.into(), value);
        }
        let mut workload = json!({"revision":desired["revision"],"specHash":desired["fingerprints"]["overall"],
            "powerState":desired["powerState"],"image":desired["image"],"workspace":desired["workspace"],
            "policy":normalized_policy(&desired["policy"])?,"secretBindings":desired["secretBindings"],
            "fingerprints":desired["fingerprints"],"resources":desired["resources"]});
        for key in ["runtime", "environment"] {
            if let Some(v) = desired.get(key) {
                workload[key] = v.clone();
            }
        }
        let request = format!(
            "PUT\n/v1/organizations/{}/workloads/{}\n{}",
            input["organization"]["organizationId"]
                .as_str()
                .ok_or_else(conflict)?,
            backend.identity.workload_id,
            canonical(&workload)
        );
        annotations.insert(
            "globster.dev/request-fingerprint".into(),
            format!("sha256:{:x}", Sha256::digest(request)),
        );
        (
            input["launch"]["command"].clone(),
            input["launch"]["environment"].clone(),
            input["organization"]["workspaceName"]
                .as_str()
                .ok_or_else(conflict)?
                .to_owned(),
        )
    } else {
        (json!(["/bin/false"]), json!({}), "default".into())
    };
    proto(
        "openshell.v1.CreateSandboxRequest",
        json!({
            "name":runtime_name(backend.identity.workload_id),"workspace":workspace,
            "labels":labels,"annotations":annotations,"spec":{"command":command,"environment":environment,
                "providers":providers.unwrap_or_default(),
                "template":{"image": if bound {input["request"]["desired"]["image"].clone()} else {json!(backend.config.prewarm.as_ref().ok_or_else(conflict)?.image)},
                    "labels":labels,"resources":{"limits":resources},"driverConfig":{"kubernetes":{
                        "volumes":[{"name":"globster-workspace","persistent_volume_claim":{"claim_name":backend.storage()["claimName"],"read_only":false}}],
                        "containers":{"agent":{"volume_mounts":[{"name":"globster-workspace","mount_path":"/workspace","read_only":false},
                            {"name":"globster-workspace","mount_path":"/sandbox/persist","sub_path":format!("{}/.globster-openshell-persist",backend.identity.workload_id),"read_only":false}]}}
                    }}},
                "policy":{"version":1,"filesystem":{"includeWorkdir":true,"readOnly":["/usr","/lib","/proc","/dev/urandom","/app","/etc","/var/log"],
                    "readWrite":["/sandbox","/workspace","/tmp","/dev/null"]},"landlock":{"compatibility":"best_effort"},
                    "process":{"runAsUser":"sandbox","runAsGroup":"sandbox"},"networkPolicies":if bound {input["launch"]["networkPolicies"].clone()} else {json!({})}}
            }
        }),
    )
}

pub(super) async fn configure(
    backend: &Backend<'_>,
    principal: &Principal,
    input: &Value,
) -> Result<Sandbox, Status> {
    let workspace = input["organization"]["workspaceName"]
        .as_str()
        .ok_or_else(conflict)?;
    let owner = input["organization"]["ownershipMarker"]
        .as_str()
        .ok_or_else(conflict)?;
    let existing = backend
        .state
        .store
        .get_message_by_name::<Workspace>("", workspace)
        .await
        .map_err(|_| conflict())?;
    if existing.is_none() {
        let request = CreateWorkspaceRequest {
            name: workspace.into(),
            labels: HashMap::from([
                (MANAGED.into(), MANAGED_VALUE.into()),
                (OWNER.into(), owner.into()),
            ]),
        };
        match super::super::super::workspace::handle_create_workspace(
            backend.state,
            authed(principal, request),
        )
        .await
        {
            Ok(_) => {}
            Err(e) if e.code() == tonic::Code::AlreadyExists => {}
            Err(_) => {
                return Err(Status::failed_precondition(
                    "ordinary organization workspace creation failed",
                ));
            }
        }
    }
    let existing = backend
        .state
        .store
        .get_message_by_name::<Workspace>("", workspace)
        .await
        .map_err(|_| conflict())?
        .ok_or_else(conflict)?;
    let meta = existing.metadata.ok_or_else(conflict)?;
    if meta.labels.get(OWNER).map(String::as_str) != Some(owner)
        || meta.labels.get(MANAGED).map(String::as_str) != Some(MANAGED_VALUE)
        || meta.deletion_timestamp_ms != 0
    {
        return Err(conflict());
    }
    let bindings = input["request"]["desired"]["secretBindings"]
        .as_array()
        .ok_or_else(conflict)?;
    let writes = input["request"]["credentialWrites"]
        .as_array()
        .ok_or_else(conflict)?;
    if writes.len() > bindings.len() {
        return Err(conflict());
    }
    let mut names = Vec::new();
    for binding in bindings {
        let id = binding["id"].as_str().ok_or_else(conflict)?;
        let name = format!("{}-sb-{id}", runtime_name(backend.identity.workload_id));
        let ticket_name = format!("provider:{id}");
        let (cm, mut slot) = backend.load().await?;
        let existing = backend
            .state
            .store
            .get_message_by_name::<Provider>(workspace, &name)
            .await
            .map_err(|_| conflict())?;
        if let Some(provider) = existing {
            let meta = provider.metadata.as_ref().ok_or_else(conflict)?;
            let resource_meta = kube::core::ObjectMeta {
                labels: Some(
                    meta.labels
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
                ..Default::default()
            };
            backend.check_labels(&resource_meta, slot.allocation.as_ref())?;
            if meta.labels.get(ALLOCATION).map(String::as_str) != input["allocationId"].as_str()
                || meta.labels.get(OWNER).map(String::as_str) != Some(owner)
                || provider.r#type != binding["profile"]
                || provider
                    .config
                    .get("globster.dev/secret-ref")
                    .map(String::as_str)
                    != binding["secretRef"].as_str()
            {
                return Err(conflict());
            }
            let ticket = slot.tickets.get_mut(&ticket_name).ok_or_else(conflict)?;
            if ticket.uid.as_ref().is_some_and(|uid| uid != &meta.id) {
                return Err(conflict());
            }
            if ticket.uid.is_none() {
                ticket.uid = Some(meta.id.clone());
                backend.save(cm, &slot).await?;
            }
            names.push(name);
            continue;
        }
        if slot.phase != Phase::Binding {
            return Err(conflict());
        }
        let ticket = slot.tickets.entry(ticket_name.clone()).or_default();
        if ticket.issued {
            return Err(quarantine());
        }
        let matching: Vec<_> = writes
            .iter()
            .filter(|w| w["binding"]["id"] == binding["id"])
            .collect();
        if matching.len() != 1 || matching[0]["binding"] != *binding {
            return Err(Status::failed_precondition(
                "prewarm provider requires its exact normal credential write",
            ));
        }
        let credentials = matching[0]["credentials"].as_array().ok_or_else(conflict)?;
        let mut values = serde_json::Map::new();
        let mut expires = serde_json::Map::new();
        for credential in credentials {
            let key = credential["name"].as_str().ok_or_else(conflict)?;
            if values
                .insert(key.into(), credential["value"].clone())
                .is_some()
            {
                return Err(conflict());
            }
            let expiry = match credential.get("expiresAt") {
                None => 0i64,
                Some(value) => {
                    let timestamp: prost_types::Timestamp = value
                        .as_str()
                        .ok_or_else(conflict)?
                        .parse()
                        .map_err(|_| conflict())?;
                    timestamp
                        .seconds
                        .checked_mul(1000)
                        .and_then(|s| s.checked_add(i64::from(timestamp.nanos) / 1_000_000))
                        .ok_or_else(conflict)?
                }
            };
            expires.insert(key.into(), json!(expiry.to_string()));
        }
        let mut actual: Vec<_> = values.keys().cloned().collect();
        actual.sort();
        let mut expected: Vec<_> = binding["credentialNames"]
            .as_array()
            .ok_or_else(conflict)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(conflict))
            .collect::<Result<_, _>>()?;
        expected.sort();
        if actual != expected {
            return Err(conflict());
        }
        let mut labels = backend.labels();
        labels.insert(OWNER.into(), owner.into());
        labels.insert(
            ALLOCATION.into(),
            input["allocationId"].as_str().ok_or_else(conflict)?.into(),
        );
        labels.insert("globster.dev/secret-binding-id".into(), id.into());
        let profile = super::super::super::provider::handle_get_provider_profile(
            backend.state,
            authed(
                principal,
                openshell_core::proto::GetProviderProfileRequest {
                    id: binding["profile"].as_str().ok_or_else(conflict)?.into(),
                    workspace: workspace.into(),
                },
            ),
        )
        .await
        .map_err(|_| {
            Status::failed_precondition(
                "ordinary provider profile is unavailable in the organization workspace",
            )
        })?
        .into_inner()
        .profile
        .ok_or_else(conflict)?;
        let request: CreateProviderRequest = proto(
            "openshell.v1.CreateProviderRequest",
            json!({"workspace":workspace,
            "provider":{"metadata":{"name":name,"labels":labels,"annotations":{"globster.dev/secret-ref":binding["secretRef"]}},
                "type":binding["profile"],"profileWorkspace":workspace,"credentials":values,"credentialExpiresAtMs":expires,
                "config":{"globster.dev/secret-ref":binding["secretRef"],"globster.dev/provider-profile-revision":profile.resource_version.to_string()}}}),
        )?;
        ticket.issued = true;
        backend.save(cm, &slot).await?;
        let result=super::super::super::provider::handle_create_provider(backend.state,authed(principal,request)).await
            .map_err(|_|Status::failed_precondition("ordinary prewarm provider initialization failed; retry only to discover its committed record"))?
            .into_inner().provider.ok_or_else(conflict)?;
        let (cm, mut slot) = backend.load().await?;
        slot.tickets.get_mut(&ticket_name).ok_or_else(conflict)?.uid =
            Some(result.metadata.ok_or_else(conflict)?.id);
        backend.save(cm, &slot).await?;
        names.push(name);
    }
    names.sort();
    let request = sandbox_request(
        backend,
        input,
        &input["request"]["desired"]["resources"],
        Some(names),
    )?;
    if let Some(existing) = backend
        .state
        .store
        .get_message::<Sandbox>(&backend.identity.workload_id.to_string())
        .await
        .map_err(|_| conflict())?
    {
        let meta = existing.metadata.as_ref().ok_or_else(conflict)?;
        if meta.workspace != workspace
            || meta.labels.get(ALLOCATION).map(String::as_str) != input["allocationId"].as_str()
        {
            return Err(conflict());
        }
        return Ok(existing);
    }
    super::super::super::sandbox::persist_bound_sandbox(
        backend.state,
        authed(principal, request),
        &backend.identity.workload_id.to_string(),
    )
    .await
    .map_err(|error| {
        tracing::warn!(code = ?error.code(), "Ordinary retained sandbox configuration rejected");
        if error.code() == tonic::Code::AlreadyExists {
            Status::aborted(
                "retained sandbox was concurrently persisted; retry the same allocation",
            )
        } else {
            Status::failed_precondition(
                "ordinary tenant sandbox configuration was rejected; retry the same allocation",
            )
        }
    })
}

pub(super) async fn bindings_ready(backend: &Backend<'_>, slot: &Slot) -> Result<bool, Status> {
    let allocation = slot.allocation.as_ref().ok_or_else(conflict)?;
    let workspace = allocation["workspaceName"].as_str().ok_or_else(conflict)?;
    let catalog = backend
        .state
        .provider_profile_sources
        .snapshot_catalog(backend.state.store.as_ref(), workspace)
        .await?;
    for binding in allocation["bindings"].as_array().ok_or_else(conflict)? {
        let id = binding["id"].as_str().ok_or_else(conflict)?;
        let name = format!("{}-sb-{id}", runtime_name(backend.identity.workload_id));
        let Some(provider) = backend
            .state
            .store
            .get_message_by_name::<Provider>(workspace, &name)
            .await
            .map_err(|_| conflict())?
        else {
            return Ok(false);
        };
        let Some(meta) = provider.metadata.as_ref() else {
            return Ok(false);
        };
        let Some(profile) = catalog.get_profile(&provider.r#type) else {
            return Ok(false);
        };
        if slot
            .tickets
            .get(&format!("provider:{id}"))
            .and_then(|t| t.uid.as_deref())
            != Some(meta.id.as_str())
            || provider.r#type != binding["profile"]
            || provider.profile_workspace != workspace
            || provider
                .config
                .get("globster.dev/secret-ref")
                .map(String::as_str)
                != binding["secretRef"].as_str()
            || provider
                .config
                .get("globster.dev/provider-profile-revision")
                != Some(&profile.resource_version.to_string())
        {
            return Ok(false);
        }
        for name in binding["credentialNames"].as_array().ok_or_else(conflict)? {
            let name = name.as_str().ok_or_else(conflict)?;
            if !provider.credentials.contains_key(name)
                || provider
                    .credential_expires_at_ms
                    .get(name)
                    .is_some_and(|expiry| {
                        *expiry != 0 && *expiry <= crate::persistence::current_time_ms()
                    })
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn component_fingerprints_match_the_gateway_v1_golden_vector() {
        let desired = json!({"schemaVersion":1,"revision":7,"powerState":"running",
            "image":format!("registry.example/agent@sha256:{}","a".repeat(64)),
            "workspace":{"capacity":"1Gi"},"resources":{"cpu":"1000m","memory":"512Mi"},"environment":{"NORMAL":"value"},
            "policy":{"schemaVersion":1,"revision":2,"defaultAction":"deny","rules":[
                {"id":"api","host":"API.EXAMPLE.COM.","ports":[8443,443],"protocol":"tcp",
                    "executables":["/usr/bin/curl","/app/.venv/bin/python"]}]},
            "secretBindings":[
                {"schemaVersion":1,"id":"z-binding","profile":"openai","secretRef":"secret-z","credentialNames":["TOKEN_B","TOKEN_A"]},
                {"schemaVersion":1,"id":"a-binding","profile":"anthropic","secretRef":"secret-a","credentialNames":["API_KEY"]}]});
        // Generated by the consumer's actual agentRuntimeFingerprints export.
        assert_eq!(
            fingerprints(&desired).unwrap(),
            json!({
            "compute":"sha256:318ddfde5807db57a3a07f80785e2e2ece1595d2a918e764818f9aa2b575c1d0",
            "policy":"sha256:ad984c47d12d3baf6e3cb39a368b474dac4f5189b41cddd8a61524d71aa20973",
            "secretBindings":"sha256:1207ec51d293046ff647e4e577904796a7f4b1a63417ee80ae4edc1ab57e06d5",
            "overall":"sha256:465212e66a145013efc717e37ac0e4a446ff97778f8edf3b8b1b3f952e132e36"})
        );
        let input = json!({"request":{"desired":desired},"organization":{"organizationId":"org"},"launch":{"networkPolicies":{}}});
        assert_eq!(
            normal_metadata_hashes(
                &input,
                Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()
            )
            .unwrap(),
            (
                "sha256:e3761d9d18719759794c19f86798a25ceb71b278eb32c3bb9f7ed6774ab35292".into(),
                "sha256:c4552d52ee63189f7375b63a38d182c407c4a3978a1d73a2269fcbafad51ea63".into()
            )
        );
    }
    #[test]
    fn organization_context_is_derived_not_a_caller_selected_workspace() {
        let digest = Sha256::digest("globster/organization-owner/v1\0org");
        let mut value = json!({"organizationId":"org","workspaceName":"arbitrary","ownershipMarker":format!("{digest:x}")[..32].to_owned()});
        assert!(organization(&value).is_err());
        value["ownershipMarker"] = json!("forged");
        assert!(organization(&value).is_err());
    }
}
