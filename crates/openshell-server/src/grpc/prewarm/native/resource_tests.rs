// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native resource proof, deliberately not a customer/agent readiness test.

use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use openshell_core::proto::PrewarmSlotRequest;

async fn state(
    config: KubernetesComputeConfig,
    store: Option<Arc<crate::persistence::Store>>,
) -> Arc<ServerState> {
    let original = test_server_state().await;
    let mut state = Arc::try_unwrap(original).unwrap();
    if let Some(store) = store {
        state.store = store;
    }
    let (_shutdown, rx) = tokio::sync::watch::channel(false);
    state.compute = crate::compute::ComputeRuntime::new_kubernetes(
        config,
        state.store.clone(),
        state.sandbox_index.clone(),
        state.sandbox_watch_bus.clone(),
        state.tracing_log_bus.clone(),
        state.supervisor_sessions.clone(),
        rx,
    )
    .await
    .unwrap()
    .0;
    Arc::new(state)
}

async fn call(
    state: &Arc<ServerState>,
    operation: Operation,
    input: &Value,
) -> Result<Value, Status> {
    let identity = json!({"schemaVersion":input["schemaVersion"],"slotId":input["slotId"],
        "workloadId":input["workloadId"],"generation":input["generation"]});
    let input = if matches!(operation, Operation::Observe) {
        &identity
    } else {
        input
    };
    let response = super::super::handle_operation(
        state,
        authed_request(PrewarmSlotRequest {
            request_json: input.to_string(),
        }),
        operation,
    )
    .await?;
    Ok(serde_json::from_str(&response.into_inner().evidence_json).unwrap())
}

async fn retry(state: &Arc<ServerState>, operation: Operation, input: &Value) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match call(state, operation, input).await {
            Ok(value) => return value,
            Err(error)
                if matches!(
                    error.code(),
                    tonic::Code::Aborted | tonic::Code::Unavailable
                ) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("native fixture operation failed: {error}"),
        }
    }
}

fn prepare(config: &KubernetesComputeConfig) -> Value {
    let approved = config.prewarm.as_ref().unwrap();
    let workload = Uuid::new_v4();
    let mut storage = json!({"namespace":config.namespace,"claimName":format!("globster-workspace-{workload}"),"accessModes":["ReadWriteOnce"]});
    if !config.workspace_storage_class.is_empty() {
        storage["storageClassName"] = json!(config.workspace_storage_class);
    }
    json!({"schemaVersion":1,"slotId":Uuid::new_v4(),"workloadId":workload,"generation":1,
        "preparation":{"schemaVersion":1,"providerArtifact":approved.provider_artifact,
            "placementKey":approved.placement_key,"image":approved.image,
            "recipe":{"id":approved.recipe_id,"digest":approved.recipe_digest,"image":approved.recipe_image},
            "resources":{"cpu":"1000m","memory":"512Mi"},"workspace":{"capacity":"1Gi"}},"storage":storage})
}

fn binding(prepare: &Value, receipt: &Value) -> Value {
    let organization = "native-resource-fixture";
    let id = prepare["workloadId"].as_str().unwrap();
    let owner = format!(
        "{:x}",
        Sha256::digest(format!("globster/organization-owner/v1\0{organization}"))
    )[..32]
        .to_owned();
    let workspace = format!(
        "gw-{}",
        tenant::compact(&Sha256::digest(format!(
            "globster/workspace/v1\0{organization}"
        )))
    );
    let mut desired = json!({"schemaVersion":1,"revision":1,"powerState":"running",
        "image":prepare["preparation"]["image"],"recipe":prepare["preparation"]["recipe"],
        "resources":prepare["preparation"]["resources"],"workspace":prepare["preparation"]["workspace"],
        "policy":{"schemaVersion":1,"revision":1,"defaultAction":"deny","rules":[]},"secretBindings":[]});
    desired["fingerprints"] = tenant::fingerprints(&desired).unwrap();
    let mut input = prepare.clone();
    input["allocationId"] = json!(Uuid::new_v4());
    input["resourceReceipt"] = receipt.clone();
    input["request"] = json!({"schemaVersion":1,"desired":desired,"credentialWrites":[]});
    input["organization"] =
        json!({"organizationId":organization,"workspaceName":workspace,"ownershipMarker":owner});
    input["launch"] = json!({"command":["/app/.venv/bin/python","-m","agent_harness","serve","--headless","--host","0.0.0.0","--port","9000"],
        "environment":{"AGENT_DATA_DIR":"/workspace","AGENT_ID":id,"GLOBSTER_ORGANIZATION_ID":organization,
            "AGENT_STORAGE_ROOT":format!("/workspace/{id}/workspace"),"AGENT_HOST_CREDENTIAL_REFERENCE_TEMPLATE":"openshell:resolve:env:{credential}","HOME":"/workspace"},
        "networkPolicies":{},"platformPolicyRevision":1,"workspaceMountPath":"/workspace",
        "persistenceMountPath":"/sandbox/persist","persistenceSubPath":format!("{id}/.globster-openshell-persist")});
    input
}

#[tokio::test]
#[ignore = "requires isolated Kubernetes and explicitly approved immutable native gate fixtures; not customer proof"]
async fn retained_prewarm_resources_and_cross_replica_fences() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    assert_eq!(
        kube::config::Kubeconfig::read()
            .unwrap()
            .current_context
            .as_deref(),
        Some("kind-globster-prewarm-native"),
        "refusing an unapproved Kubernetes context"
    );
    let filename = std::env::var("OPENSHELL_PREWARM_RESOURCE_TEST_CONFIG")
        .expect("explicit isolated fixture configuration required");
    let config: KubernetesComputeConfig =
        serde_json::from_slice(&std::fs::read(&filename).unwrap()).unwrap();
    assert!(
        config.namespace.starts_with("native-prewarm-fixture-"),
        "refusing non-fixture namespace"
    );
    let store_path = std::path::Path::new(&filename)
        .parent()
        .unwrap()
        .join(format!("native-resource-proof-{}.sqlite", Uuid::new_v4()));
    let store_url = format!("sqlite://{}?mode=rwc", store_path.display());
    let open_store = || async {
        Arc::new(
            crate::persistence::Store::connect(&store_url)
                .await
                .unwrap(),
        )
    };
    let first = state(config.clone(), Some(open_store().await)).await;
    let second = state(config.clone(), Some(open_store().await)).await;
    let input = prepare(&config);
    let mut evidence = retry(&first, Operation::Prepare, &input).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    while evidence["observation"]["state"] != "idle_ready" {
        assert!(
            tokio::time::Instant::now() < deadline,
            "held init did not become ready"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        evidence = retry(&second, Operation::Observe, &input).await;
    }
    let receipt = evidence["resources"]["receipt"].clone();
    assert_eq!(evidence["tenantConfigured"], false);
    assert!(
        first
            .store
            .get_message::<Sandbox>(input["workloadId"].as_str().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        call(&second, Operation::Prepare, &input).await.unwrap()["resources"]["receipt"],
        receipt
    );
    let mut bound = binding(&input, &receipt);
    let mut wrong_receipt = bound.clone();
    wrong_receipt["resourceReceipt"]["computeUid"] = json!(Uuid::new_v4());
    assert_eq!(
        call(&second, Operation::Bind, &wrong_receipt)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut stale_generation = input.clone();
    stale_generation["generation"] = json!(2);
    assert_eq!(
        call(&second, Operation::Observe, &stale_generation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        call(&second, Operation::Retire, &stale_generation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let unchanged = retry(&first, Operation::Observe, &input).await;
    assert_eq!(unchanged["observation"]["state"], "idle_ready");
    assert_eq!(unchanged["tenantConfigured"], false);
    assert_eq!(unchanged["resources"]["receipt"], receipt);
    let mut competing = bound.clone();
    competing["allocationId"] = json!(Uuid::new_v4());
    let (left, right) = tokio::join!(
        call(&first, Operation::Bind, &bound),
        call(&second, Operation::Bind, &competing)
    );
    assert!(
        !(left.is_ok() && right.is_ok()),
        "two allocations passed the resource-side fence"
    );
    let allocated = retry(&second, Operation::Observe, &input).await;
    if allocated["observation"]["allocation"]["id"] == competing["allocationId"] {
        bound = competing;
    }
    assert_eq!(
        allocated["observation"]["allocation"]["id"],
        bound["allocationId"]
    );
    retry(&first, Operation::Bind, &bound).await;
    let mut conflict = bound.clone();
    conflict["allocationId"] = json!(Uuid::new_v4());
    assert_eq!(
        call(&second, Operation::Bind, &conflict)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        evidence = retry(&second, Operation::Observe, &input).await;
        if evidence["observation"]["state"] == "bound" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "initialization did not complete"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(evidence["resources"]["receipt"], receipt);
    assert_eq!(evidence["tenantConfigured"], true);
    assert_eq!(evidence["singleWriterInitialized"], true);
    assert_eq!(evidence["observation"]["launchReleased"], true);
    assert_eq!(
        evidence["observation"]["result"]["ready"], false,
        "fixture is not an agent/harness customer proof"
    );
    assert_eq!(
        call(&first, Operation::Bind, &bound).await.unwrap()["resources"]["receipt"],
        receipt
    );
    let reopened = state(config.clone(), Some(open_store().await)).await;
    assert_eq!(
        call(&reopened, Operation::Observe, &input).await.unwrap()["resources"]["receipt"],
        receipt
    );
    assert_eq!(
        call(&first, Operation::Retire, &input)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut forbidden = first
        .store
        .get_message::<Sandbox>(input["workloadId"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let metadata = forbidden.metadata.as_mut().unwrap();
    metadata.id = Uuid::new_v4().to_string();
    metadata.name = "fixture-forbidden-writer".into();
    let forbidden = crate::compute::driver_sandbox_from_public(&forbidden, "kubernetes").unwrap();
    let error = first
        .compute
        .prewarm_driver
        .as_ref()
        .unwrap()
        .create_sandbox(&forbidden)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("reserved native prewarm claim"),
        "ordinary create did not enforce claim exclusivity"
    );
    let mut cold_config = config.clone();
    cold_config.prewarm = None;
    let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let cold_driver = KubernetesComputeDriver::new(cold_config, shutdown_rx)
        .await
        .unwrap();
    let error = cold_driver.create_sandbox(&forbidden).await.unwrap_err();
    assert!(
        error.to_string().contains("reserved native prewarm claim"),
        "removing prewarm configuration disabled reserved-claim protection"
    );
    // Proof markers carry outcomes only; resource receipts are asserted above and
    // are never written to the test log.
    println!("NATIVE_RESOURCE_BIND_PROOF initialized=true retained=true customerReady=false");

    let unused = prepare(&config);
    let prepared = retry(&first, Operation::Prepare, &unused).await;
    let unused_receipt = prepared["resources"]["receipt"].clone();
    let mut retirement = unused.clone();
    retirement["resourceReceipt"] = unused_receipt.clone();
    let mut wrong_retirement = retirement.clone();
    wrong_retirement["resourceReceipt"]["storageUid"] = json!(Uuid::new_v4());
    assert_eq!(
        call(&second, Operation::Retire, &wrong_retirement)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        retry(&first, Operation::Prepare, &unused).await["resources"]["receipt"],
        unused_receipt
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let retired = retry(&second, Operation::Retire, &retirement).await;
        if retired["observation"]["state"] == "retired" {
            assert_eq!(retired["computeAbsent"], true);
            assert_eq!(retired["storageAbsent"], true);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "retirement did not complete"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(call(&first, Operation::Prepare, &unused).await.is_err());
    println!("NATIVE_RESOURCE_RETIRE_PROOF computeAbsent=true storageAbsent=true");

    let uncertain = prepare(&config);
    let driver = first.compute.prewarm_driver.as_ref().unwrap();
    let (client, config) = driver.prewarm_context();
    let principal = authed_request(())
        .extensions()
        .get::<Principal>()
        .unwrap()
        .clone();
    let backend = Backend {
        state: &first,
        driver,
        principal: &principal,
        config,
        client,
        identity: identity(&uncertain).unwrap(),
        name: format!("prewarm-{}", uncertain["workloadId"].as_str().unwrap()),
    };
    backend.reserve(&uncertain, false).await.unwrap();
    backend.ensure_fence().await.unwrap();
    let (cm, mut slot) = backend.load().await.unwrap();
    // Model a process crash after durable ticket issuance, before HTTP CREATE.
    slot.tickets.insert(
        "compute".into(),
        Ticket {
            issued: true,
            uid: None,
            rejected: false,
        },
    );
    backend.save(cm, &slot).await.unwrap();
    assert_eq!(
        call(&second, Operation::Prepare, &uncertain)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        call(&first, Operation::Retire, &uncertain)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(
        backend
            .api::<Pod>()
            .get_opt(&backend.name)
            .await
            .unwrap()
            .is_none()
    );
    let (_, slot) = backend.load().await.unwrap();
    assert!(slot.phase == Phase::Retiring && slot.quarantined);
    assert!(
        backend
            .api::<PersistentVolumeClaim>()
            .get_opt(slot.storage["claimName"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
    println!(
        "NATIVE_RESOURCE_QUARANTINE_PROOF workload={} recreated=false falselyRetired=false storagePreserved=true",
        uncertain["workloadId"]
    );
    // Deliver the original worker's delayed, single CREATE after retirement
    // won its fence. Retirement must discover it before storage can disappear.
    let (cm, slot) = backend.load().await.unwrap();
    let rendered = backend.neutral_sandbox(&slot.preparation).await.unwrap();
    let template = backend
        .held_template(&rendered.data["spec"]["podTemplate"], &slot)
        .unwrap();
    let pod:DynamicObject=serde_json::from_value(json!({"apiVersion":"v1","kind":"Pod","metadata":{
        "name":backend.name,"namespace":config.namespace,"labels":backend.labels(),
        "annotations":template["metadata"]["annotations"],"ownerReferences":[backend.owner(&cm).unwrap()]},
        "spec":template["spec"]})).unwrap();
    backend
        .pod_api()
        .create(&PostParams::default(), &pod)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let retired = retry(&second, Operation::Retire, &uncertain).await;
        if retired["observation"]["state"] == "retired" {
            assert_eq!(retired["computeAbsent"], true);
            assert_eq!(retired["storageAbsent"], true);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "delayed creation was not settled"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!(
        "NATIVE_RESOURCE_DELAYED_CREATE_PROOF workload={} lateCreateSettled=true computeAbsent=true storageAbsent=true",
        uncertain["workloadId"]
    );
}
