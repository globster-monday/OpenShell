// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted, pre-supervisor startup gate. The resource owner must publish a grant
//! only after its durable, single-use resource binding has committed.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::sandbox_env::{self, MainProcessConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::binding_workspace::{self, WorkspaceInitialization};

pub const SUBCOMMAND: &str = "await-binding";
pub const GRANT_VERSION: u32 = 1;
const MAX_GRANT_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_ARGS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_WAIT_SECONDS: u64 = 86400;

#[derive(Parser)]
struct GateArgs {
    #[arg(long)]
    slot_id: Uuid,
    #[arg(long)]
    generation: u64,
    #[arg(long)]
    pod_uid: Uuid,
    #[arg(long)]
    sandbox_id: Uuid,
    /// Root-owned, owner-readable-only file on a read-only projected volume.
    #[arg(long)]
    grant: PathBuf,
    #[arg(long, default_value_t = MAX_WAIT_SECONDS)]
    wait_seconds: u64,
    /// Reject grants without retained-pod workspace initialization.
    #[arg(long)]
    require_workspace_initialization: bool,
    /// Held init-container mode. Initialize once, publish a sanitized Kubernetes
    /// termination receipt and exit without ever constructing a supervisor.
    #[arg(long)]
    initialize_only: bool,
    /// Normal supervisor flags; no workload command override.
    #[arg(last = true)]
    supervisor_args: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundLaunchGrant {
    pub version: u32,
    pub slot_id: Uuid,
    pub generation: u64,
    pub pod_uid: Uuid,
    pub sandbox_id: Uuid,
    pub allocation_id: Uuid,
    pub main_process: MainProcessConfig,
    pub environment: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_initialization: Option<WorkspaceInitialization>,
}

impl BoundLaunchGrant {
    fn validate(&self, expected: &GateArgs) -> Result<()> {
        if self.version != GRANT_VERSION
            || self.slot_id != expected.slot_id
            || self.generation != expected.generation
            || self.pod_uid != expected.pod_uid
            || self.sandbox_id != expected.sandbox_id
            || self.allocation_id.is_nil()
        {
            return Err(miette::miette!(
                "binding grant identity or version mismatch"
            ));
        }
        if self.main_process.version != MainProcessConfig::VERSION
            || self.main_process.command.is_empty()
            || self.main_process.command.len() > MAX_COMMAND_ARGS
            || self.main_process.command[0].is_empty()
            || self
                .main_process
                .command
                .iter()
                .any(|arg| arg.len() > MAX_ARGUMENT_BYTES || arg.contains('\0'))
        {
            return Err(miette::miette!("invalid bound main process"));
        }
        if self.environment.len() > MAX_ENVIRONMENT_ENTRIES
            || self
                .environment
                .iter()
                .any(|(key, value)| !valid_environment_key(key) || value.contains('\0'))
        {
            return Err(miette::miette!("invalid bound workload environment"));
        }
        if expected.require_workspace_initialization && self.workspace_initialization.is_none() {
            return Err(miette::miette!(
                "bound workspace initialization is required"
            ));
        }
        if let Some(initialization) = &self.workspace_initialization {
            initialization.validate()?;
        }
        Ok(())
    }
}

fn valid_environment_key(key: &str) -> bool {
    if key.is_empty() || key.starts_with("OPENSHELL_") {
        return false;
    }
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn read_grant(path: &Path, expected: &GateArgs) -> Result<Option<BoundLaunchGrant>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).into_diagnostic(),
    };
    let metadata = file.metadata().into_diagnostic()?;
    // Follow the projected volume's atomic symlink, then check the opened inode.
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o400
        || metadata.len() > MAX_GRANT_BYTES
    {
        return Err(miette::miette!(
            "binding grant must be a private root-owned file"
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_GRANT_BYTES + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() as u64 > MAX_GRANT_BYTES {
        return Err(miette::miette!("binding grant exceeds size limit"));
    }
    let grant: BoundLaunchGrant = serde_json::from_slice(&bytes)
        .map_err(|_| miette::miette!("invalid binding grant document"))?;
    grant.validate(expected)?;
    Ok(Some(grant))
}

/// Wait without starting a supervisor, acquiring tenant credentials, or launching
/// workload processes; then replace the gate with the normal supervisor.
pub fn run(arguments: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let args = GateArgs::try_parse_from(
        std::iter::once(SUBCOMMAND.to_string()).chain(arguments.iter().cloned()),
    )
    .into_diagnostic()?;
    if !nix::unistd::geteuid().is_root()
        || !args.grant.is_absolute()
        || args.slot_id.is_nil()
        || args.pod_uid.is_nil()
        || args.sandbox_id.is_nil()
        || args.generation == 0
        || args.wait_seconds == 0
        || args.wait_seconds > MAX_WAIT_SECONDS
    {
        return Err(miette::miette!(
            "invalid trusted binding gate configuration"
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(args.wait_seconds);
    if args.initialize_only {
        binding_workspace::verify_prepared_blank(&serde_json::json!({
            "slotId":args.slot_id,"generation":args.generation,"podUid":args.pod_uid,"sandboxId":args.sandbox_id,
        }))?;
        eprintln!(
            "OpenShell held-init ready slot={} generation={} pod={} sandbox={}",
            args.slot_id, args.generation, args.pod_uid, args.sandbox_id
        );
    }
    eprintln!("Waiting for committed workload binding");
    loop {
        if Instant::now() >= deadline {
            return Err(miette::miette!("workload binding deadline exceeded"));
        }
        if let Some(grant) = read_grant(&args.grant, &args)? {
            if args.initialize_only {
                binding_workspace::prepare_blank_claim()?;
            }
            // Hold the pod-private lock until exec closes it. The initializer
            // finishes as UID/GID 1000 before the privileged supervisor exists.
            let _writer = binding_workspace::initialize_retained_pod(&grant, deadline)?;
            if args.initialize_only {
                use sha2::{Digest, Sha256};
                let canonical =
                    serde_json::to_vec(&serde_json::to_value(&grant).into_diagnostic()?)
                        .into_diagnostic()?;
                let receipt = serde_json::json!({
                    "version": 1,
                    "slotId": grant.slot_id,
                    "generation": grant.generation,
                    "podUid": grant.pod_uid,
                    "sandboxId": grant.sandbox_id,
                    "allocationId": grant.allocation_id,
                    "grantHash": format!("{:x}", Sha256::digest(canonical)),
                });
                std::fs::write(
                    "/dev/termination-log",
                    serde_json::to_vec(&receipt).into_diagnostic()?,
                )
                .into_diagnostic()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(miette::miette!("workload binding deadline exceeded"));
            }
            let mut command =
                std::process::Command::new(std::env::current_exe().into_diagnostic()?);
            command
                .args(&args.supervisor_args)
                .env(sandbox_env::SANDBOX_ID, grant.sandbox_id.to_string())
                .env(
                    sandbox_env::MAIN_PROCESS_SPEC,
                    serde_json::to_string(&grant.main_process).into_diagnostic()?,
                )
                .env(
                    sandbox_env::USER_ENVIRONMENT,
                    serde_json::to_string(&grant.environment).into_diagnostic()?,
                );
            return Err(command.exec()).into_diagnostic();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> GateArgs {
        GateArgs {
            slot_id: Uuid::from_u128(1),
            generation: 3,
            pod_uid: Uuid::from_u128(2),
            sandbox_id: Uuid::from_u128(3),
            grant: PathBuf::from("/run/openshell-binding/grant.json"),
            wait_seconds: 60,
            require_workspace_initialization: false,
            initialize_only: false,
            supervisor_args: Vec::new(),
        }
    }

    fn grant() -> BoundLaunchGrant {
        let expected = expected();
        BoundLaunchGrant {
            version: GRANT_VERSION,
            slot_id: expected.slot_id,
            generation: expected.generation,
            pod_uid: expected.pod_uid,
            sandbox_id: expected.sandbox_id,
            allocation_id: Uuid::from_u128(4),
            main_process: MainProcessConfig {
                version: MainProcessConfig::VERSION,
                command: vec!["/app/agent".to_string(), "argument with spaces".to_string()],
                tty: false,
            },
            environment: HashMap::from([("AGENT_ID".to_string(), "tenant-agent".to_string())]),
            workspace_initialization: None,
        }
    }

    #[test]
    fn accepts_exact_binding_and_lossless_process_configuration() {
        let original = grant();
        let bytes = serde_json::to_vec(&original).unwrap();
        let decoded: BoundLaunchGrant = serde_json::from_slice(&bytes).unwrap();
        decoded.validate(&expected()).unwrap();
        assert_eq!(decoded.main_process, original.main_process);
        assert_eq!(decoded.environment, original.environment);
    }

    #[test]
    fn rejects_stale_or_different_resources_and_missing_allocation() {
        let changes: [fn(&mut BoundLaunchGrant); 6] = [
            |grant: &mut BoundLaunchGrant| grant.slot_id = Uuid::from_u128(9),
            |grant: &mut BoundLaunchGrant| grant.generation += 1,
            |grant: &mut BoundLaunchGrant| grant.pod_uid = Uuid::from_u128(9),
            |grant: &mut BoundLaunchGrant| grant.sandbox_id = Uuid::from_u128(9),
            |grant: &mut BoundLaunchGrant| grant.allocation_id = Uuid::nil(),
            |grant: &mut BoundLaunchGrant| grant.version += 1,
        ];
        for change in changes {
            let mut candidate = grant();
            change(&mut candidate);
            assert!(candidate.validate(&expected()).is_err());
        }
    }

    #[test]
    fn rejects_supervisor_environment_override_and_invalid_process() {
        for key in [
            "OPENSHELL_SANDBOX_TOKEN",
            "OPENSHELL_MAIN_PROCESS_SPEC",
            "A=B",
            "",
        ] {
            let mut candidate = grant();
            candidate
                .environment
                .insert(key.to_string(), "value".to_string());
            assert!(candidate.validate(&expected()).is_err());
        }
        for command in [
            vec![],
            vec![String::new()],
            vec!["/app/agent\0".to_string()],
        ] {
            let mut candidate = grant();
            candidate.main_process.command = command;
            assert!(candidate.validate(&expected()).is_err());
        }
    }

    #[test]
    fn required_initialization_cannot_be_omitted_or_supply_malformed_configuration() {
        let mut expected = expected();
        expected.require_workspace_initialization = true;
        let mut candidate = grant();
        assert!(candidate.validate(&expected).is_err());
        candidate.workspace_initialization = Some(WorkspaceInitialization {
            recipe_id: "base-agent".into(),
            recipe_digest: format!("sha256:{}", "a".repeat(64)),
            initial_configuration_json: None,
        });
        candidate.validate(&expected).unwrap();
        candidate
            .workspace_initialization
            .as_mut()
            .unwrap()
            .initial_configuration_json = Some("secret-malformed-configuration".into());
        let error = candidate.validate(&expected).unwrap_err();
        assert!(!format!("{error:?}").contains("secret-malformed-configuration"));
    }
}
