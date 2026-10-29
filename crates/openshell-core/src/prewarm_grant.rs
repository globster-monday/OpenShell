// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixed, one-shot publication of pod-local launch grants. No grant is projected
//! through a group-readable Secret or returned by recovery/status operations.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const STATE_PATH: &str = "/run/openshell-binding-state";
pub const PRIVATE_DIRECTORY: &str = "private";
pub const PREPARED_RECEIPT: &str = "blank.json";
pub const DELIVER_SUBCOMMAND: &str = "deliver-binding-grant";
pub const STATUS_SUBCOMMAND: &str = "binding-grant-status";
pub const MAX_GRANT_BYTES: u64 = 1024 * 1024;
pub const POD_UID_ENV: &str = "OPENSHELL_PREWARM_POD_UID";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantRole {
    Init,
    Network,
    Process,
}

impl GrantRole {
    fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Network => "network",
            Self::Process => "process",
        }
    }

    #[must_use]
    pub fn path(self) -> PathBuf {
        Path::new(STATE_PATH)
            .join(PRIVATE_DIRECTORY)
            .join(format!("{}.json", self.name()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantIdentity {
    pub slot_id: Uuid,
    pub generation: u64,
    pub pod_uid: Uuid,
    pub sandbox_id: Uuid,
    pub allocation_id: Uuid,
}

impl GrantIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.slot_id.is_nil()
            || self.pod_uid.is_nil()
            || self.sandbox_id.is_nil()
            || self.allocation_id.is_nil()
            || self.generation == 0
            || self.generation > 9_007_199_254_740_991
        {
            return Err(miette::miette!("invalid private grant identity"));
        }
        Ok(())
    }

    fn matches_grant(&self, grant: &Value) -> bool {
        grant["version"] == 1
            && grant["slot_id"] == self.slot_id.to_string()
            && grant["generation"] == self.generation
            && grant["pod_uid"] == self.pod_uid.to_string()
            && grant["sandbox_id"] == self.sandbox_id.to_string()
            && grant["allocation_id"] == self.allocation_id.to_string()
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantStatus {
    pub identity: GrantIdentity,
    pub role: GrantRole,
    pub issued: bool,
    pub grant_hash: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub identity: GrantIdentity,
    pub role: GrantRole,
    pub grant_hash: Option<String>,
}

#[must_use]
pub fn grant_hash(grant: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(grant).expect("JSON value"))
    )
}

/// Only an inert root gate can establish this directory. The store never
/// creates it, repairs permissions, follows links or accepts a caller's path.
pub struct GrantStore {
    directory: PathBuf,
    owner: u32,
}

impl GrantStore {
    pub fn open() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(miette::miette!("private grant helper requires UID 0"));
        }
        let store = Self {
            directory: Path::new(STATE_PATH).join(PRIVATE_DIRECTORY),
            owner: 0,
        };
        store.check_directory(Path::new(STATE_PATH))?;
        store.check_directory(&store.directory)?;
        Ok(store)
    }

    fn check_directory(&self, path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).into_diagnostic()?;
        if !metadata.is_dir() || metadata.uid() != self.owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(miette::miette!("private grant directory is unsafe"));
        }
        Ok(())
    }

    fn read_private(&self, path: &Path, mode: u32) -> Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(miette::miette!("private grant file is unavailable")),
        };
        let metadata = file.metadata().into_diagnostic()?;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o7777 != mode
            || metadata.len() > MAX_GRANT_BYTES
        {
            return Err(miette::miette!("private grant file is unsafe"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_GRANT_BYTES + 1)
            .read_to_end(&mut bytes)
            .into_diagnostic()?;
        if bytes.len() as u64 > MAX_GRANT_BYTES {
            return Err(miette::miette!("private grant exceeds size limit"));
        }
        Ok(Some(bytes))
    }

    pub fn verify_prepared_identity(&self, identity: &GrantIdentity) -> Result<()> {
        identity.validate()?;
        self.check_directory(&self.directory)?;
        let bytes = self
            .read_private(&self.directory.join(PREPARED_RECEIPT), 0o600)?
            .ok_or_else(|| miette::miette!("prepared identity is unavailable"))?;
        let prepared: Value = serde_json::from_slice(&bytes)
            .map_err(|_| miette::miette!("invalid prepared identity"))?;
        if prepared
            != serde_json::json!({
                "slotId":identity.slot_id,"generation":identity.generation,
                "podUid":identity.pod_uid,"sandboxId":identity.sandbox_id,
            })
        {
            return Err(miette::miette!("private grant prepared identity mismatch"));
        }
        if let Some(bytes) = self.read_private(&self.directory.join("allocation.json"), 0o400)? {
            let allocation: GrantIdentity = serde_json::from_slice(&bytes)
                .map_err(|_| miette::miette!("invalid private grant allocation"))?;
            if allocation != *identity {
                return Err(miette::miette!(
                    "private grant allocation identity mismatch"
                ));
            }
        }
        Ok(())
    }

    fn claim_allocation(&self, identity: &GrantIdentity, role: GrantRole) -> Result<()> {
        let allocation = self.directory.join("allocation.json");
        if self.read_private(&allocation, 0o400)?.is_none() {
            if role != GrantRole::Init {
                return Err(miette::miette!(
                    "private grant initialization has not been issued"
                ));
            }
            self.write_once(
                &allocation,
                &serde_json::to_vec(identity).into_diagnostic()?,
            )?;
        }
        self.verify_prepared_identity(identity)?;
        let previous = match role {
            GrantRole::Init => return Ok(()),
            GrantRole::Network => GrantRole::Init,
            GrantRole::Process => GrantRole::Network,
        };
        if self.status(identity, previous)?.grant_hash.is_none() {
            return Err(miette::miette!(
                "previous private grant has not been published"
            ));
        }
        Ok(())
    }

    fn path(&self, role: GrantRole, suffix: &str) -> PathBuf {
        self.directory.join(format!("{}.{suffix}", role.name()))
    }

    fn write_once(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                miette::miette!(
                    "private grant delivery already issued or unavailable; observe only"
                )
            })?;
        file.write_all(bytes).into_diagnostic()?;
        file.sync_all().into_diagnostic()?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .into_diagnostic()
    }

    /// An issued or interrupted delivery is never replayed, even with identical
    /// bytes. Only status may settle an uncertain outcome.
    pub fn publish(
        &self,
        identity: &GrantIdentity,
        role: GrantRole,
        grant: &Value,
    ) -> Result<GrantStatus> {
        self.verify_prepared_identity(identity)?;
        if !identity.matches_grant(grant) {
            return Err(miette::miette!(
                "private grant allocation identity mismatch"
            ));
        }
        let bytes = serde_json::to_vec(grant).into_diagnostic()?;
        if bytes.len() as u64 > MAX_GRANT_BYTES {
            return Err(miette::miette!("private grant exceeds size limit"));
        }
        self.claim_allocation(identity, role)?;
        let receipt = GrantStatus {
            identity: identity.clone(),
            role,
            issued: true,
            grant_hash: Some(grant_hash(grant)),
        };
        self.write_once(
            &self.path(role, "issued"),
            &serde_json::to_vec(&receipt).into_diagnostic()?,
        )?;
        let pending = self.path(role, "pending");
        self.write_once(&pending, &bytes)?;
        // Unlike rename, hard_link cannot overwrite an existing published grant.
        fs::hard_link(&pending, self.path(role, "json")).into_diagnostic()?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .into_diagnostic()?;
        Ok(receipt)
    }

    pub fn status(&self, identity: &GrantIdentity, role: GrantRole) -> Result<GrantStatus> {
        self.verify_prepared_identity(identity)?;
        let mut status = GrantStatus {
            identity: identity.clone(),
            role,
            issued: false,
            grant_hash: None,
        };
        let issued = self.read_private(&self.path(role, "issued"), 0o400)?;
        let published = self.read_private(&self.path(role, "json"), 0o400)?;
        let receipt = issued
            .map(|bytes| {
                let receipt: GrantStatus = serde_json::from_slice(&bytes)
                    .map_err(|_| miette::miette!("invalid private grant receipt"))?;
                if receipt.identity != *identity || receipt.role != role || !receipt.issued {
                    return Err(miette::miette!("private grant receipt mismatch"));
                }
                Ok(receipt)
            })
            .transpose()?;
        status.issued = receipt.is_some();
        match (receipt, published) {
            (_, None) => {}
            (Some(receipt), Some(bytes)) => {
                let grant: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| miette::miette!("invalid private grant document"))?;
                if receipt.grant_hash.as_deref() != Some(grant_hash(&grant).as_str())
                    || !identity.matches_grant(&grant)
                {
                    return Err(miette::miette!("private grant receipt mismatch"));
                }
                status.grant_hash = receipt.grant_hash;
            }
            (None, Some(_)) => {
                return Err(miette::miette!("private grant has no delivery receipt"));
            }
        }
        Ok(status)
    }
}

fn read_document<R: BufRead>(input: &mut R, limit: u64) -> Result<Value> {
    let mut bytes = Vec::new();
    input
        .take(limit + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| miette::miette!("private grant input is unavailable"))?;
    if bytes.len() as u64 > limit || bytes.last() != Some(&b'\n') {
        return Err(miette::miette!(
            "private grant input is incomplete or exceeds limit"
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| miette::miette!("invalid private grant input"))
}

fn write_status<W: Write>(output: &mut W, status: &GrantStatus) -> Result<()> {
    serde_json::to_writer(&mut *output, status).into_diagnostic()?;
    output.write_all(b"\n").into_diagnostic()?;
    output.flush().into_diagnostic()
}

fn exchange<R: BufRead, W: Write>(
    store: &GrantStore,
    input: &mut R,
    output: &mut W,
    pod_uid: &str,
    observe_only: bool,
) -> Result<()> {
    let request: GrantRequest = serde_json::from_value(read_document(input, 4096)?)
        .map_err(|_| miette::miette!("invalid private grant request"))?;
    if request.identity.pod_uid.to_string() != pod_uid {
        return Err(miette::miette!(
            "private grant downward pod identity mismatch"
        ));
    }
    let status = store.status(&request.identity, request.role)?;
    write_status(output, &status)?;
    if observe_only {
        return Ok(());
    }
    if status.issued {
        return Err(miette::miette!(
            "private grant delivery already issued; observe only"
        ));
    }
    let expected_hash = request
        .grant_hash
        .filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| miette::miette!("invalid private grant hash"))?;
    // The first reply contains no grant bytes. The caller must revalidate the
    // retained Pod/container and issue its durable delivery ticket before stdin
    // continues. Kubernetes exec itself has no Pod UID precondition.
    let grant = read_document(input, MAX_GRANT_BYTES + 1)?;
    if grant_hash(&grant) != expected_hash {
        return Err(miette::miette!("private grant hash mismatch"));
    }
    write_status(
        output,
        &store.publish(&request.identity, request.role, &grant)?,
    )
}

/// Internal fixed-command helper. Its stdin/stdout protocol contains a bounded
/// nonsecret handshake, then one grant and one sanitized acknowledgment.
pub fn run_helper(observe_only: bool) -> Result<()> {
    let pod_uid = std::env::var(POD_UID_ENV)
        .map_err(|_| miette::miette!("private grant downward pod identity is unavailable"))?;
    let store = GrantStore::open()?;
    exchange(
        &store,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &pod_uid,
        observe_only,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, GrantStore, GrantIdentity, Value) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = GrantStore {
            directory: directory.path().into(),
            owner: nix::unistd::geteuid().as_raw(),
        };
        let identity = GrantIdentity {
            slot_id: Uuid::from_u128(1),
            generation: 1,
            pod_uid: Uuid::from_u128(2),
            sandbox_id: Uuid::from_u128(3),
            allocation_id: Uuid::from_u128(4),
        };
        let blank = store.directory.join(PREPARED_RECEIPT);
        fs::write(
            &blank,
            serde_json::to_vec(&serde_json::json!({
                "slotId":identity.slot_id,"generation":identity.generation,
                "podUid":identity.pod_uid,"sandboxId":identity.sandbox_id,
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(blank, fs::Permissions::from_mode(0o600)).unwrap();
        let mut grant = serde_json::to_value(&identity).unwrap();
        grant["version"] = serde_json::json!(1);
        grant["environment"] = serde_json::json!({"SECRET":"never-return-this"});
        (directory, store, identity, grant)
    }

    #[test]
    fn publication_is_private_one_shot_and_status_is_sanitized() {
        let (_directory, store, identity, grant) = fixture();
        assert_eq!(
            store.status(&identity, GrantRole::Init).unwrap().grant_hash,
            None
        );
        let receipt = store.publish(&identity, GrantRole::Init, &grant).unwrap();
        assert_eq!(store.status(&identity, GrantRole::Init).unwrap(), receipt);
        assert!(
            !serde_json::to_string(&receipt)
                .unwrap()
                .contains("never-return-this")
        );
        let metadata = fs::metadata(store.path(GrantRole::Init, "json")).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert!(store.publish(&identity, GrantRole::Init, &grant).is_err());
        assert_eq!(store.status(&identity, GrantRole::Init).unwrap(), receipt);
    }

    #[test]
    fn interrupted_delivery_is_observable_but_never_replayed() {
        let (_directory, store, identity, grant) = fixture();
        let receipt = GrantStatus {
            identity: identity.clone(),
            role: GrantRole::Init,
            issued: true,
            grant_hash: Some(grant_hash(&grant)),
        };
        store
            .write_once(
                &store.path(GrantRole::Init, "issued"),
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();
        let status = store.status(&identity, GrantRole::Init).unwrap();
        assert!(status.issued);
        assert_eq!(status.grant_hash, None);
        assert!(store.publish(&identity, GrantRole::Init, &grant).is_err());
        assert!(!store.path(GrantRole::Init, "json").exists());
    }

    #[test]
    fn wrong_resource_allocation_and_unsafe_files_are_rejected() {
        let (_directory, store, identity, grant) = fixture();
        let mut wrong = identity.clone();
        wrong.pod_uid = Uuid::from_u128(9);
        assert!(store.publish(&wrong, GrantRole::Init, &grant).is_err());
        wrong = identity.clone();
        wrong.allocation_id = Uuid::from_u128(9);
        assert!(store.publish(&wrong, GrantRole::Init, &grant).is_err());
        assert!(!store.path(GrantRole::Init, "issued").exists());
        store.publish(&identity, GrantRole::Init, &grant).unwrap();
        let path = store.path(GrantRole::Init, "json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        assert!(store.status(&identity, GrantRole::Init).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(store.path(GrantRole::Init, "pending"), &path).unwrap();
        assert!(store.status(&identity, GrantRole::Init).is_err());
    }

    #[test]
    fn helper_checks_downward_identity_and_hash_before_publication() {
        let (_directory, store, identity, grant) = fixture();
        let request = GrantRequest {
            identity: identity.clone(),
            role: GrantRole::Init,
            grant_hash: Some(grant_hash(&grant)),
        };
        let input = format!("{}\n{}\n", serde_json::to_string(&request).unwrap(), grant);
        let mut output = Vec::new();
        assert!(
            exchange(
                &store,
                &mut input.as_bytes(),
                &mut output,
                &Uuid::from_u128(9).to_string(),
                false
            )
            .is_err()
        );
        assert!(output.is_empty());
        exchange(
            &store,
            &mut input.as_bytes(),
            &mut output,
            &identity.pod_uid.to_string(),
            false,
        )
        .unwrap();
        let replies: Vec<GrantStatus> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2);
        assert!(!replies[0].issued);
        assert_eq!(replies[1].grant_hash, request.grant_hash);
        let mut output = Vec::new();
        let request = format!("{}\n", serde_json::to_string(&request).unwrap());
        exchange(
            &store,
            &mut request.as_bytes(),
            &mut output,
            &identity.pod_uid.to_string(),
            true,
        )
        .unwrap();
        assert!(
            !String::from_utf8(output)
                .unwrap()
                .contains("never-return-this")
        );
    }

    #[test]
    fn wrong_hash_truncated_and_oversized_input_cannot_issue_delivery() {
        let (_directory, store, identity, grant) = fixture();
        let request = GrantRequest {
            identity: identity.clone(),
            role: GrantRole::Init,
            grant_hash: Some("0".repeat(64)),
        };
        let input = format!("{}\n{}\n", serde_json::to_string(&request).unwrap(), grant);
        let error = exchange(
            &store,
            &mut input.as_bytes(),
            &mut Vec::new(),
            &identity.pod_uid.to_string(),
            false,
        )
        .unwrap_err();
        assert!(!format!("{error:?}").contains("never-return-this"));
        assert!(!store.path(GrantRole::Init, "issued").exists());
        for input in ["{}\n".to_string(), "{}".to_string(), " ".repeat(4097)] {
            assert!(
                exchange(
                    &store,
                    &mut input.as_bytes(),
                    &mut Vec::new(),
                    &identity.pod_uid.to_string(),
                    false,
                )
                .is_err()
            );
        }
        assert!(!store.path(GrantRole::Init, "issued").exists());
    }

    #[test]
    fn competing_deliveries_cannot_replace_the_winner() {
        for different_allocation in [false, true] {
            let (_directory, store, identity, grant) = fixture();
            let mut other = identity.clone();
            if different_allocation {
                other.allocation_id = Uuid::from_u128(9);
            }
            let mut other_grant = grant.clone();
            other_grant["allocation_id"] = serde_json::json!(other.allocation_id);
            let (first, second) = std::thread::scope(|scope| {
                let first =
                    scope.spawn(|| store.publish(&identity, GrantRole::Init, &grant).is_ok());
                let second =
                    scope.spawn(|| store.publish(&other, GrantRole::Init, &other_grant).is_ok());
                (first.join().unwrap(), second.join().unwrap())
            });
            assert_ne!(first, second);
            let (winner, document) = if first {
                (&identity, &grant)
            } else {
                (&other, &other_grant)
            };
            assert_eq!(
                store.status(winner, GrantRole::Init).unwrap().grant_hash,
                Some(grant_hash(document))
            );
        }
    }

    #[test]
    fn role_releases_keep_one_allocation_and_require_publication_order() {
        let (_directory, store, identity, grant) = fixture();
        assert!(
            store
                .publish(&identity, GrantRole::Network, &grant)
                .is_err()
        );
        store.publish(&identity, GrantRole::Init, &grant).unwrap();
        assert!(
            store
                .publish(&identity, GrantRole::Process, &grant)
                .is_err()
        );
        let mut other = identity.clone();
        other.allocation_id = Uuid::from_u128(9);
        let mut other_grant = grant.clone();
        other_grant["allocation_id"] = serde_json::json!(other.allocation_id);
        assert!(
            store
                .publish(&other, GrantRole::Network, &other_grant)
                .is_err()
        );
        assert!(store.status(&other, GrantRole::Init).is_err());
        store
            .publish(&identity, GrantRole::Network, &grant)
            .unwrap();
        store
            .publish(&identity, GrantRole::Process, &grant)
            .unwrap();
    }
}
