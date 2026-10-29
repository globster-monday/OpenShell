// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retained-pod workspace initialization, before any supervisor or tenant process.
//!
//! The root gate holds the pod-private writer lock. This subprocess drops to the
//! workload identity and receives its bounded plan on stdin, never in environment
//! variables or process arguments. It does not execute recipe-provided code.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::binding_gate::BoundLaunchGrant;

pub const SUBCOMMAND: &str = "initialize-bound-workspace";
pub const WORKLOAD_UID: u32 = 1000;
pub const WORKLOAD_GID: u32 = 1000;
pub(crate) const MAX_PLAN_BYTES: u64 = 1024 * 1024;
pub(crate) const RECIPE_PATH: &str = "/recipe/template";
pub(crate) const WORKSPACE_PATH: &str = "/workspace";
const MARKER_NAME: &str = ".globster-recipe.json";
const CONFIG_NAME: &str = "initial-plugin-config.json";
const STORAGE_DIRECTORY: &str = "workspace";
const PERSISTENCE_DIRECTORY: &str = ".globster-openshell-persist";
const MAX_CONFIGURATION_BYTES: usize = 65_536;
const MAX_RECIPE_ENTRIES: u64 = 100_000;
const MAX_RECIPE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECIPE_DEPTH: usize = 64;
const STATE_MOUNT: &str = openshell_core::prewarm_grant::STATE_PATH;
const STATE_DIRECTORY: &str = openshell_core::prewarm_grant::PRIVATE_DIRECTORY;
const RECEIPT_FILE: &str = "initialized.json";
const PENDING_RECEIPT_FILE: &str = "initialized.pending";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InitializationReceipt {
    version: u32,
    slot_id: Uuid,
    generation: u64,
    pod_uid: Uuid,
    sandbox_id: Uuid,
    allocation_id: Uuid,
    recipe: RecipeMarker,
}

/// Trusted owner-supplied recipe intent. Paths and workload UID are not inputs.
///
/// `initial_configuration_json` is the gateway's canonical UTF-8 serialization.
/// Preserve those exact bytes so its marker digest agrees with cold creation,
/// including JSON number formatting. Do not round-trip it through serde.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInitialization {
    pub recipe_id: String,
    pub recipe_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_configuration_json: Option<String>,
}

// This type deliberately does not implement Debug: configuration can be secret.

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitializationPlan {
    pub workload_id: Uuid,
    pub initialization: WorkspaceInitialization,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecipeMarker {
    pub schema_version: u32,
    pub id: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_configuration_digest: Option<String>,
}

impl WorkspaceInitialization {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.recipe_id.is_empty()
            || self.recipe_id.len() > 253
            || self.recipe_id.chars().any(char::is_control)
            || !valid_digest(&self.recipe_digest)
        {
            return Err(miette::miette!("invalid bound recipe identity"));
        }
        if let Some(json) = &self.initial_configuration_json {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase", deny_unknown_fields)]
            struct Configuration {
                schema_version: u32,
                plugins: std::collections::BTreeMap<
                    String,
                    std::collections::BTreeMap<String, serde_json::Value>,
                >,
            }
            if json.len() > MAX_CONFIGURATION_BYTES {
                return Err(miette::miette!("bound initial configuration exceeds limit"));
            }
            let configuration: Configuration = serde_json::from_str(json)
                .map_err(|_| miette::miette!("invalid bound initial configuration"))?;
            if configuration.schema_version != 1 {
                return Err(miette::miette!("invalid bound initial configuration"));
            }
            // Deserialize the complete shape, not merely schemaVersion.
            let _ = configuration.plugins;
        }
        Ok(())
    }

    pub(crate) fn marker(&self) -> RecipeMarker {
        RecipeMarker {
            schema_version: 1,
            id: self.recipe_id.clone(),
            digest: self.recipe_digest.clone(),
            initial_configuration_digest: self
                .initial_configuration_json
                .as_ref()
                .map(|json| format!("{:x}", Sha256::digest(json.as_bytes()))),
        }
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[allow(unsafe_code)] // Linux flock, with a borrowed live File descriptor.
fn lock_writer(directory: &Path) -> Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    ensure_private_directory(directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join("writer.lock"))
        .into_diagnostic()?;
    let metadata = lock.metadata().into_diagnostic()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(miette::miette!("bound workspace writer lock is unsafe"));
    }
    // SAFETY: flock borrows a live file descriptor and has no pointer arguments.
    if unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } != 0 {
        return Err(miette::miette!("bound workspace writer is already active"));
    }
    Ok(lock)
}

#[allow(unsafe_code)] // Linux statvfs; no portable std equivalent exposes mount flags.
fn require_read_only_recipe_mount() -> Result<()> {
    let path = std::ffi::CString::new(RECIPE_PATH).into_diagnostic()?;
    let mut stat = std::mem::MaybeUninit::<nix::libc::statvfs>::uninit();
    // SAFETY: the path is NUL-terminated and stat points to valid writable space.
    if unsafe { nix::libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(miette::miette!("bound recipe mount is unavailable"));
    }
    // SAFETY: successful statvfs initialized the output above.
    let stat = unsafe { stat.assume_init() };
    if stat.f_flag & nix::libc::ST_RDONLY == 0 {
        return Err(miette::miette!("bound recipe mount must be read-only"));
    }
    Ok(())
}

fn read_receipt(path: &Path) -> Result<Option<InitializationReceipt>> {
    use std::os::unix::fs::MetadataExt;

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).into_diagnostic(),
    };
    let metadata = file.metadata().into_diagnostic()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_PLAN_BYTES
    {
        return Err(miette::miette!("bound initialization receipt is unsafe"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err(miette::miette!(
            "bound initialization receipt exceeds limit"
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| miette::miette!("invalid bound initialization receipt"))
}

/// CSI filesystems initially belong to root. Change only the blank mount root,
/// after allocation, before the sole unprivileged writer. Never recursively
/// chown an existing workspace or seed a directory during prepare.
pub(crate) fn prepare_blank_claim() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(WORKSPACE_PATH);
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    if !metadata.is_dir() {
        return Err(miette::miette!("bound workspace must be a directory"));
    }
    if metadata.uid() == WORKLOAD_UID && metadata.gid() == WORKLOAD_GID {
        return Ok(());
    }
    if metadata.uid() != 0 || !blank_claim(path)? {
        return Err(miette::miette!("prepared workspace is not blank"));
    }
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(WORKLOAD_UID)),
        Some(nix::unistd::Gid::from_raw(WORKLOAD_GID)),
    )
    .into_diagnostic()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).into_diagnostic()
}

fn blank_claim(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    for entry in fs::read_dir(path).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let metadata = fs::symlink_metadata(entry.path()).into_diagnostic()?;
        // A newly formatted ext filesystem may contain its empty recovery
        // directory. It is filesystem metadata, never a recipe or tenant seed.
        if entry.file_name() != "lost+found"
            || !metadata.is_dir()
            || metadata.uid() != 0
            || fs::read_dir(entry.path())
                .into_diagnostic()?
                .next()
                .is_some()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn verify_prepared_blank(identity: &serde_json::Value) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let state = Path::new(STATE_MOUNT);
    let metadata = fs::symlink_metadata(state).into_diagnostic()?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        return Err(miette::miette!("prepared binding state is unsafe"));
    }
    // Kubelet creates emptyDir with mode 0777. Only the inert root init can
    // establish this private directory, and only while it is completely empty.
    if metadata.mode() & 0o022 != 0 {
        if fs::read_dir(state).into_diagnostic()?.next().is_some() {
            return Err(miette::miette!(
                "nonprivate prepared binding state is not empty"
            ));
        }
        fs::set_permissions(state, fs::Permissions::from_mode(0o700)).into_diagnostic()?;
        sync_directory(state)?;
    }
    let directory = state.join(STATE_DIRECTORY);
    let _lock = lock_writer(&directory)?;
    let path = directory.join(openshell_core::prewarm_grant::PREPARED_RECEIPT);
    let bytes = serde_json::to_vec(identity).into_diagnostic()?;
    if path.exists() {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .into_diagnostic()?;
        let metadata = file.metadata().into_diagnostic()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > 4096
        {
            return Err(miette::miette!("prepared blank receipt is unsafe"));
        }
        let mut actual = Vec::new();
        file.take(4097).read_to_end(&mut actual).into_diagnostic()?;
        if actual != bytes {
            return Err(miette::miette!("prepared blank receipt identity mismatch"));
        }
        return Ok(());
    }
    if !blank_claim(Path::new(WORKSPACE_PATH))? {
        return Err(miette::miette!("prepared workspace contains existing data"));
    }
    write_private_file(&path, &bytes)?;
    sync_directory(&directory)
}

/// Return the exclusive writer lock after successful initialization, to keep it
/// held through the root gate's exec into the supervisor. This is a pod-local
/// single-writer guarantee, not a resource-side allocation or retirement fence.
pub(crate) fn initialize_retained_pod(
    grant: &BoundLaunchGrant,
    deadline: std::time::Instant,
) -> Result<Option<File>> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let Some(initialization) = &grant.workspace_initialization else {
        return Ok(None);
    };
    if !nix::unistd::geteuid().is_root() {
        return Err(miette::miette!(
            "bound initialization requires the root gate"
        ));
    }
    initialization.validate()?;
    require_read_only_recipe_mount()?;
    let state_mount = Path::new(STATE_MOUNT);
    let metadata = fs::symlink_metadata(state_mount).into_diagnostic()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(miette::miette!(
            "bound initialization state mount is unsafe"
        ));
    }
    let state_directory = state_mount.join(STATE_DIRECTORY);
    let writer = lock_writer(&state_directory)?;
    let receipt = InitializationReceipt {
        version: 1,
        slot_id: grant.slot_id,
        generation: grant.generation,
        pod_uid: grant.pod_uid,
        sandbox_id: grant.sandbox_id,
        allocation_id: grant.allocation_id,
        recipe: initialization.marker(),
    };
    let existing = read_receipt(&state_directory.join(RECEIPT_FILE))?;
    if existing
        .as_ref()
        .is_some_and(|existing| existing != &receipt)
    {
        return Err(miette::miette!(
            "bound initialization receipt does not match allocation"
        ));
    }
    let plan = serde_json::to_vec(&InitializationPlan {
        workload_id: grant.sandbox_id,
        initialization: initialization.clone(),
    })
    .into_diagnostic()?;
    if plan.len() as u64 > MAX_PLAN_BYTES {
        return Err(miette::miette!("bound workspace plan exceeds limit"));
    }
    let mut child = Command::new(std::env::current_exe().into_diagnostic()?)
        .arg(SUBCOMMAND)
        .env_clear()
        .current_dir("/")
        .gid(WORKLOAD_GID)
        .uid(WORKLOAD_UID)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .into_diagnostic()?;
    // Do not leave a detached initializer if feeding stdin fails.
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| miette::miette!("bound workspace initializer input is unavailable"))
        .and_then(|mut stdin| stdin.write_all(&plan).into_diagnostic());
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(miette::miette!("bound workspace initialization failed"));
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err(miette::miette!("bound workspace initialization failed")),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(miette::miette!("bound workspace initialization failed"));
            }
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(miette::miette!(
                "bound workspace initialization deadline exceeded"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if std::time::Instant::now() >= deadline {
        return Err(miette::miette!(
            "bound workspace initialization deadline exceeded"
        ));
    }
    if existing.is_none() {
        let pending = state_directory.join(PENDING_RECEIPT_FILE);
        // A killed gate may have left its own incomplete receipt, never tenant
        // state. Validate its inode before removing it under the writer lock.
        match fs::symlink_metadata(&pending) {
            Ok(metadata) if metadata.is_file() => {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.permissions().mode() & 0o7777 != 0o600 {
                    return Err(miette::miette!("pending initialization receipt is unsafe"));
                }
                fs::remove_file(&pending).into_diagnostic()?;
            }
            Ok(_) => return Err(miette::miette!("pending initialization receipt is unsafe")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).into_diagnostic(),
        }
        write_private_file(&pending, &serde_json::to_vec(&receipt).into_diagnostic()?)?;
        publish(&pending, &state_directory.join(RECEIPT_FILE))?;
        sync_directory(&state_directory)?;
    }
    Ok(Some(writer))
}

/// Internal child entrypoint. The root gate is the only supported orchestrator.
pub fn run() -> Result<()> {
    if nix::unistd::geteuid().as_raw() != WORKLOAD_UID
        || nix::unistd::getegid().as_raw() != WORKLOAD_GID
    {
        return Err(miette::miette!(
            "bound workspace initializer requires the workload identity"
        ));
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err(miette::miette!("bound workspace plan exceeds limit"));
    }
    let plan: InitializationPlan = serde_json::from_slice(&bytes)
        .map_err(|_| miette::miette!("invalid bound workspace plan"))?;
    initialize(&plan, Path::new(RECIPE_PATH), Path::new(WORKSPACE_PATH))
}

fn ensure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(miette::miette!("bound workspace directory is unsafe"));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .into_diagnostic()
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !path.try_exists().into_diagnostic()? {
        create_private_directory(path)?;
    }
    ensure_directory(path)?;
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o700 != 0o700
    {
        return Err(miette::miette!(
            "bound workspace directory permissions are unsafe"
        ));
    }
    Ok(())
}

fn ensure_workload_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !path.try_exists().into_diagnostic()? {
        create_private_directory(path)?;
    }
    ensure_directory(path)?;
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o300 != 0o300
    {
        return Err(miette::miette!("bound workload directory is not writable"));
    }
    Ok(())
}

fn ensure_persistence_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    ensure_workload_directory(path)?;
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    let mode = metadata.permissions().mode();
    if mode & 0o007 != 0 || (mode & 0o070 != 0 && metadata.gid() != nix::unistd::getegid().as_raw())
    {
        return Err(miette::miette!(
            "bound persistence directory permissions are unsafe"
        ));
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .into_diagnostic()?;
    file.write_all(bytes).into_diagnostic()?;
    file.sync_all().into_diagnostic()
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .into_diagnostic()?
        .sync_all()
        .into_diagnostic()
}

/// Use Linux's no-replace rename so an unexpected existing destination can never
/// be overwritten, even if it is an empty directory.
#[allow(unsafe_code)] // Linux no-replace rename is the publication safety boundary.
fn publish(staging: &Path, destination: &Path) -> Result<()> {
    let staging = std::ffi::CString::new(staging.as_os_str().as_bytes()).into_diagnostic()?;
    let destination =
        std::ffi::CString::new(destination.as_os_str().as_bytes()).into_diagnostic()?;
    // SAFETY: both paths are live NUL-terminated strings; no borrowed FDs.
    let result = unsafe {
        nix::libc::renameat2(
            nix::libc::AT_FDCWD,
            staging.as_ptr(),
            nix::libc::AT_FDCWD,
            destination.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    Ok(())
}

#[derive(Default)]
struct CopyBudget {
    entries: u64,
    bytes: u64,
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    budget: &mut CopyBudget,
    depth: usize,
) -> Result<()> {
    if depth > MAX_RECIPE_DEPTH {
        return Err(miette::miette!("bound recipe exceeds nesting limit"));
    }
    ensure_directory(source)?;
    create_private_directory(destination)?;
    for entry in fs::read_dir(source).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&from).into_diagnostic()?;
        budget.entries += 1;
        budget.bytes = budget.bytes.saturating_add(metadata.len());
        if budget.entries > MAX_RECIPE_ENTRIES || budget.bytes > MAX_RECIPE_BYTES {
            return Err(miette::miette!("bound recipe exceeds copy limit"));
        }
        if metadata.is_dir() {
            copy_tree(&from, &to, budget, depth + 1)?;
        } else if metadata.is_file() {
            // Source is the approved read-only recipe mount, never a tenant path.
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&from)
                .into_diagnostic()?;
            let mode = 0o600 | (metadata.permissions().mode() & 0o100);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&to)
                .into_diagnostic()?;
            let copied = std::io::copy(&mut input, &mut output).into_diagnostic()?;
            if copied != metadata.len() {
                return Err(miette::miette!("bound recipe changed during copy"));
            }
            output.sync_all().into_diagnostic()?;
        } else {
            return Err(miette::miette!(
                "bound recipe contains a link or special file"
            ));
        }
    }
    sync_directory(destination)
}

fn read_marker(path: &Path) -> Result<RecipeMarker> {
    use std::os::unix::fs::MetadataExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .into_diagnostic()?;
    let metadata = file.metadata().into_diagnostic()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_PLAN_BYTES
    {
        return Err(miette::miette!("bound recipe marker is unsafe"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err(miette::miette!("bound recipe marker exceeds limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| miette::miette!("invalid bound recipe marker"))
}

fn initialize(plan: &InitializationPlan, source: &Path, workspace: &Path) -> Result<()> {
    plan.initialization.validate()?;
    if plan.workload_id.is_nil() {
        return Err(miette::miette!("invalid bound workspace identity"));
    }
    ensure_directory(workspace)?;
    ensure_directory(source)?;
    for reserved in [PERSISTENCE_DIRECTORY, MARKER_NAME, CONFIG_NAME] {
        if fs::symlink_metadata(source.join(reserved)).is_ok() {
            return Err(miette::miette!("bound recipe contains reserved state"));
        }
    }
    let destination = workspace.join(plan.workload_id.to_string());
    let expected = plan.initialization.marker();
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            ensure_workload_directory(&destination)?;
            if read_marker(&destination.join(MARKER_NAME))? != expected {
                return Err(miette::miette!("bound workspace contains different state"));
            }
            ensure_workload_directory(&destination.join(STORAGE_DIRECTORY))?;
            ensure_persistence_directory(&destination.join(PERSISTENCE_DIRECTORY))?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).into_diagnostic(),
    }

    let staging = workspace.join(format!(".globster-recipe-{}", plan.workload_id));
    match fs::symlink_metadata(&staging) {
        Ok(_) => {
            ensure_private_directory(&staging)?;
            fs::remove_dir_all(&staging).into_diagnostic()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).into_diagnostic(),
    }
    // A crash leaves only this private staging directory. The published
    // destination is never repaired or overwritten when its marker differs.
    copy_tree(source, &staging, &mut CopyBudget::default(), 0)?;
    ensure_workload_directory(&staging.join(STORAGE_DIRECTORY))?;
    ensure_persistence_directory(&staging.join(PERSISTENCE_DIRECTORY))?;
    if let Some(configuration) = &plan.initialization.initial_configuration_json {
        write_private_file(
            &staging.join(CONFIG_NAME),
            format!("{configuration}\n").as_bytes(),
        )?;
    }
    let marker = serde_json::to_vec(&expected).into_diagnostic()?;
    write_private_file(&staging.join(MARKER_NAME), &marker)?;
    sync_directory(&staging)?;
    publish(&staging, &destination)?;
    sync_directory(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, InitializationPlan) {
        let root = tempfile::Builder::new()
            .prefix(".binding-workspace-test-")
            .tempdir_in(".")
            .unwrap();
        fs::create_dir(root.path().join("recipe")).unwrap();
        fs::create_dir(root.path().join("workspace")).unwrap();
        fs::write(root.path().join("recipe/template.txt"), "approved recipe").unwrap();
        let plan = InitializationPlan {
            workload_id: Uuid::from_u128(7),
            initialization: WorkspaceInitialization {
                recipe_id: "base-agent".into(),
                recipe_digest: format!("sha256:{}", "a".repeat(64)),
                initial_configuration_json: Some(
                    r#"{"plugins":{"example":{"n":1e+21}},"schemaVersion":1}"#.into(),
                ),
            },
        };
        (root, plan)
    }

    fn apply(root: &Path, plan: &InitializationPlan) -> Result<()> {
        initialize(plan, &root.join("recipe"), &root.join("workspace"))
    }

    #[test]
    fn initializes_once_with_exact_configuration_bytes_and_cold_compatible_marker() {
        let (root, plan) = fixture();
        apply(root.path(), &plan).unwrap();
        let destination = root
            .path()
            .join("workspace")
            .join(plan.workload_id.to_string());
        assert_eq!(
            fs::read_to_string(destination.join("template.txt")).unwrap(),
            "approved recipe"
        );
        let configuration = plan
            .initialization
            .initial_configuration_json
            .as_ref()
            .unwrap();
        assert_eq!(
            fs::read_to_string(destination.join(CONFIG_NAME)).unwrap(),
            format!("{configuration}\n")
        );
        let marker: serde_json::Value =
            serde_json::from_slice(&fs::read(destination.join(MARKER_NAME)).unwrap()).unwrap();
        assert_eq!(marker["schemaVersion"], 1);
        assert_eq!(marker["id"], "base-agent");
        assert_eq!(
            marker["initialConfigurationDigest"],
            format!("{:x}", Sha256::digest(configuration.as_bytes()))
        );
        fs::write(destination.join("template.txt"), "tenant data").unwrap();
        apply(root.path(), &plan).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("template.txt")).unwrap(),
            "tenant data"
        );
        for name in [STORAGE_DIRECTORY, PERSISTENCE_DIRECTORY] {
            assert_eq!(
                fs::metadata(destination.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn refuses_different_recipe_or_initial_configuration_without_overwriting_data() {
        let (root, mut plan) = fixture();
        apply(root.path(), &plan).unwrap();
        plan.initialization.recipe_digest = format!("sha256:{}", "b".repeat(64));
        assert!(apply(root.path(), &plan).is_err());
        plan.initialization.recipe_digest = format!("sha256:{}", "a".repeat(64));
        plan.initialization.initial_configuration_json = None;
        assert!(apply(root.path(), &plan).is_err());
    }

    #[test]
    fn retry_preserves_ordinary_group_private_persistence_and_rejects_world_access() {
        let (root, plan) = fixture();
        apply(root.path(), &plan).unwrap();
        let persistence = root
            .path()
            .join("workspace")
            .join(plan.workload_id.to_string())
            .join(PERSISTENCE_DIRECTORY);
        fs::set_permissions(&persistence, fs::Permissions::from_mode(0o770)).unwrap();
        apply(root.path(), &plan).unwrap();
        assert_eq!(
            fs::metadata(&persistence).unwrap().permissions().mode() & 0o777,
            0o770
        );
        fs::set_permissions(&persistence, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(apply(root.path(), &plan).is_err());
    }

    #[test]
    fn rejects_source_links_reserved_state_and_unsafe_existing_workspace() {
        let (root, plan) = fixture();
        let source = root.path().join("recipe");
        symlink("../workspace", source.join("escape")).unwrap();
        assert!(apply(root.path(), &plan).is_err());
        fs::remove_file(source.join("escape")).unwrap();
        fs::write(source.join(PERSISTENCE_DIRECTORY), "reserved").unwrap();
        assert!(apply(root.path(), &plan).is_err());
        fs::remove_file(source.join(PERSISTENCE_DIRECTORY)).unwrap();
        let destination = root
            .path()
            .join("workspace")
            .join(plan.workload_id.to_string());
        symlink(&source, &destination).unwrap();
        assert!(apply(root.path(), &plan).is_err());
        assert!(!source.join(MARKER_NAME).exists());
    }

    #[test]
    fn resumes_abandoned_staging_but_never_adopts_unmarked_customer_data() {
        let (root, plan) = fixture();
        let workspace = root.path().join("workspace");
        let staging = workspace.join(format!(".globster-recipe-{}", plan.workload_id));
        create_private_directory(&staging).unwrap();
        fs::write(staging.join("partial"), "incomplete").unwrap();
        apply(root.path(), &plan).unwrap();
        assert!(!staging.exists());
        let destination = workspace.join(plan.workload_id.to_string());
        fs::remove_file(destination.join(MARKER_NAME)).unwrap();
        assert!(apply(root.path(), &plan).is_err());
        assert!(destination.join("template.txt").exists());
    }

    #[test]
    fn rejects_oversized_or_malformed_configuration_without_creating_a_destination() {
        let (root, mut plan) = fixture();
        for json in [
            format!("{}secret-value", " ".repeat(MAX_CONFIGURATION_BYTES)),
            r#"{"schemaVersion":2,"plugins":{}}"#.into(),
            r#"{"schemaVersion":1,"plugins":[]}"#.into(),
        ] {
            plan.initialization.initial_configuration_json = Some(json);
            let error = apply(root.path(), &plan).unwrap_err();
            assert!(!format!("{error:?}").contains("secret-value"));
        }
        assert!(
            !root
                .path()
                .join("workspace")
                .join(plan.workload_id.to_string())
                .exists()
        );
    }

    #[test]
    fn no_replace_publication_rejects_even_an_empty_destination() {
        let root = tempfile::Builder::new()
            .prefix(".binding-publish-test-")
            .tempdir_in(".")
            .unwrap();
        let staging = root.path().join("staging");
        let destination = root.path().join("destination");
        create_private_directory(&staging).unwrap();
        create_private_directory(&destination).unwrap();
        assert!(publish(&staging, &destination).is_err());
        assert!(staging.is_dir());
        assert!(destination.is_dir());
    }

    #[test]
    fn pod_private_lock_excludes_a_second_writer_and_is_recoverable_after_exit() {
        let root = tempfile::Builder::new()
            .prefix(".binding-lock-test-")
            .tempdir_in(".")
            .unwrap();
        let directory = root.path().join("state");
        let first = lock_writer(&directory).unwrap();
        assert!(lock_writer(&directory).is_err());
        drop(first);
        lock_writer(&directory).unwrap();
        fs::set_permissions(
            directory.join("writer.lock"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(lock_writer(&directory).is_err());
    }
}
