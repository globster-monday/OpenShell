# Globster downstream release

The fork's `main` branch mirrors `NVIDIA/OpenShell`. Downstream release
branches contain only the patches required while an upstream change is
pending.

Current release:

- Upstream base: `v0.0.91`
- Downstream branch: `codex/workspace-storage-class-v0.0.91`
- Upstream patch: `NVIDIA/OpenShell#2463`
- Image: `crglobsterglobal.azurecr.io/openshell/gateway:0.0.91-globster.1`

Publish the AMD64 gateway with the `Globster Gateway Release` GitHub Actions
workflow. The workflow compiles the gateway with a persistent BuildKit cache,
authenticates to Azure through workload identity federation, pushes immutable
version and commit tags to ACR, and records the resulting image digest.

Direct ACR quick builds are not the release path: the default two-CPU worker
cannot complete a cold OpenShell build reliably within a short feedback loop.

For a new upstream release, create a new branch from its signed release tag,
reapply only the still-unmerged downstream commits, update the two version
arguments in the Dockerfile, and publish a new immutable image tag. When the
upstream release contains the StorageClass feature, return Flux to the
official gateway image and retire this downstream image.
