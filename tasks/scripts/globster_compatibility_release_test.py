# SPDX-FileCopyrightText: Copyright (c) 2026 Globster. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import globster_compatibility_release as release

GATEWAY_DIGEST = "sha256:" + "a" * 64
SUPERVISOR_DIGEST = "sha256:" + "b" * 64
CHART_DIGEST = "sha256:" + "c" * 64


def _package(chart: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz") as output:
        output.add(chart, arcname="helm-chart")


class CompatibilityReleaseTest(unittest.TestCase):
    def test_plan_pins_the_validated_compatibility_members(self) -> None:
        plan = release.plan()

        self.assertEqual(
            plan["source"],
            {
                "repository": "globster-monday/OpenShell",
                "commit": "26722e6901ed59bbbf6302770fa0994eff258d04",
                "tree": "f1e56a5c0ca106a884216e7be57e1568944a71c2",
            },
        )
        self.assertEqual(plan["openshellVersion"], "0.0.92")
        self.assertEqual(plan["cargoVersion"], "0.0.92-globster.5")
        self.assertEqual(plan["artifactTag"], "0.0.92-resident-26722e69")
        self.assertEqual(plan["chartVersion"], "0.0.92-globster.6")
        self.assertEqual(plan["platforms"], ["linux/amd64", "linux/arm64"])
        self.assertEqual(
            plan["agentSandbox"],
            {
                "version": "0.5.3",
                "manifestSha256": (
                    "50f54b0e746376455ae6bb8b90b436bdd8798e1296cff0d72b6267bbeb858e3c"
                ),
                "controllerImage": (
                    "registry.k8s.io/agent-sandbox/agent-sandbox-controller"
                    "@sha256:ba381b4e0c86cca597d5c5a31860e38d30ec1c45e0a7a8328bb2799c87d059c0"
                ),
            },
        )

    def test_verifies_both_the_reviewed_source_commit_and_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "source"
            repository.mkdir()
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Test"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            (repository / "reviewed").write_text("source\n")
            subprocess.run(
                ["git", "-C", str(repository), "add", "reviewed"], check=True
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "reviewed"],
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
            ).strip()
            tree = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
                text=True,
            ).strip()

            with (
                mock.patch.object(release, "SOURCE_COMMIT", commit),
                mock.patch.object(release, "SOURCE_TREE", tree),
            ):
                release.verify_source(repository)
            with (
                mock.patch.object(release, "SOURCE_COMMIT", "0" * 40),
                self.assertRaisesRegex(
                    release.CompatibilityReleaseError, "source commit"
                ),
            ):
                release.verify_source(repository)
            with (
                mock.patch.object(release, "SOURCE_COMMIT", commit),
                mock.patch.object(release, "SOURCE_TREE", "0" * 40),
                self.assertRaisesRegex(
                    release.CompatibilityReleaseError, "source tree"
                ),
            ):
                release.verify_source(repository)

    def test_renders_and_verifies_the_exact_digest_pinned_chart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            repository = Path(__file__).resolve().parents[2]
            chart = temporary / "chart"
            release.render_chart(repository, chart, GATEWAY_DIGEST, SUPERVISOR_DIGEST)
            archive = temporary / "helm-chart.tgz"
            _package(chart, archive)

            self.assertEqual(
                release.verify_chart(archive),
                release.receipt(GATEWAY_DIGEST, SUPERVISOR_DIGEST),
            )
            values = (chart / "values.yaml").read_text()
            self.assertIn(f'tag: "{release.ARTIFACT_TAG}@{GATEWAY_DIGEST}"', values)
            self.assertIn(f'tag: "{release.ARTIFACT_TAG}@{SUPERVISOR_DIGEST}"', values)

    def test_rejects_tampered_receipt_and_mutable_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            repository = Path(__file__).resolve().parents[2]
            chart = temporary / "chart"
            release.render_chart(repository, chart, GATEWAY_DIGEST, SUPERVISOR_DIGEST)
            embedded_path = chart / "globster-compatibility.json"
            embedded = json.loads(embedded_path.read_text())
            embedded["source"]["commit"] = "0" * 40
            embedded_path.write_text(json.dumps(embedded))
            archive = temporary / "tampered.tgz"
            _package(chart, archive)

            with self.assertRaisesRegex(
                release.CompatibilityReleaseError, "release plan"
            ):
                release.verify_chart(archive)
            with self.assertRaisesRegex(
                release.CompatibilityReleaseError, "immutable sha256"
            ):
                release.receipt("latest", SUPERVISOR_DIGEST)

    def test_outer_receipt_adds_only_the_verified_chart_digest(self) -> None:
        embedded = release.receipt(GATEWAY_DIGEST, SUPERVISOR_DIGEST)
        published = release.receipt(GATEWAY_DIGEST, SUPERVISOR_DIGEST, CHART_DIGEST)

        self.assertNotIn("digest", embedded["artifacts"]["chart"])
        self.assertEqual(published["artifacts"]["chart"]["digest"], CHART_DIGEST)
        self.assertEqual(
            published["source"],
            {
                "repository": "globster-monday/OpenShell",
                "commit": release.SOURCE_COMMIT,
                "tree": release.SOURCE_TREE,
            },
        )

    def test_rejects_an_unsafe_chart_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.tgz"
            payload = Path(directory) / "payload"
            payload.write_text("unsafe\n")
            with tarfile.open(archive, "w:gz") as output:
                output.add(payload, arcname="../payload")

            with self.assertRaisesRegex(
                release.CompatibilityReleaseError, "unsafe path"
            ):
                release.verify_chart(archive)

    def test_workflow_is_exact_idempotent_and_clean_client_verified(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        workflow = (
            repository / ".github/workflows/globster-maintained-images.yml"
        ).read_text()

        self.assertIn(release.SOURCE_COMMIT, workflow)
        self.assertIn(release.ARTIFACT_TAG, workflow)
        self.assertIn(release.CHART_VERSION, workflow)
        self.assertIn("state=conflict", workflow)
        self.assertIn("needs.preflight.outputs.state == 'publish'", workflow)
        self.assertIn('elif [[ "$published" -eq "${#states[@]}" ]]; then', workflow)
        self.assertIn("ref: ${{ github.workflow_sha }}", workflow)
        self.assertIn("--repository .release-source", workflow)
        self.assertIn("$ARTIFACT_TAG-amd64", workflow)
        self.assertIn("$ARTIFACT_TAG-arm64", workflow)
        self.assertIn("Unable to determine publication state", workflow)
        self.assertIn(
            "Unable to determine compatibility chart publication state", workflow
        )
        self.assertEqual(workflow.count("printf false"), 2)
        self.assertEqual(workflow.count("printf error"), 2)
        image_probe = workflow.split("probe_image() {", 1)[1].split(
            "probe_chart() {", 1
        )[0]
        chart_probe = workflow.split("probe_chart() {", 1)[1].split("states=(", 1)[0]
        for probe in (image_probe, chart_probe):
            self.assertIn(
                "elif grep -Eqi "
                "'(: not found|404 Not Found|manifest unknown|name unknown)"
                "([[:space:]]|$)' "
                '<<<"$output"; then\n              printf false\n            else',
                probe,
            )
            self.assertIn("printf error", probe)
        self.assertIn('case "$state" in', workflow)
        self.assertIn("Compatibility publication state could not be verified", workflow)
        self.assertGreaterEqual(workflow.count("timeout 60s"), 3)
        self.assertNotIn(">/dev/null 2>&1 && gateway=true", workflow)
        self.assertNotIn(
            'helm show chart "$CHART_REPOSITORY" --version "$CHART_VERSION" >/dev/null 2>&1',
            workflow,
        )
        self.assertIn("helm pull", workflow)
        self.assertIn("imagetools inspect", workflow)
        self.assertIn('sort == ["linux/amd64", "linux/arm64"]', workflow)
        self.assertIn("actions/attest@", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn("push-to-registry: true", workflow)
        self.assertIn("compatibility-publication-receipt", workflow)
        self.assertNotIn(":latest", workflow)
        self.assertNotIn("checkout-ref: 58e11af2", workflow)

    def test_mirror_merge_base_supports_slash_base_refs(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        action = (repository / ".github/actions/pr-merge-base/action.yml").read_text()
        helm_workflow = (repository / ".github/workflows/helm-lint.yml").read_text()

        self.assertIn('base_remote_ref="refs/remotes/origin/$base_ref"', action)
        self.assertIn(
            'git fetch --no-tags origin "+refs/heads/$base_ref:$base_remote_ref"',
            action,
        )
        self.assertIn(
            'base_sha=$(git merge-base "$base_remote_ref" "$GITHUB_SHA_VALUE")',
            action,
        )
        self.assertNotIn("compare/$base_ref", action)
        checkout = helm_workflow.split("- id: merge-base", 1)[0].rsplit(
            "- uses: actions/checkout@", 1
        )[1]
        self.assertIn("fetch-depth: 0", checkout)

    def test_required_fork_checks_use_available_hosted_runners(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        required_workflows = "\n".join(
            (repository / path).read_text()
            for path in (
                ".github/workflows/branch-checks.yml",
                ".github/workflows/helm-lint.yml",
            )
        )

        self.assertNotIn("linux-amd64-cpu8", required_workflows)
        self.assertNotIn("linux-arm64-cpu8", required_workflows)
        self.assertNotIn("ghcr.io/nvidia/openshell/ci:latest", required_workflows)
        self.assertIn("ubuntu-24.04", required_workflows)
        self.assertIn("ubuntu-24.04-arm", required_workflows)
        self.assertEqual(
            required_workflows.count(
                "jdx/mise-action@3c2e0cf82a5b2e5249f0d3635a4d83d0ae861518"
            ),
            6,
        )
        self.assertEqual(required_workflows.count("version: 2026.4.25"), 6)
        self.assertIn(
            "rustup component add rustfmt rust-src rust-analyzer clippy",
            required_workflows,
        )


if __name__ == "__main__":
    unittest.main()
