#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
binary=${1:?usage: test-bwrap-root-startup.sh SUPERVISOR_BINARY}
fixture_root=$(mktemp -d)
fixture_image="openshell-bwrap-fixture:$(date +%s)-$$"
fixture_profile="openshell-bwrap-fixture-$$"
profile_loaded=false
cleanup() {
  if "$profile_loaded"; then sudo apparmor_parser --remove "$fixture_root/apparmor"; fi
  docker image rm "$fixture_image" >/dev/null 2>&1 || true
  rm -rf "$fixture_root"
}
trap cleanup EXIT
cp "$binary" "$fixture_root/openshell-sandbox"
chmod 755 "$fixture_root/openshell-sandbox"
cp -r e2e/fixtures/bwrap-root-startup "$fixture_root/fixture"
cp crates/openshell-supervisor-network/data/sandbox-policy.rego "$fixture_root/policy.rego"
docker build --file "$fixture_root/fixture/Dockerfile" --tag "$fixture_image" "$fixture_root"
fixture_apparmor=unconfined
if [[ -r /sys/module/apparmor/parameters/enabled ]] && grep -q Y /sys/module/apparmor/parameters/enabled; then
  # A named profile allows userns in this disposable CI container only. The
  # fixture verifies the supervisor's own Landlock/seccomp boundary on both
  # architectures. The staging node's stricter bwrap profile is tested separately.
  printf 'abi <abi/4.0>,\nprofile %s flags=(unconfined) { userns, }\n' "$fixture_profile" > "$fixture_root/apparmor"
  sudo apparmor_parser --add "$fixture_root/apparmor"
  profile_loaded=true
  fixture_apparmor=$fixture_profile
fi
docker run --rm --network none --pids-limit 512 --memory 1g \
  --security-opt seccomp=unconfined --security-opt "apparmor=$fixture_apparmor" \
  "$fixture_image"
