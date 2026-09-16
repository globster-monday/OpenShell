# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
RUN apt-get update \
    && apt-get install --yes --no-install-recommends bubblewrap iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /app/.venv \
    && groupadd --gid 10001 agent \
    && useradd --uid 10001 --gid 10001 --no-create-home agent \
    && install -d -o 10001 -g 10001 /sandbox
COPY openshell-sandbox /openshell-sandbox
COPY fixture /fixture
COPY policy.rego /fixture-policy.rego
ENV OPENSHELL_EXPERIMENTAL_BWRAP_LAUNCHER=1 INLINE_CODE_TEST_CANARY=nonsecret-fixture-canary
CMD ["/bin/sh", "-c", "/openshell-sandbox --mode process --policy-rules /fixture-policy.rego --policy-data /fixture/policy.yaml -- /bin/sh /fixture/run.sh; result=$?; cat /tmp/bwrap-root-probe.log; exit $result"]
