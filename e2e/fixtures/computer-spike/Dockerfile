# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap chromium libreoffice-writer fonts-dejavu libseccomp2 apparmor-utils time nodejs git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir python-docx \
    && groupadd -g 10001 assistant && useradd -u 10001 -g 10001 assistant \
    && install -d -m 0700 -o 10001 -g 10001 /probe-root
COPY . /fixture
ENTRYPOINT ["python", "/fixture/probe.py"]
