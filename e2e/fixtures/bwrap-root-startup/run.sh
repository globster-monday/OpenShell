#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
exec /app/.venv/bin/python /fixture/probe.py > /tmp/bwrap-root-probe.log 2>&1
