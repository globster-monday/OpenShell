# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Acceptance probe executed by the real root-started supervisor's agent child."""

import json
import os
import socket
import stat
from pathlib import Path

assert os.getuid() == os.geteuid() == 10001
assert os.getgid() == os.getegid() == 10001
path = "/tmp/openshell-bwrap-launcher.sock"
metadata = Path(path).stat()
assert metadata.st_uid == 10001
assert metadata.st_gid == 10001
assert stat.S_IMODE(metadata.st_mode) == 0o600
code = """import json, os, socket
assert os.getuid() != 0
assert not os.path.exists('/fixture')
assert not os.path.exists('/sandbox')
assert 'INLINE_CODE_TEST_CANARY' not in os.environ
try:
    socket.create_connection(('1.1.1.1', 443), timeout=0.2)
except OSError:
    pass
else:
    raise AssertionError('network access escaped')
print(json.dumps({'total': sum([1, 2, 3])}))
"""
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(10)
    client.connect(path)
    client.sendall(json.dumps({"protocol_version": 1, "code": code}).encode() + b"\n")
    result = json.loads(client.makefile("rb").readline(2 * 1024 * 1024))
assert result["status"] == "succeeded", result
assert result["exit_code"] == 0, result
assert json.loads(result["stdout"]) == {"total": 6}, result
print(
    json.dumps(
        {
            "root_started_supervisor": "passed",
            "agent_uid": os.getuid(),
            "bubblewrap_output": {"total": 6},
        }
    )
)
