# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Confirm Chromium DevTools can use inherited pipes without a TCP listener."""

import json
import os
import select
import subprocess

read_input, write_input = os.pipe()
read_output, write_output = os.pipe()
process = subprocess.Popen(
    [
        "bash",
        "-c",
        f"exec chromium --headless=new --no-sandbox --no-zygote --disable-gpu --disable-dev-shm-usage --user-data-dir=/tmp/pipe-chrome --remote-debugging-pipe 3<&{read_input} 4>&{write_output}",
    ],
    pass_fds=(read_input, write_output),
    stdout=subprocess.DEVNULL,
)
os.close(read_input)
os.close(write_output)
try:
    os.write(
        write_input,
        json.dumps({"id": 1, "method": "Browser.getVersion"}).encode() + b"\0",
    )
    result = b""
    while b"\0" not in result:
        if not select.select([read_output], [], [], 20)[0]:
            raise TimeoutError("DevTools pipe")
        chunk = os.read(read_output, 65536)
        if not chunk:
            raise RuntimeError("DevTools pipe closed")
        result += chunk
    reply = json.loads(result.split(b"\0")[0])
    assert reply["id"] == 1 and "result" in reply, reply
    print(json.dumps({"devtools_pipe": reply["result"]["product"]}))
finally:
    os.close(write_input)
    os.close(read_output)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
