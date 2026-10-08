# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Temporary feasibility probes; never shipped as a runtime launcher."""

import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path


def output(name, **values):
    print(json.dumps({"probe": name, **values}), flush=True)


def jail(command, proc=True):
    args = [
        os.environ.get("BWRAP_BIN", "bwrap"),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "LD_LIBRARY_PATH",
        "/usr/local/lib",
        "--setenv",
        "HOME",
        "/agent",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--ro-bind",
        "/etc",
        "/etc",
        "--dev",
        "/dev",
        "--size",
        "268435456",
        "--tmpfs",
        "/dev/shm",
        "--bind",
        "/probe-root",
        "/agent",
        "--bind",
        "/probe-root/scratch",
        "/tmp",
        "--ro-bind",
        "/fixture",
        "/fixture",
    ]
    if Path("/probe-root/tools.sock").exists():
        args += ["--bind", "/probe-root/tools.sock", "/run/tools.sock"]
    if proc:
        args += ["--proc", "/proc", "--remount-ro", "/proc"]
    args += ["--chdir", "/agent", "python", "/fixture/probe.py", "child", command]
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    output(
        "jail",
        command=command,
        proc=proc,
        exit_code=result.returncode,
        stdout=result.stdout[-6000:],
        stderr=result.stderr[-2000:],
    )
    return result.returncode


def harden():
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, 0, 0, 1)
    output("landlock", abi=abi)
    if abi < 1:
        raise OSError(ctypes.get_errno(), "Landlock unavailable")
    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 1 << 13
    if abi >= 3:
        handled |= 1 << 14
    if abi >= 5:
        handled |= 1 << 15

    class Ruleset(ctypes.Structure):
        _fields_ = [("access", ctypes.c_uint64)]

    class Rule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("access", ctypes.c_uint64), ("fd", ctypes.c_int32)]

    ruleset = Ruleset(handled)
    fd = libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    read = (1 << 0) | (1 << 2) | (1 << 3)
    for path, access in [
        ("/usr", read),
        ("/etc", read),
        ("/proc", read),
        ("/fixture", read),
        ("/agent", handled),
        ("/tmp", handled),
        ("/dev", handled),
    ]:
        if not Path(path).exists():
            continue
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        rule = Rule(access, path_fd)
        if libc.syscall(445, fd, 1, ctypes.byref(rule), 0) < 0:
            raise OSError(ctypes.get_errno(), "landlock_add_rule " + path)
        os.close(path_fd)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.syscall(446, fd, 0) != 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    os.close(fd)
    # Block every network family except AF_UNIX, leaving runtime socket and asyncio usable.
    sec = ctypes.CDLL("libseccomp.so.2")
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
    ]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]

    class Compare(ctypes.Structure):
        _fields_ = [
            ("arg", ctypes.c_uint),
            ("op", ctypes.c_int),
            ("a", ctypes.c_uint64),
            ("b", ctypes.c_uint64),
        ]

    ctx = sec.seccomp_init(0x7FFF0000)
    socket_nr = sec.seccomp_syscall_resolve_name(b"socket")
    cmp = Compare(0, 1, socket.AF_UNIX, 0)  # SCMP_CMP_NE
    if (
        sec.seccomp_rule_add_array(ctx, 0x50000 | 1, socket_nr, 1, ctypes.byref(cmp))
        != 0
        or sec.seccomp_load(ctx) != 0
    ):
        raise RuntimeError("seccomp filter")
    os.execv("/bin/bash", ["bash", "--noprofile", "--norc", "-c", sys.argv[2]])


if len(sys.argv) > 1 and sys.argv[1] == "child":
    harden()
else:
    try:
        apparmor = Path("/proc/self/attr/current").read_text().strip()
    except OSError:
        apparmor = "unavailable"
    output(
        "environment", kernel=os.uname().release, uid=os.geteuid(), apparmor=apparmor
    )
    if os.geteuid() == 0:
        Path("/root/full-proc").mkdir(exist_ok=True)
        result = subprocess.run(
            ["mount", "-t", "proc", "proc", "/root/full-proc"],
            capture_output=True,
            text=True,
        )
        output(
            "supervisor_proc_mount", exit_code=result.returncode, stderr=result.stderr
        )
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    Path("/probe-root/scratch").mkdir(exist_ok=True)
    Path("/probe-root/page.html").write_text(Path("/fixture/page.html").read_text())
    Path("/probe-root/tools.sock").unlink(missing_ok=True)
    if Path("/fixture/pipe.py").exists():
        Path("/probe-root/pipe.py").write_text(Path("/fixture/pipe.py").read_text())
    listener = socket.socket(socket.AF_UNIX)
    listener.bind("/probe-root/tools.sock")
    listener.listen()

    def serve():
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"turn-socket-ok")

    threading.Thread(target=serve, daemon=True).start()
    proc = jail("cat /proc/self/status | head -2")
    jail(
        "python -c \"import asyncio,socket; asyncio.run(asyncio.sleep(0)); s=socket.socket(socket.AF_UNIX); s.connect('/run/tools.sock'); print(s.recv(100).decode()); print(open('/proc/self/status').read().splitlines()[0])\"",
        proc == 0,
    )
    if proc:
        jail(
            "python -c \"import asyncio; asyncio.run(asyncio.sleep(0)); print('asyncio-ok')\"",
            False,
        )
    jail(
        "chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --no-zygote --print-to-pdf=/agent/page.pdf --screenshot=/agent/page.png file:///agent/page.html; test -s /agent/page.pdf && test -s /agent/page.png",
        proc == 0,
    )
    jail("python /agent/pipe.py", proc == 0)
    jail(
        "python -c \"from docx import Document; d=Document(); d.add_paragraph('Computer spike'); d.save('/agent/input.docx')\"; /usr/bin/time -v libreoffice -env:UserInstallation=file:///tmp/lo-profile --headless --convert-to pdf --outdir /agent /agent/input.docx; test -s /agent/input.pdf",
        proc == 0,
    )
    jail('python -c "import socket; socket.socket(socket.AF_INET)"', proc == 0)
    jail(
        "test ! -e /app && test ! -e /probe-root && echo private-paths-hidden",
        proc == 0,
    )
