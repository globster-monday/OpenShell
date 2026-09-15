# Root-started supervisor acceptance

This fixture reproduces hosted Kubernetes startup: the supervisor starts as root,
then launches both the fixed Bubblewrap helper and the agent as UID/GID 10001.
The probe runs through the real supervisor startup path and requires a mode-0600
socket owned by that identity, JSON output, and denied network, workspace, and
inherited-environment access from generated Python.

Use a Linux image with the full harness, Bubblewrap, and Python at
`/app/.venv/bin/python`. Mount the freshly built supervisor as `/openshell-sandbox`,
this directory as `/fixture-source`, and
`crates/openshell-supervisor-network/data/sandbox-policy.rego` as
`/fixture-policy.rego`. Run the disposable container as root with no network,
`--security-opt seccomp=unconfined`, a 512 PID limit, and 1 GiB memory. The trusted
supervisor installs the normal agent seccomp policy; Bubblewrap's child installs
its stricter policy. No additional host capabilities or host namespaces are needed.

Set `OPENSHELL_EXPERIMENTAL_BWRAP_LAUNCHER=1` and
`INLINE_CODE_TEST_CANARY=nonsecret-fixture-canary`, then execute:

```sh
cp -r /fixture-source /fixture
/openshell-sandbox --mode process \
  --policy-rules /fixture-policy.rego --policy-data /fixture/policy.yaml \
  -- /bin/sh /fixture/run.sh
result=$?
cat /tmp/bwrap-root-probe.log
exit "$result"
```

Copying the fixture first keeps Landlock tests on the container's native
filesystem instead of the macOS Docker bind-mount filesystem. `run.sh` retains
probe output because the supervisor's noninteractive child output belongs to its
session service. A passing run prints `root_started_supervisor: passed` and
`bubblewrap_output: {total: 6}` and exits zero.

The process-crate unit test additionally verifies cleared supplementary groups
and effective, permitted, inheritable, ambient, and bounding capabilities in the
helper launched from root, while the supervisor keeps its setup identity.
