# Computer feasibility spike (33.03.02)

Disposable probes for procfs preparation, local sockets, Chromium (rendering and
DevTools pipes), LibreOffice and Landlock. This branch is deliberately unmerged.
The settled results live in Workspace computer-design section 3.6; these probes
are not a replacement for protocol-v3 supervisor acceptance.

Build the Dockerfile, then run as root with `SYS_ADMIN` and `seccomp=unconfined`.
The root process mounts a private full procfs, drops groups/UID/GID, and runs each
Bubblewrap child with Landlock and an internet-socket deny filter. Running without
root procfs preparation reproduces the expected rendering failures.

The separate AppArmor profile uses only the spike executable path. It was loaded
on one staging node for dedicated probes and removed after the run. It must never
replace a shared production profile.
