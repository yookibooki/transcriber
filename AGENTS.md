# AGENTS.md
## Philosophy
Extreme efficiency, idiomatic C: minimal RAM/binary/LOC/syscalls. Ask "but why?" of every decision. Rebuild-cheap > runtime-flexible.

## Project
Single-file push-to-talk daemon (transcriber.c): hold Right Ctrl, speak → transcript at cursor + stdout. Any distro; dev box = test target, not template.

## Build
```sh
./build.sh
```
musl-gcc only. First run downloads pinned BearSSL 0.6. Installs to ~/.local/bin/transcriber.

## Tests
Agents run no tests (tools/ = measurement rigs). Build, hand over, report changes; never claim PASS.

## Do not
Commit build/ or gitignored tools/ (force-adding it defeats the policy); install outside ~/.local/bin; hand-edit build/anchors.h.

## Pre-approved
Code/build changes, new files; tooling via sudo/pacman; suspending PipeWire/Pulse for ALSA.

## Ask first
Commits/pushes; history rewrites/force-pushes; BearSSL/anchors; systemd unit; pinned endpoint/model/language; DoD adjudication.
