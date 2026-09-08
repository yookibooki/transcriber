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
