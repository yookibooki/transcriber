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

## Provider
Env-only, read at startup: TRANSCRIBE_API_KEY (required); TRANSCRIBE_HOST/MODEL/LANGUAGE/PATH (Groq defaults). OpenAI-compatible /audio/transcriptions; switch = edit env + restart. Trust = build-time anchors/ only, never a system store; new root → add .pem + rebuild (ask-first).

## Definition of done
| Metric | PASS | Measure |
|---|---|---|
| Idle CPU | <5 wakeups/s | /proc ctxt delta (10s) |
| Idle Memory | <200KB | VmRSS |
| Rec CPU | <2% 1-core | /proc/<pid>/stat utime+stime over a hold |
| Binary | <200KB stripped | stat -c%s installed |
| LOC | <1100 soft | wc -l transcriber.c |

## Tests
Agents run no tests (tools/ = measurement rigs). Build, hand over, report changes; never claim PASS.

## Code rules
- transcriber.c only: C11, tabs, no heap, all error paths handled; tools/ = dep-free python rigs.
- Never exit at runtime: poll errors retry 1s; lost inputs rescan; failures log `discarded, idle`. Exit 1 (env/DNS), 2 (no mic): startup-only.
- No hardcoded device numbers, distro paths/packages, fallback DNS.
- TRANSCRIBE_API_KEY read once, zeroed, unset; g_sess madvise(DONTNEED)-wiped after send. Never weaken security/pinning to pass a build.
- Unsupported env (Wayland paste, IPv6 resolv.conf): skip + flag.

## Do not
Commit build/; install outside ~/.local/bin; hand-edit build/anchors.h.

## Pre-approved
Code/build changes, new files; tooling via sudo/pacman; suspending PipeWire/Pulse for ALSA.

## Ask first
Commits/pushes; BearSSL/anchors; systemd unit; pinned endpoint/model/language; DoD adjudication.
