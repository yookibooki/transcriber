# ARCHITECTURE.md
## Code rules
- transcriber.c only: C11, tabs, no heap, all error paths handled; tools/ = dep-free python rigs, local-only (untracked, never pushed).
- Never exit at runtime: poll errors retry 1s; lost inputs rescan; failures log `discarded, idle`. Exit 1 (env/DNS), 2 (no mic): startup-only.
- No hardcoded device numbers, distro paths/packages, fallback DNS.
- TRANSCRIBE_API_KEY read once, zeroed, unset; g_sess madvise(DONTNEED)-wiped after send. Never weaken security/pinning to pass a build.
- TLS session-ID resumption (user-approved 2026-09-09): the 85-byte session params incl. master secret survive between sends in g_tls_sess, outside g_sess so the page-exact wipe still covers engine/transcript/buffers; server refusal of resumption falls back silently to a full pinned-anchor handshake.
- Unsupported env (Wayland paste, IPv6 resolv.conf): skip + flag.
