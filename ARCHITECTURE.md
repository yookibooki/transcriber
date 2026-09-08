# ARCHITECTURE.md
## Code rules
- transcriber.c only: C11, tabs, no heap, all error paths handled; tools/ = measurement rigs, local-only (untracked, never pushed).
- Never exit at runtime: poll errors retry 1s; lost inputs rescan; failures log. Exit 1 (env/DNS), 2 (no mic): startup-only.
- No hardcoded device numbers, distro paths/packages, fallback DNS.
- TRANSCRIBE_API_KEY read once, zeroed, unset; g_sess madvise(DONTNEED)-wiped after send. Never weaken security/pinning to pass a build.
- TLS session-ID resumption (user-approved 2026-09-09): the 86-byte session params incl. master secret survive between sends in g_tls_sess, outside g_sess so the page-exact wipe still covers engine/transcript/buffers; server refusal of resumption falls back silently to a full pinned-anchor handshake.
- Anchors (user-approved 2026-09-09): `anchors/*.pem` → const `.rodata` table (`build/ta.h`) at build time via vendored `brssl ta` (compiled from the same pinned BearSSL with the same musl-gcc); runtime does chain validation only — no anchor ASN.1 decode, no anchor .bss. Trust decisions unchanged, tool output verified byte-identical to the pre-rework runtime parse.
- Unsupported env (Wayland paste, IPv6 resolv.conf): skip + flag.
