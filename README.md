# transcriber

Single-file, statically-linked C push-to-talk daemon: hold Right Ctrl, speak, release — audio is recorded, WAV POSTed to Groq's `whisper-large-v3-turbo` over TLS 1.2 (own stack, pinned anchors), and the transcript is pasted at the cursor and echoed to stdout.

## Files

| Path | What |
|---|---|
| `transcriber.c` | Whole tool (1071 LOC, no heap, no libc TLS stack) |
| `build.sh` | Build: embeds CA anchors, compiles BearSSL, links static, installs to `~/.local/bin/transcriber` |
| `anchors/*.pem` | Pinned trust anchors for `api.groq.com`: ISRG Root X1/X2 (Let's Encrypt), GTS Root R4 (Google) — flattened to DER in `build/anchors.h` at build time |
| `build/` | Build cache/artifacts — gitignored |
| `tools/` | Local-only measurement rigs (`rec-cpu.py`, `res-qa/`) — gitignored, never pushed |

## Build

```sh
./build.sh
```

Needs: `musl-gcc`, `openssl`, `strip`, `python3`, `curl`, `tar`, `sha256sum`, `stat`, `file`, `tr`, `cut`.
Downloads BearSSL 0.6 (sha256-pinned), caches objects in `build/obj/`. Output: `~/.local/bin/transcriber`, 112,280 bytes static stripped ELF. Do **not** commit `build/`.

## Run

```sh
export TRANSCRIBE_API_KEY=...    # required; zeroed + unset in own environment after read
transcriber                      # straight from ~/.local/bin
```

Env config (env-only; no provider flags). Defaults in parens:

- `TRANSCRIBE_API_KEY` — required
- `TRANSCRIBE_HOST` (api.groq.com)
- `TRANSCRIBE_MODEL` (whisper-large-v3-turbo)
- `TRANSCRIBE_LANGUAGE` (en)
- `TRANSCRIBE_PATH` (/openai/v1/audio/transcriptions)

Any OpenAI-compatible `/audio/transcriptions` endpoint works without recompile. TLS still trusts **only `anchors/`** — a provider whose chain terminates elsewhere handshake-fails by design; adding a root to `anchors/` is a trust-policy change (ask-first).

Flags: `--event-path /dev/input/eventX` (repeatable), `--alsa-dev /dev/snd/pcmC0D0c` (defaults first, then any `pcmC*D*c` under `/dev/snd`), `--help`. Right Ctrl is the only hotkey — there is no keycode option.

Runtime deps: paste needs `xclip` + `xdotool` on PATH (X11; skipped when the session is Wayland, incl. `XDG_SESSION_TYPE=wayland`); `/dev/input/` + `/dev/snd/` access (input + audio groups or root); DNS from `/etc/resolv.conf`.

## Behavior

- Mic opens 48 kHz stereo S16 LE (mono fallback), downsampled 3:1 to 16 kHz mono WAV in-code.
- Hold < 300 ms: ignored, no network. Cap 60 s per press. HTTP response cap 8 KB; transcript cap 4 KB.
- No `EVIOCGRAB` — keyboard stays fully usable.
- Clipboard paste: only after `xclip -o` confirms the transcript is actually served (up to 2 s, then skip) — replaces a fixed 50 ms race. Clipboard content is still overwritten by design.
- After each send, the request buffer (which contains the API key) is zeroed, and session memory (`g_sess`: TLS state, keys, transcript buffers) is wiped via `madvise(MADV_DONTNEED)`; `sizeof g_sess` is compile-time asserted to be a page multiple so the wipe stays exact.
- Own DNS (raw UDP to all IPv4 nameservers in resolv.conf, in order) and own TLS 1.2 client (ECDHE AES-GCM suites only, pinned anchors — never a system store). TLS session-ID resumption keeps the handshake state between sends (user-approved): repeat dictations do an abbreviated handshake; if the server refuses, it falls back to a full handshake automatically.
- The daemon never exits at runtime: poll errors retry after 1s, dead input devices are dropped/re-scanned, record failures discard the capture silently. A rejected send logs one line: `transcriber: HTTP 429` (server status) or `transcriber: send failed` (transport). Exit codes 1 (bad env/anchors/DNS) and 2 (no mic) are startup-only fail-fast.
- Transcript goes to stdout and cursor-paste both.

## Autostart (systemd user service)

`~/.config/systemd/user/transcriber.service` — enabled, runs `~/.local/bin/transcriber` after `graphical-session.target` with `DISPLAY=:0`, `XAUTHORITY`, and `TRANSCRIBE_API_KEY` (in `~/.config/environment.d/transcribe.conf`, mode 0600) with `Restart=always`. Manage:

```sh
systemctl --user status|restart|stop transcriber.service
journalctl --user -u transcriber.service -f      # logs: "dns ok", "mic ...", "ready"
```

## Definition of done

| Metric | PASS |
|---|---|
| Idle CPU | <5 wakeups/s |
| Idle Memory | <200KB |
| Rec CPU | <2% 1-core |
| Binary | <200KB stripped |
| LOC | <1100, soft limit |

Measured on the 2026-09-08 build: 0 context switches over 10 s idle, RSS 144 kB, binary 112,288 bytes stripped static, 1,005 LOC. Rebuilt after the 2026-09-08 review fixes (single-page wipe assertion, right-ctrl-only, tls pump de-dup, paste confirmation): 112,280 bytes, 1,071 LOC. Idle/rec-CPU/memory not re-measured — rigs are local-only.

## History

Renamed 2026-09-08 from `whisper-push` (old repo `~/workspace/whisperpush-zero` no longer exists; stale references remain in `~/workspace/context.md`). `proof/` (foreign challenge-variant artifacts claiming seccomp/`--no-sandbox`/`--self-test` features that never existed here) was added in the `init` commit by mistake and removed from the tree the same day; `tools/` was removed from the tree and git history by rewrite the same day. Nothing in either was sensitive.
