# transcriber

Single-file, statically-linked C push-to-talk daemon: hold a key (default Right Ctrl), speak, release — audio is recorded, WAV POSTed to Groq's `whisper-large-v3-turbo` over TLS 1.2 (own stack, pinned anchors), and the transcript is pasted at the cursor and echoed to stdout.

## Files

| Path | What |
|---|---|
| `transcriber.c` | Whole tool (1005 LOC, no heap, no libc TLS stack) |
| `build.sh` | Build: embeds CA anchors, compiles BearSSL, links static, installs to `~/.local/bin/transcriber` |
| `anchors/*.pem` | Pinned trust anchors for `api.groq.com`: ISRG Root X1/X2 (Let's Encrypt), GTS Root R4 (Google) — flattened to DER in `build/anchors.h` at build time |
| `build/` | Build cache/artifacts — gitignored |

## Build

```sh
./build.sh
```

Needs: `musl-gcc`, `openssl`, `strip`, `python3`, `curl`, `tar`, `sha256sum`, `stat`, `file`, `cut`.
Downloads BearSSL 0.6 (sha256-pinned), caches objects in `build/obj/`. Output: `~/.local/bin/transcriber`, 112,288 bytes static stripped ELF. Do **not** commit `build/`.

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

Flags: `--event-path /dev/input/eventX` (repeatable), `--keycode N` (default 97 = Right Ctrl), `--alsa-dev /dev/snd/pcmC0D0c` (defaults first, then any `pcmC*D*c` under `/dev/snd`), `--help`.

Runtime deps: paste needs `xclip` + `xdotool` on PATH (X11; skipped under Wayland-only); `/dev/input/` + `/dev/snd/` access (input + audio groups or root); DNS from `/etc/resolv.conf`.

## Behavior

- Mic opens 48 kHz stereo S16 LE (mono fallback), downsampled 3:1 to 16 kHz mono WAV in-code; ring buffer of 2 halves × 2048 samples.
- Hold < 300 ms: ignored, no network. Cap 60 s per press. HTTP response cap 8 KB; transcript cap 4 KB.
- No `EVIOCGRAB` — keyboard stays fully usable.
- Own DNS (raw UDP to all IPv4 nameservers in resolv.conf, in order) and own TLS 1.2 client (ECDHE AES-GCM suites only, pinned anchors — never a system store).
- After each send, session memory (`g_sess`: TLS state, keys, transcript buffers) is wiped via `madvise(MADV_DONTNEED)`.
- The daemon never exits at runtime: poll errors retry after 1s, dead input devices are dropped/re-scanned, record failures discard the capture and print `transcriber: discarded, idle` on stderr. Exit codes 1 (bad env/anchors/DNS) and 2 (no mic) are startup-only fail-fast.
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

Measured on the 2026-09-08 build: 0 context switches over 10 s idle, RSS 144 kB, binary 112,288 bytes stripped static, 1,005 LOC.

## History

Renamed 2026-09-08 from `whisper-push` (old repo `~/workspace/whisperpush-zero` no longer exists; stale references remain in `~/workspace/context.md`). Foreign/proof artifacts never in git history removed 2026-09-08: `proof/` claimed seccomp/`--no-sandbox`/`--self-test` features that never existed in any commit of this repo — they came from someone else's challenge variant of the code.
