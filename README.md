# transcriber

**transcriber is a single-file, statically-linked C push-to-talk daemon: hold a key (default Right Ctrl), speak, release, and it records from the mic, HTTPS-POSTs the WAV to Groq's `whisper-large-v3-turbo`, and pastes the transcript at your cursor (clipboard + `ctrl+shift+v`) while echoing it to stdout.**

> **Build rule: `build.sh` always installs the binary to `~/.local/bin/transcriber` — NEVER to the project root.** Repo stays source-only. (`.gitignore` still ignores a root `transcriber` purely as a safety net; don't create one.)

## Files

| Path | What |
|---|---|
| `transcriber.c` | The whole tool (~1400 LOC, no heap, no libc TLS stack) |
| `build.sh` | Build: embeds CA anchors, compiles BearSSL, links static, installs to `~/.local/bin/transcriber` |
| `anchors/*.pem` | Pinned trust anchors for `api.groq.com`: ISRG Root X1/X2 (Let's Encrypt), GTS Root R4 (Google) — flattened to DER in `build/anchors.h` at build time |
| `proof/` | Old test evidence (functional, size, strace, malloc/fs/seccomp checks, perf logs) |
| `build/` | Build cache/artifacts — gitignored |

## Build

```sh
./build.sh
```

Needs: `musl-gcc`, `openssl`, `strip`, `python3`, `curl`, `tar`.
Downloads BearSSL 0.6 (sha256-pinned), caches objects in `build/obj/`.
Output: `~/.local/bin/transcriber`, ~106 KB static stripped ELF (on PATH).

## Run

```sh
export GROQ_API_KEY=...        # required; zeroed + unset in own environment after read
transcriber                    # straight from ~/.local/bin
```

Flags: `--event-path /dev/input/eventX` (repeatable), `--keycode N` (default 97 = Right Ctrl), `--alsa-dev /dev/snd/pcmC0D0c` (auto-falls back to `pcmC0D0c`–`pcmC2D3c` scan), `--help`.

Runtime deps on this machine: **`xclip` and `xdotool` on PATH** (used to paste), membership in `input` + `audio` groups (or root) for `/dev/input/event*` and `/dev/snd/*`, and DNS from `/etc/resolv.conf`.

## Behavior notes (so I don't forget)

- Hold ≥ **300 ms** or the press is ignored (no network). Cap **60 s**.
- Mic is opened 48 kHz stereo S16 and downsampled 3:1 to **16 kHz mono** WAV in-code.
- No `EVIOCGRAB` — keyboard stays fully usable; Right Ctrl still reaches apps.
- Own DNS resolver (raw UDP queries the first `nameserver` in resolv.conf) and own TLS 1.2 client (ECDHE AES-GCM only, pinned anchors above — no system cert store).
- After each send, session memory (`g_sess`: TLS state, keys, transcript buffers) is wiped via `madvise(DONTNEED)`.
- Failure mode is silent-ish: prints `transcriber: discarded, idle` on stderr and keeps running. Needs no network at idle after startup DNS.
- Text goes to stdout *and* clipboard-paste; if audio works but nothing appears, check stderr (`transcriber 2>log`).

## Autostart (systemd user service)

`~/.config/systemd/user/transcriber.service` — enabled, runs `~/.local/bin/transcriber` after `graphical-session.target` with `DISPLAY=:0`, `XAUTHORITY`, and `GROQ_API_KEY` inline (Restart=always). Manage with:

```sh
systemctl --user status|restart|stop transcriber.service
journalctl --user -u transcriber.service -f      # logs: "dns ok", "mic ...", "ready"
```

## Related on this box

- Fake key from uinput for testing: `snd-dummy` (`pcmC1D0c`) — see `proof/functional.txt` for the rig.
- Renamed 2026-09-08 from `whisper-push` (old repo dir `~/workspace/whisperpush-zero` no longer exists; stale references remain in `~/workspace/context.md`).
