# transcriber

Single-file, statically-linked C push-to-talk daemon: hold Right Ctrl, speak, release — audio is recorded, WAV POSTed to Groq's `whisper-large-v3-turbo` over TLS 1.2 (own stack, pinned anchors), and the transcript is pasted at the cursor.

## Files

| Path | What |
|---|---|
| `transcriber.c` | Whole tool (981 LOC, no heap, no libc TLS stack) |
| `build.sh` | Build: compiles BearSSL + its `brssl` tool (generates the anchor table), links static, installs to `~/.local/bin/transcriber` |
| `anchors/*.pem` | Pinned trust anchors for `api.groq.com`: ISRG Root X1/X2 (Let's Encrypt), GTS Root R4 (Google) — compiled into a const `br_x509_trust_anchor` table (`build/ta.h`) at build time by the vendored `brssl`; the daemon does no anchor ASN.1 decode |
| `build/` | Build cache/artifacts — gitignored |

## Build

```sh
./build.sh
```

Needs: `musl-gcc`, `strip`, `curl`, `tar`, `sha256sum`, `stat`, `file`, `tr`, `cut` (no openssl, no python).
Downloads BearSSL 0.6 (sha256-pinned), caches objects in `build/obj/` (first run: ~53 s; cached: ~2 s). Output: `~/.local/bin/transcriber`, 108,176 bytes static stripped ELF. Do **not** commit `build/`.

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

No flags. Autoscan only: Right Ctrl from any `eventN` device that has that keycode (kernel `EVIOCGBIT` query), mic from `/dev/snd/pcmC0D0c`, else any `pcmC*D*c` under `/dev/snd`. Right Ctrl is the only hotkey — there is no keycode option either.

Runtime deps: paste needs `xclip` + `xdotool` on PATH (X11; skipped when the session is Wayland, incl. `XDG_SESSION_TYPE=wayland`); `/dev/input/` + `/dev/snd/` access (input + audio groups or root); DNS from `/etc/resolv.conf`.

## Behavior

- Mic opens 48 kHz stereo S16 LE (mono fallback), downsampled 3:1 to 16 kHz mono WAV in-code.
- Hold < 300 ms: ignored, no network. Cap 60 s per press. HTTP response cap 8 KB; transcript cap 4 KB.
- No `EVIOCGRAB` — keyboard stays fully usable.
- Clipboard paste: only after `xclip -o` confirms the transcript is actually served (up to 2 s, then skip) — replaces a fixed 50 ms race. Clipboard content is still overwritten by design.
- After each send, the request buffer (which contains the API key) is zeroed, and session memory (`g_sess`: TLS state, keys, transcript buffers) is wiped via `madvise(MADV_DONTNEED)`; `sizeof g_sess` is compile-time asserted to be a page multiple so the wipe stays exact.
- Own DNS (raw UDP to all IPv4 nameservers in resolv.conf, in order) and own TLS 1.2 client (ECDHE AES-GCM suites only, pinned anchors as a compiled-in table — never a system store). TLS session-ID resumption keeps the handshake state between sends (user-approved): repeat dictations do an abbreviated handshake; if the server refuses, it falls back to a full handshake automatically.
- The daemon never exits at runtime: poll errors retry after 1s, dead input devices are dropped/re-scanned, record failures discard the capture silently. A rejected send logs one line: `transcriber: HTTP 429` (server status) or `transcriber: send failed` (transport). Exit codes 1 (bad env/DNS, stray arguments) and 2 (no mic) are startup-only fail-fast; the anchor table is a build-time artifact, so it cannot fail at runtime.
- Transcript is delivered only by cursor-paste (stdout is never written; on a per-send basis journald must not hold your dictations).

## Autostart (systemd user service)

`~/.config/systemd/user/transcriber.service` — enabled, runs `~/.local/bin/transcriber` after `graphical-session.target` with `DISPLAY=:0`, `XAUTHORITY`, and `TRANSCRIBE_API_KEY` (in `~/.config/environment.d/transcribe.conf`, mode 0600) with `Restart=always`. Manage:

```sh
systemctl --user status|restart|stop transcriber.service
journalctl --user -u transcriber.service -f      # logs: "dns ok", "mic ...", "ready"
```
