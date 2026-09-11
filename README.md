# transcriber

Hold **Right Ctrl**, speak, release — your words are typed at the cursor. Works anywhere you can type.

Single static binary (~155 KB, zero idle wakeups). Records while held, sends to any OpenAI-compatible transcription endpoint (Groq by default), pastes via `xclip` + `xdotool`.

> **X11 Linux + ALSA mic only.** No Wayland, no PipeWire/Pulse fallback. Each hold uploads audio — see Notes.

## Install

```sh
sudo usermod -aG input,audio $USER   # then re-login
# Debian/Ubuntu: sudo apt install xclip xdotool
# Fedora:        sudo dnf install xclip xdotool
# Arch:          sudo pacman -S xclip xdotool
```

```sh
mkdir -p ~/.config/environment.d
echo 'TRANSCRIBE_API_KEY=your-key-here' > ~/.config/environment.d/transcribe.conf
chmod 600 ~/.config/environment.d/transcribe.conf
```

Get a key at [console.groq.com](https://console.groq.com). Then:

```sh
./build.sh
```

This builds, runs tests, installs to `~/.local/bin/transcriber`, and enables the user service (autostarts on login). First build ~1 min, rebuilds take seconds. Needs `musl-gcc`, `curl`, `tar`.

Try it: click any text field, hold Right Ctrl, speak, release.

## Configure

Env vars only. Restart after changing: `systemctl --user restart transcriber.service`.

| Variable | Default | Required |
|---|---|---|
| `TRANSCRIBE_API_KEY` | — | yes |
| `TRANSCRIBE_HOST` | `api.groq.com` | no |
| `TRANSCRIBE_MODEL` | `whisper-large-v3-turbo` | no |
| `TRANSCRIBE_LANGUAGE` | `en` | no |
| `TRANSCRIBE_PATH` | `/openai/v1/audio/transcriptions` | no |

Logs: `journalctl --user -u transcriber.service -f`. Silence means success — a line appears only on failure. Transcripts never hit the log.

## Use

- Taps under 0.3 s are ignored; holds cap at 60 s.
- If text doesn't paste, press `Ctrl+V` yourself — it's already in the clipboard.
- One attempt per press, no retries. If network/key fails, just hold again.

## If it doesn't work

| Symptom | Fix |
|---|---|
| Nothing happens | Re-login after `usermod`? `groups` must show `input audio`. `echo $XDG_SESSION_TYPE` must say `x11`. |
| `no usable mic` | Mic busy or no `audio` group. Close apps holding ALSA, restart service. |
| `no key device` / no paste | Missing `input` group, or not on X11 / missing `xclip` + `xdotool`. |
| `HTTP 401/403`, `send failed` | Wrong key/host, no network, or quota. Check conf, restart, retry. |

## Notes

- Voice leaves your machine as 16 kHz WAV to `TRANSCRIBE_HOST`. Nothing stored locally; audio stays in RAM, key is locked/wiped.
- TLS trusts only `anchors/` (ISRG X1/X2, GTS R4) — other providers need their root added there + rebuild.
