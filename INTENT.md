# INTENT.md
## Provider
Env-only, read at startup: TRANSCRIBE_API_KEY (required); TRANSCRIBE_HOST/MODEL/LANGUAGE/PATH (Groq defaults). OpenAI-compatible /audio/transcriptions; switch = edit env + restart. Trust = build-time anchors/ only, never a system store; new root → add .pem + rebuild (ask-first).

## Definition of done
| Metric | PASS | Measure |
|---|---|---|
| Idle CPU | <5 wakeups/s | /proc ctxt delta (10s) |
| Idle Memory | <200KB | VmRSS |
| Rec CPU | <2% of one core | /proc/<pid>/stat utime+stime over a hold |
| Binary | <150KB | stat -c%s installed |
| LOC | <1000 | wc -l transcriber.c |
