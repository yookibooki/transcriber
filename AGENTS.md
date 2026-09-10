Single-file push-to-talk daemon (`transcriber.c`): hold Right Ctrl, speak → transcript at the cursor.

Goal: simplest solution that just works.
Philosophy: extreme efficiency, idiomatic C — minimal RAM / binary / LOC / syscalls.

## Hard Requirements
| Metric | Requirement |
|---|---|
| Idle CPU | 0 wakeups |
| Idle Memory | <200KB |
| Binary Size | <200KB |
| LOC | <1500 |
| Compatibility | all distros, any arch |

Build: `./build.sh`

## Tests
Agents run no tests. Build and ask user to test.
