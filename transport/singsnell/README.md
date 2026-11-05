# singsnell

Snell v6 client/server implementation ported from
[SagerNet/sing-snell](https://github.com/SagerNet/sing-snell)
(commit `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`), licensed under GPL-3.0-or-later (see LICENSE).

Changes relative to upstream:

- imports rewritten to `github.com/metacubex/sing` and this module path
- root package renamed to `singsnell`
- language features newer than the Go version declared in go.mod replaced
  with equivalent helpers
- only the v6 protocol is ported; v4/v5 live in `transport/snell`
