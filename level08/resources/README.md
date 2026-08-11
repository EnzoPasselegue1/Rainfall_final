# level08 — "Maelcum" — Format-String Canary Leak → ret2leave Pivot → `open`/`read`/`write` ROP

## Concept

`./maelcum`, SUID owned by `flag08`, home dir `/home/level08/`. By far
the most involved exploit among the mandatory levels solved so far — the
canary-leak-then-overflow shape is now familiar (level06, level07), but
this time the overflow window is so small (24 bytes — barely enough for
a single return address) that a real stack-pivot technique was required
just to get a ROP chain running at all, and the natural choice of
payload (`setreuid` + `system("/bin/sh")`) turned out to be fundamentally
incompatible with the pivoted buffer's size, requiring a second,
different technique to work around.

## Recon

Login: `ssh level08@127.0.0.1 -p 4244`, password = level07's flag
(`s3cgzrg5q78t6xx73ljvm3m2zfwk02ix`).

No source. `nm ./maelcum`: `init_routing`, `print_banner`, `add_route`,
`relay_status`, `relay_data`, `print_routes`, called from `main` in that
order. `checksec`: canary found, NX enabled, no PIE. `getent passwd
flag08` → uid 1025.

`add_route`/`print_routes` just manage a fixed in-memory routing table
from hardcoded strings in `main` — no user input reaches them, dead end.

`relay_status()`: `read(0, buf, 0x3f)` into an 80-byte buffer (bounded,
safe), then `printf(buf)` directly — the by-now-familiar format-string
leak pattern.

`relay_data()`, the real target — two `read()` calls:
```c
// (reconstructed from disassembly, not literal source)
char buf[48];                          // rbp-0x30, frame is only 0x40 (64) total
n = read(0, buf, 0x40);                // reads up to 64 bytes -- OVERFLOWS the 48-byte buf!
if (strncmp(buf, "RELAY:", 6) == 0) {
    unsigned count = strtoul(buf + 6, NULL, 10);
    if (count <= 0x1ff) {               // <= 511
        read(0, relay_buf, count);      // relay_buf: GLOBAL, fixed addr 0x404200, 512 bytes
    }
}
```

## Retrieving the addresses, command by command

`relay_data()`'s first `read(0, buf, 0x40)` reads up to 64 bytes into a
48-byte buffer (`rbp-0x30`, frame is 0x40 total) with the canary at
`rbp-0x8` — 40 safe bytes, so the read's 64-byte cap leaves exactly 24
bytes of overflow room: canary (8) + saved rbp (8) + return address
(8), with nothing left over for a gadget's own arguments. This was
confirmed with the same two-step canary check used on every prior
level: a wrong byte at offset 40 triggers `*** stack smashing detected
***`/SIGABRT, and a correctly leaked canary with a garbage return
address gives a clean SIGSEGV instead.

The canary leaks through `relay_status`'s `printf(buf)`; probing
`%N$p` for the `0x00`-low-byte signature lands on argument index 17,
stable across repeated runs.

With only eight bytes free for the return address itself, a single
gadget can't carry both an address and an argument, so a stack pivot
is needed to get the real ROP chain running at all. This uses
ret2leave: the 8 bytes conventionally treated as "junk" saved-rbp are
instead set to `relay_buf`'s address — a fixed, non-PIE global at
`0x404200`, so no leak is needed for it — and the actual return
address is set to a plain `leave ; ret` gadget (`ROPgadget --only
"leave|ret"` against libc turns up exactly one hit, at libc+0x299d2).
Mechanically: `relay_data`'s own `leave` (still using its real rbp)
loads our injected `relay_buf` address into the rbp register, and
its `ret` jumps to the chosen gadget; that gadget's own `leave` then
does `rsp = rbp`, completing the pivot into `relay_buf`, and its `ret`
pops the first real gadget straight out of `relay_buf`'s contents —
filled separately via the second `read()`, entirely decoupled from the
tiny first-overflow window. `relay_buf[0:8]` is a throwaway value
consumed by this second `leave`'s implicit "pop rbp"; the real chain
starts at `relay_buf[8:16]`. A live gdb trace confirmed the pivot:
`do_system(line="/bin/sh")` was reached with the exact expected
argument, proving both the pivot mechanics and the `setreuid` portion
of the chain are correct.

Only `pop rdi ; ret` and `pop rsi ; pop rbp ; ret` were available from
earlier levels' gadget set, leaving no direct way to set `rdx` for
`read()`/`write()`. This was solved with a second application of the
same pivot idea: `pop rdx ; leave ; ret`, found by raw-scanning libc
for the `5a c3` byte pattern and cross-checking each hit against
`readelf -S` to confirm it actually lands inside the executable
`.text` section (an unfiltered scan turns up matches inside
non-executable `.gnu.hash` data, which don't work). Chained together,
the final payload calls `open(path, O_RDONLY)`, assumes the returned
fd is 3 (0/1/2 are already taken by stdin/stdout/stderr and nothing
else opens a file first), then `read(3, buf, 100)` and
`write(1, buf, 100)`, each redirected into its own small "continuation
block" inside `relay_buf` via the `pop rdx ; leave ; ret` pivot.

## Why open/read/write, not system()

The `setreuid` + `system("/bin/sh")` chain that worked on every
earlier level reaches `do_system` correctly here too, but then
segfaults on a plain `movl $0xffffffff,0x8(%rsp)` deep in its
prologue — `do_system` allocates roughly 0x380 (896) bytes of its own
stack space, more than `relay_buf`'s 512-byte total capacity once the
ROP chain itself has already consumed some of it. Sweeping the
alignment-fixup count from 0 to 8 (the parameter that fixed the
equivalent-looking crash on every earlier level) didn't help,
confirming this is a hard size limit rather than a stack-alignment
parity issue — a plain `mov`/`movl` writing far into the frame, rather
than an SSE `movaps`-style fault, is the tell. Since `system()`
doesn't fit, the final exploit avoids it entirely and uses the
`open`/`read`/`write` chain above instead, which has a small enough
footprint to fit inside `relay_buf` comfortably.

## Exploit

Three-stage interactive session (see `exploit.py` for exact byte
offsets):

```
$ ./maelcum
[MAELCUM] Tag this relay: %17$p
[MAELCUM] Logging relay tag: 0x640ba3bf3689eb00   <- canary
[MAELCUM] Send it: RELAY:450CCCC...<canary><relay_buf addr><leave;ret addr>
[MAELCUM] Ready for 450 bytes: <the full ROP chain, written into relay_buf>
l3w1pdvtlapo1nmo8uttd1m0pen4iiuk
```

(The process segfaults immediately after — expected and harmless, since
`write()` has already sent the flag by then.)

Verified: this string works as level09's SSH password.

