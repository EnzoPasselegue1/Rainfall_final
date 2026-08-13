# bonus02 — "Flatline" — Use-After-Free Write → Function-Pointer Hijack (PIE + CET)

## Concept

`./flatline`, SUID owned by `flagbonus02`, home dir `/home/bonus02/`.
Second bonus level. Per the subject, bonus levels cover techniques not
seen in the mandatory path; bonus01 was a live-buffer heap overflow,
this level is explicitly a use-after-free (UAF) write: a global array
keeps a stale pointer to freed memory, and a later "update" operation
writes through that stale pointer without ever checking whether the
memory is still actually allocated.

## Recon

Login: `ssh bonus02@127.0.0.1 -p 4244`, password = bonus01's flag
(`8g8nnrrtsasgf9i7etv0s9a21j5f9riw`).

No source provided. `ls -la ~`: SUID binary `flatline`, owned by
`flagbonus02`, plus a `.gdbinit` (`source /opt/pwndbg/gdbinit.py` —
pwndbg is preinstalled on the VM for this level, available if deeper
live debugging turns out to be needed).

`getent passwd flagbonus02` → uid 1029.

`checksec ./flatline` (run on the VM itself, since `checksec` isn't
installed on the analysis host):
```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

`SHSTK`/`IBT` (Intel CET — shadow stack + indirect branch tracking) are
new in this project; every earlier level (including bonus01, also PIE)
lacked them. Checked directly rather than assumed, since it's a real
mitigation to account for if the hardware/kernel actually enforces it:

```
$ cat /proc/cpuinfo | grep -o "shstk\|ibt" | sort -u
(no output)
```

No CET flags exposed to the guest — this VM's virtualized CPU doesn't
present CET to the guest kernel, so enforcement is inert here regardless
of what the binary was compiled with. Confirmed empirically too: the
final exploit's indirect call executed and returned cleanly, no fault of
any kind.

`nm ./flatline` (functions of interest): `new_construct`,
`delete_construct`, `update_construct`, `run_construct`,
`default_execute`, `print_banner`, `main`.

### Disassembling `main`

Same upfront pattern as bonus01: `geteuid()` x2, `setreuid(euid,euid)`
before any application logic — no privilege-transition step needed in
the exploit payload. Then, no interactive menu: `new_construct("DIXIE")`,
`new_construct("WINTERMUTE")`, `delete_construct(0)`,
`update_construct(0)`, `run_construct(0)`, then exits.

### Disassembling `new_construct`, `delete_construct`, `update_construct`, `run_construct`

Reconstructed struct layout (each `malloc(0x70)` = 112 bytes):

```c
struct construct {
    int id;               // +0x00
    int type;              // +0x04, hardcoded to 1
    char label[32ish];      // +0x08, strncpy(dst, name, 0x1f)
    char data[64];           // +0x28, memset to 0 at alloc time (0x40 bytes)
    void (*fn)(void *self);  // +0x68, defaults to default_execute — ends exactly at +0x70
};
```

`new_construct`: allocates the struct, sets `id`/`type`/`fn` (default),
`strncpy`s the label from the caller's argument, `memset`s the data
field, stores the pointer in the global `constructs[]` array (0x4040),
increments `construct_count`.

`delete_construct(idx)`: bounds-checks `idx < construct_count`, checks
`constructs[idx] != NULL`, calls `free(constructs[idx])` — and stops
there. `constructs[idx]` is never reset to NULL. This is the actual
bug: the global array now holds a dangling pointer to freed memory that
every subsequent bounds/null-check will treat as if it were still valid.

`update_construct(idx)`: same bounds/null checks (both pass — the
dangling pointer is non-NULL, `construct_count` isn't decremented by
`delete_construct` either), then `read(0, constructs[idx]+0x28, 0xa0)` —
160 bytes into a field only 64 bytes from the struct's own end
(`0x28 + 0xa0 = 0xc8` vs. the `0x70`-byte allocation) — a genuine
overflow layered on top of the UAF: this write goes through a pointer
to memory the allocator no longer considers owned by this struct at
all, using a size that wouldn't even have fit while it was still live.

`run_construct(idx)`: bounds/null-checks again (still passes), then
`constructs[idx]->fn(constructs[idx]+0x28)` — `rdi` is unconditionally
the struct's own `data` field address, same fixed-argument pattern as
bonus01's `on_free(self)`.

### Locating the exploitable window

`fn` sits at absolute struct offset `0x68`. `update_construct`'s write
starts at offset `0x28`. `0x68 - 0x28 = 0x40` (64) — so within the same
160-byte write, byte 64 onward is the `fn` field itself.

## Retrieving the addresses, command by command

Because the offset arithmetic above puts `fn` inside the same write
that also plants the command string, no second chunk is involved at
all — unlike bonus01, where the overflow reached from one chunk into an
adjacent one. The dangling pointer already points exactly at the struct
whose function pointer is being hijacked, and the oversized `read()`
reaches it directly. This also means no heap-address leak or
chunk-adjacency tracing was needed here: the program computes
`constructs[idx]+0x28` internally and calls through
`constructs[idx]->fn` on its own, so the exploit only needs to control
the bytes at known relative offsets, never an absolute address.

Room before `fn` is `0x40` (64) bytes; `/home/flagbonus02/.pass` needs
`cat ` (4) + the 24-character path + a null = 29 bytes, comfortably
inside budget, so the literal path is used directly — no globbing
shortcut needed this time, unlike bonus01.

A single-shot payload — command string at the write's start, `system()`'s
address at byte offset 64 — worked on the first live run against the
real SUID target, with no chunk-adjacency tracing or gdb pointer probing
needed beforehand (unlike bonus01, where confirming chunk adjacency via
live breakpoints was essential before committing to a payload). The
absence of any address dependency here — only relative-offset control —
made this level notably more direct once the struct layout was
understood from disassembly.

## Exploit

Single write (`update_construct(0)`'s one `read()` call), no
interactive menu, run inside one process invocation (`subprocess.Popen`
— though unlike the canary levels, there's no per-process-random value
to worry about here; the single-invocation requirement is just because
that's the only way `main()`'s fixed call sequence executes at all):

```
payload (0xa0 = 160 bytes):
  [0x00:0x1d) = b"cat /home/flagbonus02/.pass\x00"   (29 bytes)
  [0x1d:0x40) = filler ('B')                          padding to fn's offset
  [0x40:0x48) = struct.pack("<Q", SYSTEM)              fn -> system() (LIBC_BASE + 0x58750)
  [0x48:0xa0) = filler ('C')                          spills past the struct, harmless
```

```
$ python3 exploit.py
process exited, code: 0
  [FLATLINE] ROM construct system.
  [FLATLINE] Construct manager v2.0
[FLATLINE] Construct 0 created: DIXIE
[FLATLINE] Construct 1 created: WINTERMUTE
[FLATLINE] Deleting construct 0
[FLATLINE] Update data for construct 0: l2asy8pwncmqtbwfsu12w1hfv3yf6c30
[FLATLINE] Construct 0 updated.
```

Unlike bonus01, the process exits cleanly (exit code 0) — no follow-up
`free()` ever touches the corrupted chunk, since `main()` has nothing
left to do once `run_construct(0)` returns.

Verified this string works as `bonus03`'s SSH password.

