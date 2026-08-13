# bonus01 — "Zion" — Heap Overflow → Function-Pointer Hijack (PIE)

## Concept

`./zion`, SUID owned by `flagbonus01`, home dir `/home/bonus01/`. First
bonus level, and the first genuinely new bug class in this project: a
heap overflow corrupting an allocation-metadata struct that holds a
callback function pointer, rather than a stack-frame return-address
overwrite. Also the first PIE binary encountered (every mandatory level
so far had PIE disabled).

Per the subject, bonus levels are only assessed if the mandatory portion
is complete and perfect — confirmed true as of level10 (see
`level10/resources/README.md`), and level10's flag verified as this
level's SSH password before starting.

## Recon

Login: `ssh bonus01@127.0.0.1 -p 4244`, password = level10's flag
(`6lhi9nnjkxeye0p1jh1qniao8e89f4mq`).

No source provided (unlike several mandatory levels). Started from
`nm ./zion`:

```
alloc_block       (0x1317, static offset)
default_on_free   (0x1269, static offset)
free_block        (0x1481, static offset)
list_blocks       (0x156c, static offset)
main              (0x163e, static offset)
print_banner      (0x129f, static offset)
```

`checksec ./zion`:
```
RELRO:      Full RELRO
Canary:     found
NX:         enabled
PIE:        enabled       <- new: first PIE binary in this project
```

`getent passwd flagbonus01` → uid 1028 (cross-checked against the SUID
owner name shown by `ls -la ~/zion`, both agree).

### Disassembling `main`

`gdb -batch -ex 'disas main' ./zion` shows, in order: `geteuid()` twice,
then `setreuid(euid, euid)`. This runs before anything else — meaning by
the time any application logic executes, the process's real uid is
already permanently `flagbonus01`, not just the effective uid. This is
different from most mandatory levels, where the exploit payload itself
had to call `setreuid` as part of the ROP chain. Here, no such step is
needed at all — confirmed by disassembly, not assumed.

After the uid sync: `print_banner()`, `alloc_block(0x40, "ALPHA")`,
`alloc_block(0x40, "BETA")`, `list_blocks()`, `free_block(0)`,
`free_block(1)`. No interactive menu of any kind — the whole run is this
fixed sequence.

### Disassembling `alloc_block`, `free_block`, `list_blocks`

Reconstructed (no source, so this is disassembly-derived, not literal
C) as:

```c
typedef struct {
    unsigned int id;         // offset 0
    unsigned int size;       // offset 4
    char label[16];          // offset 8
    void (*on_free)(void*);  // offset 24 (0x18), defaults to default_on_free (a no-op)
} block_meta_t;               // 32 bytes (0x20) total

void *alloc_block(unsigned int size, const char *name) {
    block_meta_t *meta = malloc(0x20);
    char *data = malloc(size);
    // (NULL checks on both, bail+free if either fails)
    meta->id = block_count;
    meta->size = size;
    meta->on_free = default_on_free;
    strncpy(meta->label, name, 15);
    blocks[block_count++] = meta;              // blocks[] is a global array at 0x4040
    printf("[ZION] Block %u allocated (%u bytes) label=%s\n", meta->id, size, name);
    printf("[ZION] Data: "); fflush(stdout);
    read(0, data, size + 0x40);                // BUG: reads size+0x40 bytes into a size-byte malloc
    free(data);
}

void free_block(unsigned int idx) {
    // bounds + NULL checks on blocks[idx]
    printf("[ZION] Freeing block %u\n", idx);
    blocks[idx]->on_free(blocks[idx]);         // indirect call; rdi = blocks[idx] itself
    free(blocks[idx]);
    blocks[idx] = NULL;
}

void list_blocks(void) {
    for each non-null blocks[i]:
        printf("[ZION] Block %u: label=%s size=%u\n", i, blocks[i]->label, blocks[i]->size);
}
```

The bug: `alloc_block` mallocs exactly `size` bytes for `data`, but
`read()`s `size + 0x40` bytes into it — a fixed 64-byte overflow past
whatever `data`'s actual chunk is, on every call (both calls in `main`
use `size = 0x40`, so 64 bytes allocated, 128 bytes read).

`list_blocks()` was checked for a pointer leak (in case a real base
leak was going to be needed) — it only prints `label` and `size`, no
raw pointers. No format-string bug anywhere either: every `printf` call
uses a fixed, hardcoded literal format string. So this level's only
available primitive is the heap write-overflow; no leak primitive
exists in the binary at all.

### Checking whether PIE actually randomizes per-run on this VM

Since `randomize_va_space=0` VM-wide was already established back in
level04's recon (and re-confirmed independently at level10 via a live
libc leak), the working assumption was that a fixed
`kernel.randomize_va_space=0` also pins PIE binaries' own load base, not
just shared-library bases — but this had never actually been exercised
on a PIE binary yet in this project, so it was checked directly rather
than assumed.

Set symbolic breakpoints (PIE requires symbolic breaks; a raw
`break *0x1463` static address fails with `Cannot access memory at
address 0x1463` until gdb has actually loaded and relocated the
binary) at `break *alloc_block+0x3b` (right after the `meta` malloc
returns) and `break *alloc_block+0x4a` (right after the `data` malloc
returns), then ran the binary under `gdb` three separate times, letting
it proceed to the first `alloc_block` call each time and printing the
returned pointers.

Result: identical addresses across all 3 runs — `meta0 =
0x55555555a2b0`, `data0 = 0x55555555a2e0` every time. Confirms PIE load
base (and thus heap layout) is just as deterministic here as every
other address space region on this VM, when ASLR is globally disabled.
This determinism is what makes hardcoding `SYSTEM` (the same fixed libc
offset, `LIBC_BASE + 0x58750`, reused from every mandatory level) valid
here too, with zero leaking needed despite PIE being on.

### Tracing chunk layout across both `alloc_block` calls

Same breakpoints, but let execution continue into the second
`alloc_block("BETA")` call:

```
call 1 ("ALPHA"): meta0 = 0x55555555a2b0,  data0 = 0x55555555a2e0
call 2 ("BETA"):  meta1 = 0x55555555a330,  data1 = 0x55555555a2e0   <- same as data0!
```

`data0`'s chunk is freed immediately after call 1's `read()` (per the
disassembly: `free(data)` right after the `read`). `data1`'s
`malloc(0x40)` — same size class as `data0`'s — comes back with the
exact same address, via glibc's tcache LIFO reuse of the just-freed
chunk. `data0`/`data1`'s chunk spans exactly 0x50 bytes (0x2e0 → 0x330,
i.e. 0x40 usable + 8-byte header, rounded up to a 16-byte boundary), and
`meta1` sits immediately adjacent at `0x330` — freshly `malloc(0x20)`'d
right after `data1`'s allocation.

## Retrieving the addresses, command by command

The chunk-layout trace above shows `data1` reusing `data0`'s freed
address via tcache LIFO, with `meta1` allocated right after it. But
reuse alone doesn't say which `alloc_block` call is the right one to
overflow: `meta1` is unconditionally initialized (`id`, `size`,
`on_free`, `label` all set) as part of call 2's own code, using
freshly-malloc'd memory whose previous contents are irrelevant. So the
overflow has to land after `meta1` is initialized and before
`free_block(1)` reads it — which means it must happen during the
*second* `alloc_block` call itself, not the first: `data1`'s
`malloc(0x40)` reuses `data0`'s chunk, `meta1` gets allocated and fully
initialized right after (the malloc/init/read/free sequence is linear
within one `alloc_block` invocation), and only then does `data1`'s own
`read()` run — writing past its 64-byte buffer directly into the
already-live `meta1` struct, with nothing left afterward to overwrite it
again before `main()` reaches `free_block(1)`.

This was verified live before building the real payload: writing
arbitrary marker bytes (`b"C"*16 + b"MARKER=="`) past the 64-byte
`data1` fill and re-running under gdb with a breakpoint just before
`free_block`'s indirect call, `x/32xb blocks[1]` showed the marker bytes
landing exactly where `meta1->label` should be — confirming the layout
before trusting it.

The hijack target is constrained by `free_block`'s own calling
convention: `blocks[idx]->on_free(blocks[idx])` unconditionally sets
`rdi = blocks[idx]`, the metadata pointer itself — there's no gadget
available through a single indirect call to redirect `rdi` elsewhere.
So the exploit has to work with this constraint: set `on_free = system`,
and arrange for the first bytes of `meta1` (what `rdi` will point to)
to spell a valid, NUL-terminated shell command. `meta1`'s first 24 bytes
(`id` + `size` + `label`, offsets 0–23) are fully attacker-controlled
via the overflow; offset 24 (`on_free`) is the last 8 bytes of the
payload. 24 bytes is not enough for `cat /home/flagbonus01/.pass\0` (29
bytes including the null), so the payload uses shell globbing instead:
`cat ../*/.pass\0` is 15 bytes, well within budget. Since the shell
process's CWD is `/home/bonus01/`, `../*` expands to every sibling home
directory (`level00`..`level10`, `flag00`..`flagbonus01`, other
`bonusNN` dirs, etc.), printing permission-denied noise for `.pass`
files this process can't read and the actual content for the one it can
(`flagbonus01`'s own, since the whole process has run as that real uid
since `main`'s opening `setreuid`) — it worked cleanly in practice with
no noise at all.

## Exploit

Two `alloc_block` calls happen automatically inside `main()`; the
exploit only needs to supply the two `read()` inputs, in one continuous
process invocation (`subprocess.Popen`, matching the pattern used for
canary levels — though here it's chunk-address determinism rather than
canary randomness driving the "one process" requirement).

```
call 1 read(): b"first\n"                       <- harmless filler, meta1 doesn't exist yet
call 2 read(): 112-byte payload:
    [0:64]   = b"A"*64                            data1 filler (up to data1's own 64-byte capacity)
    [64:80]  = b"C"*16                             padding = data1's chunk-header gap before meta1 starts
    [80:104] = b"cat ../*/.pass\x00" + b"D"*9     meta1.id/size/label -> our command, NUL-terminated
    [104:112]= struct.pack("<Q", SYSTEM)          meta1.on_free -> system() (LIBC_BASE + 0x58750)
```

`main()` then runs `free_block(1)`, which executes
`blocks[1]->on_free(blocks[1])` == `system((char*)blocks[1])` ==
`system("cat ../*/.pass")`.

```
$ python3 exploit.py
[ZION] Block 0 allocated (64 bytes) label=first
[ZION] Data: [ZION] Block 1 allocated (64 bytes) label=...
[ZION] Data: [ZION] Block 0: label=first size=64
[ZION] Block 1: label=... size=64
[ZION] Freeing block 0
[ZION] Freeing block 1
8g8nnrrtsasgf9i7etv0s9a21j5f9riw
```

The process reliably crashes shortly after with `munmap_chunk(): invalid
pointer` (SIGABRT) — expected and harmless: it comes from
`free_block`'s subsequent `free(blocks[1])` call choking on the
still-corrupted chunk metadata from our overflow, which only fires
after the `on_free` payload (and thus the flag print) has already
completed.

Verified this string works as `bonus02`'s SSH password.

