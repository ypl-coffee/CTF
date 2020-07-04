#include <fcntl.h>
#include <stdio.h>
#include <sys/auxv.h> 
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(void)
{
	unsigned long vdso = getauxval(AT_SYSINFO_EHDR);

	if (vdso != 0) {
		for (int i = 0; i < 0x2000; i++)
			printf("%02x ", *(unsigned char *)(vdso + i));
	}
	return 0;
}
