//5.7.0

//kzalloc:
//include/linux/slab.h:662:

/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kzalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags | __GFP_ZERO);
}

// cat /proc/kallsyms | grep "T _text" (requires root)
//*****************


// how to get __vdso_gettimeofday offset of running qemu?
// 1) dump vdso in QEMU using dump_vdso.c
// 2) xxd -r -p vdso.dump vdso.bin
// 3) strings -t x vdso.bin | grep __vdso_gettimeofday
//     2c6 __vdso_gettimeofday

// gef➤  p __vdso_gettimeofday
// $1 = {<text variable, no debug info>} 0xc80 <gettimeofday>