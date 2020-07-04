#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x45ab460b, "module_layout" },
	{ 0x1408b55d, "kmalloc_caches" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x409bcb62, "mutex_unlock" },
	{ 0x24428be5, "strncpy_from_user" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0xafd06a7a, "misc_register" },
	{ 0x8e17b3ae, "idr_destroy" },
	{ 0x977f511b, "__mutex_init" },
	{ 0x2ab7989d, "mutex_lock" },
	{ 0xb8f11603, "idr_alloc" },
	{ 0x7665a95b, "idr_remove" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0x9a1900c5, "__stack_chk_fail" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xde7eb9a9, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x20978fb9, "idr_find" },
	{ 0xf0810ec2, "misc_deregister" },
	{ 0xb1e12d81, "krealloc" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "55DD5BA8A8C06B6E542CEB5");
