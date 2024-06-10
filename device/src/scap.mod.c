#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
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
__used __section("__versions") = {
	{ 0x6ad771c3, "module_layout" },
	{ 0xddef5acd, "d_path" },
	{ 0xa8301e4d, "tracepoint_probe_register" },
	{ 0x11eb121f, "cdev_del" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xd90cd7e6, "cdev_init" },
	{ 0xc4f0da12, "ktime_get_with_offset" },
	{ 0x90b630c0, "__cpuhp_remove_state" },
	{ 0x2691d4b5, "for_each_kernel_tracepoint" },
	{ 0xfce45a74, "sockfd_lookup" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x9c76681d, "inode_permission" },
	{ 0x754d539c, "strlen" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0xc1d8cfaf, "__fdget" },
	{ 0xc9bfdad6, "from_kuid_munged" },
	{ 0xcb2f2b52, "boot_cpu_data" },
	{ 0x4ac84b8, "param_set_ulong" },
	{ 0x15659e9d, "device_destroy" },
	{ 0x949f7342, "__alloc_percpu" },
	{ 0x83253110, "param_ops_bool" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x999e8297, "vfree" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x21271fd0, "copy_user_enhanced_fast_string" },
	{ 0x33a21a09, "pv_ops" },
	{ 0xc9ec4e21, "free_percpu" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xaa44a707, "cpumask_next" },
	{ 0xb6b09666, "from_kgid_munged" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x90dc1eb1, "inode_owner_or_capable" },
	{ 0xb8e7ce2c, "__put_user_8" },
	{ 0x5c3c7387, "kstrtoull" },
	{ 0xdad13544, "ptrs_per_p4d" },
	{ 0x9e523753, "tracepoint_srcu" },
	{ 0x9e683f75, "__cpu_possible_mask" },
	{ 0xc4cdc804, "from_kuid" },
	{ 0x3744cf36, "vmalloc_to_pfn" },
	{ 0xa22a96f7, "current_task" },
	{ 0x5a5a2271, "__cpu_online_mask" },
	{ 0x1f199d24, "copy_user_generic_string" },
	{ 0x5a921311, "strncmp" },
	{ 0x5792f848, "strlcpy" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x70eb7a97, "device_create" },
	{ 0xc374de49, "task_cputime_adjusted" },
	{ 0x55385e2e, "__x86_indirect_thunk_r14" },
	{ 0x701f84a9, "pid_task" },
	{ 0x1d19f77b, "physical_mask" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0x1944a87d, "__cpuhp_setup_state" },
	{ 0xfcb49325, "fput" },
	{ 0x976026fd, "__task_pid_nr_ns" },
	{ 0x646eac6, "cdev_add" },
	{ 0xecdcabd2, "copy_user_generic_unrolled" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x84c49cc0, "init_task" },
	{ 0x4531ab62, "copy_from_kernel_nofault" },
	{ 0xa916b694, "strnlen" },
	{ 0x6a5cb5ee, "__get_free_pages" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x92997ed8, "_printk" },
	{ 0xed238617, "__put_cred" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xa07399db, "param_get_ulong" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xb19a5453, "__per_cpu_offset" },
	{ 0x4302d0eb, "free_pages" },
	{ 0x7e9043b8, "synchronize_srcu" },
	{ 0x6eefdc9d, "init_pid_ns" },
	{ 0x37a0cba, "kfree" },
	{ 0xa83f8817, "remap_pfn_range" },
	{ 0x72d79d83, "pgdir_shift" },
	{ 0x69acdf38, "memcpy" },
	{ 0x86388923, "fget" },
	{ 0xb3f0559, "class_destroy" },
	{ 0xe01db2c0, "kernfs_path_from_node" },
	{ 0x1020fa76, "task_active_pid_ns" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb0e602eb, "memmove" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xf757d730, "param_ops_uint" },
	{ 0x52ea150d, "__class_create" },
	{ 0x272a6d7d, "find_pid_ns" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0xc769ff48, "tracepoint_probe_unregister" },
	{ 0x8a35b432, "sme_me_mask" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D55618EBAAD6EA963C865AE");
