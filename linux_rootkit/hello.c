/*
 * Author: Daniel Liscinsky
 */



#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif


#include <asm/errno.h>
#include <linux/mman.h>
#include <asm/proto.h>
#include <asm/delay.h>
#include <linux/highmem.h>
#include <asm/desc.h>



/* Initialize the LKM */
int init_module() {

	pr_info("Hello world kernel module!\n");
	/* More normal is printk(), but there's less that can go wrong with 
	console_print(), so let's start simple.
	*/
	
	/* If we return a non zero value, it means that 
	* init_module failed and the LKM can't be loaded */
	return 0;
}

/* 
 * Cleanup - undo whatever init_module() did.
 */
void cleanup_module() {

	pr_info("Good bye world kernel module!\n");
}