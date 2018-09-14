/*
 * Author: Daniel Liscinsky
 */


#ifndef __LIBC_REIMPL_H
#define __LIBC_REIMPL_H


#include <linux/version.h>
#include <sys/types.h>



// ##########################################################################################
//							Re-implemented wrappers for syscalls
//					http://man7.org/linux/man-pages/man2/syscalls.2.html
// ##########################################################################################

//#define close(x) __close(x)
//#define dup2(x) __dup2(x)
#define init_module(a, b, c) __init_module(a, b, c)
#define finit_module(a, b, c) __finit_module(a, b, c)
//#define fork() __fork()

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
//#define geteuid() __geteuid()
#else
#define geteuid32() __geteuid32()
//#define geteuid() __geteuid32()
#define geteuid(void) __geteuid32(void)
#endif
/*
#define open(x) __open(x)
#define pipe(x) __pipe(x)
#define socket(x) __socket(x)
#define write(x) __write(x)
*/


// ##########################################################################################
//								Other re-implemented functions
//	
// ##########################################################################################

#define strlen(x) __strlen(x)



// ##########################################################################################
//							Re-implemented function prototypes for syscalls
//	
// ##########################################################################################

int __init_module(void *module_image, unsigned long len, const char *param_values);
int __finit_module(int fd, const char *param_values, int flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
//uid_t __geteuid();
#else
uid_t __geteuid32();
#endif



// ##########################################################################################
//							Other re-implemented function prototypes
//	
// ##########################################################################################

//



#endif // __LIBC_REIMPL_H