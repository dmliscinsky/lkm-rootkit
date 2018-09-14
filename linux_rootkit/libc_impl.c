/*
 * A re-implementation of parts of libc (or commonly used c functions).
 * 
 * Author: Daniel Liscinsky
 */


#include "libc_impl.h"



int __init_module(void *module_image, unsigned long len, const char *param_values) {
	int ret_value = -1;
	#ifdef __i386__
	asm(
		"mov $128, %%eax;" //init_module syscall number
		"mov %1, %%ebx;"
		"mov %2, %%ecx;"
		"mov %3, %%edx;"
		"int $0x80;"
		"mov %%eax, %0;"
		:"=r" (ret_value) //output
		:"r" (module_image), "r" (len), "r" (param_values) //input
		:"eax", "ebx", "ecx", "edx"
	);
	#elif __amd64__
	__asm__(
		"mov $175, %%rax;" //init_module syscall number
		"mov %1, %%rdi;"
		"mov %2, %%rsi;"
		"mov %3, %%rdx;"
		"syscall;"
		"mov %%eax, %0;"
		:"=r" (ret_value) //output
		:"r" (module_image), "r" (len), "r" (param_values) //input
		:"rax", "rdi", "rsi", "rdx"
	);
	#endif
	return ret_value;
}

int __finit_module(int fd, const char *param_values, int flags) {
	int ret_value = -1;
	#ifdef __amd64__
	__asm__(
		"mov $313, %%rax;" //finit_module syscall number
		"mov %1, %%edi;"
		"mov %2, %%rsi;"
		"mov %3, %%edx;"
		"syscall;"
		"mov %%eax, %0;"
		:"=r" (ret_value) //output
		:"r" (fd), "r" (param_values), "r" (flags) //input
		:"rax", "edi", "rsi", "edx"
	);
	#endif
	return ret_value;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
//uid_t __geteuid() {}
#else
uid_t __geteuid32() {
	uid_t euid;
	#ifdef __i386__
	asm(
		"mov $49, %%eax;" //geteuid syscall number
		"int $0x80;"
		"mov %%eax, %0;"
		:"=r" (euid) //output
		:			 //input
		:"eax"
	);
	#elif __amd64__
	__asm__(
		"mov $107, %%rax;" //geteuid syscall number
		"syscall;"
		"mov %%eax, %0;"
		:"=r" (euid) //output
		:			 //input
		:"rax"
	);
	#endif
	return euid;
}
#endif

size_t __strlen(const char *str) {

	size_t len = 0;
	while (*(str++)) {
		len++;
	}

	return len;
}