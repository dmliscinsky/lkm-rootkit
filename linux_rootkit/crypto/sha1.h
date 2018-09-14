/*
 * A modified SHA-1 implementation for use in kernel modules.
 * 
 * Author: Daniel Liscinsky
 */

/*
 * SHA-1 in C
 * https://raw.githubusercontent.com/clibs/sha1/master/sha1.h
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */



#ifndef SHA1_H
#define SHA1_H


#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <inttypes.h>
#endif


#define SHA1_HASH_LENGTH 20 // 20 bytes



typedef struct
{
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
	uint32_t state[5],
	const unsigned char buffer[64]
);

void SHA1Init(
	SHA1_CTX * context
);

void SHA1Update(
	SHA1_CTX * context,
	const unsigned char *data,
	uint32_t len
);

void SHA1Final(
	unsigned char digest[20],
	SHA1_CTX * context
);

void SHA1(
	char *hash_out,
	const char *str,
	int len);

#endif /* SHA1_H */