/*
 * Reserve (physical) space in the executible file to store the rootkit kernel module file.
 * 
 * Author: Daniel Liscinsky
 */

#ifndef __PAYLOAD_KERNEL_ROOTKIT_H
#define __PAYLOAD_KERNEL_ROOTKIT_H


#define KERNEL_ROOTKIT_KO_FILESIZE  10000
const unsigned int kernel_rootkit_ko_filesize = KERNEL_ROOTKIT_KO_FILESIZE;
unsigned char kernel_rootkit_ko[KERNEL_ROOTKIT_KO_FILESIZE] = { 0xff };


#endif