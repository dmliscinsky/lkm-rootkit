/*
 * Note that the system calls are organized by the library header files which 
 * contain wrapper functions for those syscalls.
 * 
 * Author: Daniel Liscinsky
 */

#ifndef __HOOKED_KERN_SYSCALLS_H
#define __HOOKED_KERN_SYSCALLS_H


#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/socket.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif



typedef unsigned int socklen_t;

struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen;
	char            d_name[1]; // Definite length field so struct type is complete
};



void init_syscall_hooks(void);



// ##########################################################################################
//									  syscall list
//					http://man7.org/linux/man-pages/man2/syscalls.2.html
// ##########################################################################################



// ==========================================================================================
//										accept
//					http://man7.org/linux/man-pages/man2/accept.2.html
// ==========================================================================================

typedef asmlinkage int (*__accept_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef asmlinkage int (*__accept4_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);


// ==========================================================================================
//										access
//					http://man7.org/linux/man-pages/man2/access.2.html
// ==========================================================================================

typedef asmlinkage int (*__access_t)(const char *pathname, int mode);
typedef asmlinkage int (*__faccessat_t)(int dirfd, const char *pathname, int mode, int flags);


// ==========================================================================================
//										acct
//					http://man7.org/linux/man-pages/man2/acct.2.html
// ==========================================================================================

//typedef asmlinkage int (*__acct_t)(const char *filename);


// ==========================================================================================
//										chdir
//					http://man7.org/linux/man-pages/man2/chdir.2.html
// ==========================================================================================

typedef asmlinkage int (*__chdir_t)(const char *path);
//typedef asmlinkage int (*__fchdir_t)(int fd);


// ==========================================================================================
//										chmod
//					http://man7.org/linux/man-pages/man2/chmod.2.html
// ==========================================================================================

typedef asmlinkage int (*__chmod_t)(const char *pathname, mode_t mode);
//typedef asmlinkage int (*__fchmod_t)(int fd, mode_t mode);
typedef asmlinkage int (*__fchmodat_t)(int dirfd, const char *pathname, mode_t mode, int flags);


// ==========================================================================================
//										chown
//					http://man7.org/linux/man-pages/man2/chown.2.html
//					http://man7.org/linux/man-pages/man2/chown32.2.html
// ==========================================================================================

typedef asmlinkage int (*__chown_t)(const char *pathname, uid_t owner, gid_t group);
//typedef asmlinkage int (*__fchown_t)(int fd, uid_t owner, gid_t group);
typedef asmlinkage int (*__lchown_t)(const char *pathname, uid_t owner, gid_t group);

typedef asmlinkage int (*__chown32_t)(const char *pathname, uid_t owner, gid_t group);
//typedef asmlinkage int (*__fchown32_t)(int fd, uid_t owner, gid_t group);
typedef asmlinkage int (*__lchown32_t)(const char *pathname, uid_t owner, gid_t group);

typedef asmlinkage int (*__fchownat_t)(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);


// ==========================================================================================
//										connect
//					http://man7.org/linux/man-pages/man2/connect.2.html
// ==========================================================================================

typedef asmlinkage int (*__connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);


// ==========================================================================================
//										creat
//					http://man7.org/linux/man-pages/man2/creat.2.html
// ==========================================================================================

typedef asmlinkage int (*__creat_t)(const char *pathname, mode_t mode);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
// ==========================================================================================
//										create_module
//					http://man7.org/linux/man-pages/man2/create_module.2.html
// ==========================================================================================

typedef asmlinkage caddr_t (*__create_module_t)(const char *name, size_t size);
#endif


// ==========================================================================================
//										delete_module
//					http://man7.org/linux/man-pages/man2/delete_module.2.html
// ==========================================================================================

typedef asmlinkage int (*__delete_module_t)(const char *name, int flags);


// ==========================================================================================
//										execve
//					http://man7.org/linux/man-pages/man2/execve.2.html
//					http://man7.org/linux/man-pages/man2/execveat.2.html
// ==========================================================================================

typedef asmlinkage int (*__execve_t)(const char *filename, char *const argv[], char *const envp[]);
typedef asmlinkage int (*__execveat_t)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);


// ==========================================================================================
//										fanotify_mark
//					http://man7.org/linux/man-pages/man2/fanotify_mark.2.html
// ==========================================================================================

typedef asmlinkage int (*__fanotify_mark_t)(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname);


// ==========================================================================================
//										getxattr
//					http://man7.org/linux/man-pages/man2/fgetxattr.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__getxattr_t)(const char *path, const char *name, void *value, size_t size);
typedef asmlinkage ssize_t (*__lgetxattr_t)(const char *path, const char *name, void *value, size_t size);
//typedef asmlinkage ssize_t (*__fgetxattr_t)(int fd, const char *name, void *value, size_t size);


// ==========================================================================================
//										 init_module
//					http://man7.org/linux/man-pages/man2/finit_module.2.html
// ==========================================================================================

typedef asmlinkage int (*__init_module_t)(void *module_image, unsigned long len, const char *param_values);
typedef asmlinkage int (*__finit_module_t)(int fd, const char *param_values, int flags);


// ==========================================================================================
//										listxattr
//					http://man7.org/linux/man-pages/man2/flistxattr.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__listxattr_t)(const char *path, char *list, size_t size);
typedef asmlinkage ssize_t (*__llistxattr_t)(const char *path, char *list, size_t size);
//typedef asmlinkage ssize_t (*__flistxattr_t)(int fd, char *list, size_t size);


// ==========================================================================================
//										fork
//					http://man7.org/linux/man-pages/man2/fork.2.html
// ==========================================================================================

//typedef asmlinkage pid_t (*__fork_t)(void);


// ==========================================================================================
//										removexattr
//					http://man7.org/linux/man-pages/man2/fremovexattr.2.html
// ==========================================================================================

typedef asmlinkage int (*__removexattr_t)(const char *path, const char *name);
typedef asmlinkage int (*__lremovexattr_t)(const char *path, const char *name);
//typedef asmlinkage int (*__fremovexattr_t)(int fd, const char *name);


// ==========================================================================================
//										setxattr
//					http://man7.org/linux/man-pages/man2/fsetxattr.2.html
// ==========================================================================================

typedef asmlinkage int (*__setxattr_t)(const char *path, const char *name, const void *value, size_t size, int flags);
typedef asmlinkage int (*__lsetxattr_t)(const char *path, const char *name, const void *value, size_t size, int flags);
//typedef asmlinkage int (*__fsetxattr_t)(int fd, const char *name, const void *value, size_t size, int flags);


// ==========================================================================================
//										stat
//					http://man7.org/linux/man-pages/man2/fstat.2.html
// ==========================================================================================

typedef asmlinkage int (*__stat_t)(const char *pathname, struct stat *statbuf);
//typedef asmlinkage int (*__fstat_t)(int fd, struct stat *statbuf);
typedef asmlinkage int (*__lstat_t)(const char *pathname, struct stat *statbuf);

typedef asmlinkage int (*__stat64_t)(const char *pathname, struct stat *statbuf);
//typedef asmlinkage int (*__fstat64_t)(int fd, struct stat *statbuf);
typedef asmlinkage int (*__lstat64_t)(const char *pathname, struct stat *statbuf);

typedef asmlinkage int (*__fstatat_t)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
typedef asmlinkage int (*__fstatat64_t)(int dirfd, const char *pathname, struct stat *statbuf, int flags);


// ==========================================================================================
//										statfs
//					http://man7.org/linux/man-pages/man2/fstatfs.2.html
// ==========================================================================================

typedef asmlinkage int (*__statfs_t)(const char *path, struct statfs *buf);
//typedef asmlinkage int (*__fstatfs_t)(int fd, struct statfs *buf);
typedef asmlinkage int (*__statfs64_t)(const char *path, struct statfs64 *buf);
//typedef asmlinkage int (*__fstatfs64_t)(int fd, struct statfs64 *buf);


// ==========================================================================================
//										truncate
//					http://man7.org/linux/man-pages/man2/ftruncate.2.html
// ==========================================================================================

typedef asmlinkage int (*__truncate_t)(const char *path, off_t length);
//typedef asmlinkage int (*__ftruncate_t)(int fd, off_t length);
typedef asmlinkage int (*__truncate64_t)(const char *path, off_t length);
//typedef asmlinkage int (*__ftruncate64_t)(int fd, off_t length);


// ==========================================================================================
//										futimesat								(Obsolete)
//					http://man7.org/linux/man-pages/man2/futimesat.2.html
// ==========================================================================================

typedef asmlinkage int (*__futimesat_t)(int dirfd, const char *pathname, const struct timeval times[2]);


// ==========================================================================================
//										getcwd
//					http://man7.org/linux/man-pages/man2/getcwd.2.html
// ==========================================================================================

//typedef asmlinkage char * (*__getcwd_t)(char *buf, size_t size);
//typedef asmlinkage char * (*__getwd_t)(char *buf);
//typedef asmlinkage char * (*__get_current_dir_name_t)(void);


// ==========================================================================================
//										getdents
//					http://man7.org/linux/man-pages/man2/getdents.2.html
// ==========================================================================================

typedef asmlinkage int (*__getdents_t)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
typedef asmlinkage int (*__getdents64_t)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);


// ==========================================================================================
//										getpeername
//					http://man7.org/linux/man-pages/man2/getpeername.2.html
// ==========================================================================================

typedef asmlinkage int (*__getpeername_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);


// ==========================================================================================
//										getpgid, setpgid
//					http://man7.org/linux/man-pages/man2/getpgid.2.html
// ==========================================================================================

typedef asmlinkage int (*__setpgid_t)(pid_t pid, pid_t pgid);
typedef asmlinkage pid_t (*__getpgid_t)(pid_t pid);

//typedef asmlinkage pid_t (*__getpgrp_t)(void);				/* POSIX.1 version */
typedef asmlinkage pid_t (*__getpgrp_t)(pid_t pid);				/* BSD version */

//typedef asmlinkage int (*__setpgrp_t)(void);					/* System V version */
typedef asmlinkage int (*__setpgrp_t)(pid_t pid, pid_t pgid);	/* BSD version */


// ==========================================================================================
//										getsid
//					http://man7.org/linux/man-pages/man2/getsid.2.html
// ==========================================================================================

typedef asmlinkage pid_t (*__getsid_t)(pid_t pid);


// ==========================================================================================
//									getsockopt, setsockopt
//					http://man7.org/linux/man-pages/man2/getsockopt.2.html
// ==========================================================================================

//typedef asmlinkage int (*__getsockopt_t)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
typedef asmlinkage int (*__setsockopt_t)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);


// ==========================================================================================
//										inotify_add_watch
//					http://man7.org/linux/man-pages/man2/inotify_add_watch.2.html
// ==========================================================================================

typedef asmlinkage int (*__inotify_add_watch_t)(int fd, const char *pathname, uint32_t mask);


// ==========================================================================================
//										kcmp
//					http://man7.org/linux/man-pages/man2/kcmp.2.html
// ==========================================================================================

typedef asmlinkage int (*__kcmp_t)(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);


// ==========================================================================================
//										kexec_load
//					http://man7.org/linux/man-pages/man2/kexec_file_load.2.html
// ==========================================================================================

typedef asmlinkage long (*__kexec_load_t)(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
typedef asmlinkage long (*__kexec_file_load_t)(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);


// ==========================================================================================
//										kill
//					http://man7.org/linux/man-pages/man2/kill.2.html
// ==========================================================================================

typedef asmlinkage int (*__kill_t)(pid_t pid, int sig);


// ==========================================================================================
//										link
//					http://man7.org/linux/man-pages/man2/link.2.html
// ==========================================================================================

typedef asmlinkage int (*__link_t)(const char *oldpath, const char *newpath);
typedef asmlinkage int (*__linkat_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);


// ==========================================================================================
//										lookup_dcookies
//					http://man7.org/linux/man-pages/man2/lookup_dcookie.2.html
// ==========================================================================================

//typedef asmlinkage int (*__lookup_dcookie_t)(u64 cookie, char *buffer, size_t len);


// ==========================================================================================
//										migrate_pages
//					http://man7.org/linux/man-pages/man2/migrate_pages.2.html
// ==========================================================================================

typedef asmlinkage long (*__migrate_pages_t)(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);


// ==========================================================================================
//										mkdir
//					http://man7.org/linux/man-pages/man2/mkdir.2.html
// ==========================================================================================

typedef asmlinkage int (*__mkdir_t)(const char *pathname, mode_t mode);
typedef asmlinkage int (*__mkdirat_t)(int dirfd, const char *pathname, mode_t mode);


// ==========================================================================================
//										mknod
//					http://man7.org/linux/man-pages/man2/mknod.2.html
// ==========================================================================================

typedef asmlinkage int (*__mknod_t)(const char *pathname, mode_t mode, dev_t dev);
typedef asmlinkage int (*__mknodat_t)(int dirfd, const char *pathname, mode_t mode, dev_t dev);


// ==========================================================================================
//										mount
//					http://man7.org/linux/man-pages/man2/mount.2.html
// ==========================================================================================

typedef asmlinkage int (*__mount_t)(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);


// ==========================================================================================
//										open
//					http://man7.org/linux/man-pages/man2/open.2.html
// ==========================================================================================

typedef asmlinkage int (*__open_t)(const char *pathname, int flags, mode_t mode);
typedef asmlinkage int (*__openat_t)(int dirfd, const char *pathname, int flags, mode_t mode);


// ==========================================================================================
//										open_by_handle_at
//					http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
// ==========================================================================================

typedef asmlinkage int (*__name_to_handle_at_t)(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
typedef asmlinkage int (*__open_by_handle_at_t)(int mount_fd, struct file_handle *handle, int flags);


// ==========================================================================================
//										ptrace
//					http://man7.org/linux/man-pages/man2/ptrace.2.html
// ==========================================================================================

typedef asmlinkage long (*__ptrace_t)(enum __ptrace_request request, pid_t pid, void *addr, void *data);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
// ==========================================================================================
//										query_module
//					http://man7.org/linux/man-pages/man2/query_module.2.html
// ==========================================================================================

typedef asmlinkage int (*__query_module_t)(const char *name, int which, void *buf, size_t bufsize, size_t *ret);
#endif


// ==========================================================================================
//										read
//					http://man7.org/linux/man-pages/man2/read.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__read_t)(int fd, void *buf, size_t count);


// ==========================================================================================
//										readdir
//					http://man7.org/linux/man-pages/man2/readdir.2.html
// ==========================================================================================

typedef asmlinkage int (*__readdir_t)(unsigned int fd, struct old_linux_dirent *dirp, unsigned int count);


// ==========================================================================================
//										readlink
//					http://man7.org/linux/man-pages/man2/readlink.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__readlink_t)(const char *pathname, char *buf, size_t bufsiz);
typedef asmlinkage ssize_t (*__readlinkat_t)(int dirfd, const char *pathname, char *buf, size_t bufsiz);


// ==========================================================================================
//										reboot
//					http://man7.org/linux/man-pages/man2/reboot.2.html
// ==========================================================================================

typedef asmlinkage int (*__reboot_t)(int cmd);


// ==========================================================================================
//										recv
//					http://man7.org/linux/man-pages/man2/recv.2.html
//					http://man7.org/linux/man-pages/man2/recvmmsg.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__recv_t)(int sockfd, void *buf, size_t len, int flags);
typedef asmlinkage ssize_t (*__recvfrom_t)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
typedef asmlinkage ssize_t (*__recvmsg_t)(int sockfd, struct msghdr *msg, int flags);
typedef asmlinkage int (*__recvmmsg_t)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);


// ==========================================================================================
//										rename
//					http://man7.org/linux/man-pages/man2/rename.2.html
// ==========================================================================================

typedef asmlinkage int (*__rename_t)(const char *oldpath, const char *newpath);
typedef asmlinkage int (*__renameat_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
typedef asmlinkage int (*__renameat2_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);


// ==========================================================================================
//										rmdir
//					http://man7.org/linux/man-pages/man2/rmdir.2.html
// ==========================================================================================

typedef asmlinkage int (*__rmdir_t)(const char *pathname);


// ==========================================================================================
//										send
//					http://man7.org/linux/man-pages/man2/send.2.html
// 					http://man7.org/linux/man-pages/man2/sendmmsg.2.html
// ==========================================================================================

typedef asmlinkage ssize_t (*__send_t)(int sockfd, const void *buf, size_t len, int flags);
typedef asmlinkage ssize_t (*__sendto_t)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef asmlinkage ssize_t (*__sendmsg_t)(int sockfd, const struct msghdr *msg, int flags);
typedef asmlinkage int (*__sendmmsg_t)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);


// ==========================================================================================
//										shutdown
//					http://man7.org/linux/man-pages/man2/shutdown.2.html
// ==========================================================================================

typedef asmlinkage int (*__shutdown_t)(int sockfd, int how);


// ==========================================================================================
//										socketcall
//					http://man7.org/linux/man-pages/man2/socketcall.2.html
// ==========================================================================================

typedef asmlinkage int (*__socketcall_t)(int call, unsigned long *args);


// ==========================================================================================
//										statx
//					http://man7.org/linux/man-pages/man2/statx.2.html
// ==========================================================================================

typedef asmlinkage int (*__statx_t)(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);


// ==========================================================================================
//										swapon
//					http://man7.org/linux/man-pages/man2/swapon.2.html
// ==========================================================================================

typedef asmlinkage int (*__swapon_t)(const char *path, int swapflags);
typedef asmlinkage int (*__swapoff_t)(const char *path);


// =========================================================================================
//										symlink
//					http://man7.org/linux/man-pages/man2/symlinkat.2.html
// ==========================================================================================

typedef asmlinkage int (*__symlink_t)(const char *target, const char *linkpath);
typedef asmlinkage int (*__symlinkat_t)(const char *target, int newdirfd, const char *linkpath);


// =========================================================================================
//										unlink
//					http://man7.org/linux/man-pages/man2/unlink.2.html
// ==========================================================================================

typedef asmlinkage int (*__unlink_t)(const char *pathname);
typedef asmlinkage int (*__unlinkat_t)(int dirfd, const char *pathname, int flags);


// =========================================================================================
//										utime
//					http://man7.org/linux/man-pages/man2/utime.2.html
// ==========================================================================================

typedef asmlinkage int (*__utime_t)(const char *filename, const struct utimbuf *times);
typedef asmlinkage int (*__utimes_t)(const char *filename, const struct timeval times[2]);

// =========================================================================================
//										utimens
//					http://man7.org/linux/man-pages/man2/utimensat.2.html
// ==========================================================================================

typedef asmlinkage int (*__utimensat_t)(int dirfd, const char *pathname, const struct timespec times[2], int flags);
typedef asmlinkage int (*__futimens_t)(int fd, const struct timespec times[2]);


// =========================================================================================
//										write
//					http://man7.org/linux/man-pages/man2/write.2.html
// ==========================================================================================
typedef asmlinkage ssize_t (*__write_t)(int fd, const void *buf, size_t count);





// ##########################################################################################
//									  Original syscalls
//	
// ##########################################################################################

__accept_t		orig_accept = NULL;
__accept4_t		orig_accept4 = NULL;

__access_t		orig_access = NULL;
__faccessat_t	orig_faccessat = NULL;

__chdir_t		orig_chdir = NULL;

__chmod_t		orig_chmod = NULL;
__fchmodat_t	orig_fchmodat = NULL;

__chown_t		orig_chown = NULL;
__lchown_t		orig_lchown = NULL;
__chown32_t		orig_chown32 = NULL;
__lchown32_t	orig_lchown32 = NULL;
__fchownat_t	orig_fchownat = NULL;

__connect_t		orig_connect = NULL;

__creat_t		orig_creat = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
__create_module_t	orig_create_module = NULL;
#endif

__delete_module_t	orig_delete_module = NULL;

__execve_t			orig_execve = NULL;
__execveat_t		orig_execveat = NULL;

__fanotify_mark_t	orig_fanotify_mark = NULL;


__getxattr_t		orig_getxatt = NULL;
__lgetxattr_t		orig_lgetxattr = NULL;
//__fgetxattr_t		orig_fgetxattr = NULL;

__init_module_t		orig_init_module = NULL;
__finit_module_t	orig_finit_module = NULL;

__listxattr_t		orig_listxattr = NULL;
__llistxattr_t		orig_llistxattr = NULL;
//__flistxattr_t	orig_flistxattr = NULL;

//__fork_t			orig_fork = NULL;

__removexattr_t		orig_removexattr = NULL;
__lremovexattr_t	orig_lremovexattr = NULL;
//__fremovexattr_t	orig_fremovexattr = NULL;

__setxattr_t	orig_setxattr = NULL;
__lsetxattr_t	orig_lsetxattr = NULL;
//__fsetxattr_t orig_fsetxattr = NULL;

__stat_t		orig_stat = NULL;
//__fstat_t		orig_fstat = NULL;
__lstat_t		orig_lstat = NULL;
__stat64_t		orig_stat64 = NULL;
//__fstat64_t	orig_fstat64 = NULL;
__lstat64_t		orig_lstat64 = NULL;
__fstatat_t		orig_fstatat = NULL;
__fstatat64_t	orig_fstatat64 = NULL;

__statfs_t		orig_statfs = NULL;
//__fstatfs_t	orig_fstatf = NULL;
__statfs64_t	orig_statfs64 = NULL;
//__fstatfs64_t orig_fstatfs64 = NULL;

__truncate_t	orig_truncate = NULL;
//__ftruncate_t orig_ftruncate = NULL;
__truncate64_t	orig_truncate64 = NULL;
//__ftruncate64_t orig_ftruncate64 = NULL;

__futimesat_t 	orig_futimesat = NULL;

//__getcwd_t	orig_getcwd = NULL;
//__getwd_t		orig_getwd = NULL;
//__get_current_dir_name_t orig_get_current_dir_name = NULL;

__getdents_t	orig_getdents = NULL;
__getdents64_t	orig_getdents64 = NULL;

__getpeername_t orig_getpeername = NULL;

__setpgid_t		orig_setpgid = NULL;
__getpgid_t		orig_getpgid = NULL;
//__getpgrp_t	orig_getpgrp = NULL;
__getpgrp_t		orig_getpgrp = NULL;
//__setpgrp_t	orig_setpgrp = NULL;
__setpgrp_t		orig_setpgrp = NULL;

__getsid_t		orig_getsid = NULL;

//__getsockopt_t		orig_getsockopt = NULL;
__setsockopt_t			orig_setsockopt = NULL;

__inotify_add_watch_t	orig_notify_add_watch = NULL;

__kcmp_t				orig_kcmp = NULL;

__kexec_load_t			orig_kexec_load = NULL;
__kexec_file_load_t		orig_kexec_file_load = NULL;

__kill_t				orig_kill = NULL;

__link_t				orig_link = NULL;
__linkat_t				orig_linkat = NULL;

//__lookup_dcookie_t	orig_lookup_dcookie = NULL;

__migrate_pages_t		orig_migrate_pages = NULL;

__mkdir_t		orig_mkdir = NULL;
__mkdirat_t		orig_mkdirat = NULL;

__mknod_t		orig_mknod = NULL;
__mknodat_t		orig_mknodat = NULL;

__mount_t		orig_mount = NULL;

__open_t orig_open = NULL;
__openat_t orig_openat = NULL;

__name_to_handle_at_t orig_name_to_handle_at = NULL;
__open_by_handle_at_t orig_open_by_handle_at = NULL;

__ptrace_t orig_ptrace = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
__query_module_t orig_query_module = NULL;
#endif

__read_t orig_read = NULL;

__readdir_t orig_readdir = NULL;

__readlink_t orig_readlink = NULL;
__readlinkat_t orig_readlinkat = NULL;

__reboot_t orig_reboot = NULL;

__recv_t orig_recv = NULL;
__recvfrom_t orig_recvfrom = NULL;
__recvmsg_t orig_recvmsg = NULL;
__recvmmsg_t orig_recvmmsg = NULL;

__rename_t orig_rename = NULL;
__renameat_t orig_renameat = NULL;
__renameat2_t orig_renameat2 = NULL;

__rmdir_t orig_rmdir = NULL;

__send_t orig_send = NULL;
__sendto_t orig_sendto = NULL;
__sendmsg_t orig_sendmsg = NULL;
__sendmmsg_t orig_sendmmsg = NULL;

__shutdown_t orig_shutdown = NULL;

__socketcall_t orig_socketcall = NULL;

__statx_t orig_statx = NULL;

__swapon_t orig_swapon = NULL;
__swapoff_t orig_swapoff = NULL;

__symlink_t orig_symlink = NULL;
__symlinkat_t orig_symlinkat = NULL;

__unlink_t orig_unlink = NULL;
__unlinkat_t orig_unlinkat = NULL;

__utime_t orig_utime = NULL;
__utimes_t orig_utimes = NULL;

__utimensat_t orig_utimensat = NULL;
__futimens_t orig_futimens = NULL;

__write_t orig_write = NULL;





// ##########################################################################################
//									  Hooked syscalls
//	
// ##########################################################################################

asmlinkage int hooked_access(const char *pathname, int mode);
asmlinkage int hooked_faccessat(int dirfd, const char *pathname, int mode, int flags);

asmlinkage int hooked_chmod(const char *pathname, mode_t mode);
//asmlinkage int hooked_fchmod(int fd, mode_t mode);
asmlinkage int hooked_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);

asmlinkage int hooked_creat(const char *pathname, mode_t mode);

asmlinkage int hooked_delete_module(const char *name, int flags);

asmlinkage int hooked_execve(const char *filename, char *const argv[], char *const envp[]);
asmlinkage int hooked_execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);

asmlinkage int hooked_init_module(void *module_image, unsigned long len, const char *param_values);
asmlinkage int hooked_finit_module(int fd, const char *param_values, int flags);

asmlinkage int hooked_stat(const char *pathname, struct stat *statbuf);
//asmlinkage int hooked_fstat(int fd, struct stat *statbuf);
asmlinkage int hooked_lstat(const char *pathname, struct stat *statbuf);
asmlinkage int hooked_stat64(const char *pathname, struct stat *statbuf);
//asmlinkage int hooked_fstat64(int fd, struct stat *statbuf);
asmlinkage int hooked_lstat64(const char *pathname, struct stat *statbuf);
asmlinkage int hooked_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
asmlinkage int hooked_fstatat64(int dirfd, const char *pathname, struct stat *statbuf, int flags);

asmlinkage int hooked_truncate(const char *path, off_t length);
//asmlinkage int hooked_ftruncate(int fd, off_t length);
asmlinkage int hooked_truncate64(const char *path, off_t length);
//asmlinkage int hooked_ftruncate64(int fd, off_t length);

asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

asmlinkage long hooked_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
asmlinkage long hooked_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);

asmlinkage int hooked_kill(pid_t pid, int sig);

asmlinkage int hooked_link(const char *oldpath, const char *newpath);
asmlinkage int hooked_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);


asmlinkage int hooked_open(const char *pathname, int flags, mode_t mode);
asmlinkage int hooked_openat(int dirfd, const char *pathname, int flags, mode_t mode);
asmlinkage int hooked_name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
asmlinkage int hooked_open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);

//asmlinkage long hooked_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
asmlinkage int hooked_query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret);
#endif

//asmlinkage ssize_t hooked_read(int fd, void *buf, size_t count);

//asmlinkage int hooked_readdir(unsigned int fd, struct old_linux_dirent *dirp, unsigned int count);

asmlinkage ssize_t hooked_readlink(const char *pathname, char *buf, size_t bufsiz);
asmlinkage ssize_t hooked_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);

asmlinkage int hooked_reboot(int cmd);

asmlinkage ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags);
asmlinkage ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
asmlinkage ssize_t hooked_recvmsg(int sockfd, struct msghdr *msg, int flags);
//asmlinkage int hooked_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

asmlinkage int hooked_rename(const char *oldpath, const char *newpath);
asmlinkage int hooked_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
asmlinkage int hooked_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);

asmlinkage int hooked_rmdir(const char *pathname);

asmlinkage ssize_t hooked_send(int sockfd, const void *buf, size_t len, int flags);
asmlinkage ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
asmlinkage ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg, int flags);
//asmlinkage int hooked_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);

//asmlinkage int hooked_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
//asmlinkage int hooked_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

//asmlinkage int hooked_shutdown(int sockfd, int how);

//asmlinkage int hooked_socketcall(int call, unsigned long *args);

asmlinkage int hooked_statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);

asmlinkage int hooked_swapon(const char *path, int swapflags);
asmlinkage int hooked_swapoff(const char *path);

asmlinkage int hooked_symlink(const char *target, const char *linkpath);
asmlinkage int hooked_symlinkat(const char *target, int newdirfd, const char *linkpath);

asmlinkage int hooked_unlink(const char *pathname);
asmlinkage int hooked_unlinkat(int dirfd, const char *pathname, int flags);

asmlinkage int hooked_utime(const char *filename, const struct utimbuf *times);
asmlinkage int hooked_utimes(const char *filename, const struct timeval times[2]);

asmlinkage int hooked_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
//asmlinkage int hooked_futimens(int fd, const struct timespec times[2]);

asmlinkage ssize_t hooked_write(int fd, const void *buf, size_t count);



#endif // __HOOKED_KERN_SYSCALLS_H