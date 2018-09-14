/*
 * Author: Daniel Liscinsky
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <linux/if_ether.h>
//#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>

#include "rte_ether.h"
#include "rte_ip.h"
#include "debug_u.h"



#define MAX_ETH_PKT_SIZE 1522



static int is_rtr_running = 0;
static int rtr_socket_fd;




/**
 * Close the socket used for forwarding traffic.
 * rtr_socket is now -1.
 */
void close_rtr_socket() {

	if (rtr_socket_fd > 0) {
		close(rtr_socket_fd);
		rtr_socket_fd = -1;
	}
}

int recv_frame(int sockfd, char *buf, unsigned int len) {

	
	int size;

	// Ensure valid socket
	if (sockfd < 0) {
		return -1;
	}


	// Receive message
	//size = sock_recvmsg(sock, &msg, msg.msg_flags);

	return size;
	
}

int load_my_ip_addrs() {

	struct ifaddrs *my_addrs, *ifa;

	int family, s, n;
	char host[NI_MAXHOST];


	if (getifaddrs(&my_addrs) < 0){
		return -1;
	}

	ifa = my_addrs;
	while (ifa)
	{
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET)
			printf("%s\n", ifa->ifa_name);

		ifa = ifa->ifa_next;
	}

	for (ifa = my_addrs, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		/* Display interface name and family (including symbolic
		form of the latter for the common families) */

		printf("%-8s %s (%d)\n",
			ifa->ifa_name,
			(family == AF_PACKET) ? "AF_PACKET" :
			(family == AF_INET) ? "AF_INET" :
			(family == AF_INET6) ? "AF_INET6" : "???",
			family);

		/* For an AF_INET* interface address, display the address */

		if (family == AF_INET || family == AF_INET6) {
			s = getnameinfo(ifa->ifa_addr,
				(family == AF_INET) ? sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6),
				host, NI_MAXHOST,
				NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}

			printf("\t\taddress: <%s>\n", host);

		} else if (family == AF_PACKET && ifa->ifa_data != NULL) {
			struct rtnl_link_stats *stats = ifa->ifa_data;

			printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
				"\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
				stats->tx_packets, stats->rx_packets,
				stats->tx_bytes, stats->rx_bytes);
		}
	}

	freeifaddrs(my_addrs);
}



/**
 * 
 */
int rtr_listen() {
	
	uint8_t buf[MAX_ETH_PKT_SIZE];
	unsigned int buf_len = MAX_ETH_PKT_SIZE;
	ssize_t bytes_read, bytes_written;
	
	
	struct sockaddr_in saddr;
	struct sockaddr_in addr;
	int addr_len;

	/*
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = port;
	saddr.sin_addr.s_addr = ip;

	inet_stream_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
	*/


	while (is_rtr_running) {
		
		// Block until a message arrives
		bytes_read = recv(rtr_socket_fd, buf, buf_len, 0);
		DEBUG_printf2("[INFO] recv size = %ld\n", bytes_read);

		// If read failed, go again
		if (bytes_read <= 0) {
			continue;
		}
		

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		unsigned int l3_hdr_offset = sizeof(struct ether_hdr);


		unsigned short eth_proto = ntohs(eth_hdr->ether_type);

		
		char mac_addr_str[18];
		ether_format_addr(mac_addr_str, sizeof(mac_addr_str), &eth_hdr->d_addr);
		DEBUG_printf2("dst MAC: %s\n", mac_addr_str);
		ether_format_addr(mac_addr_str, sizeof(mac_addr_str), &eth_hdr->s_addr);
		DEBUG_printf2("src MAC: %s\n", mac_addr_str);
		DEBUG_printf2("Ether proto: %04hx\n", eth_proto);


		// Check if VLAN tag is present
		if (eth_proto == ETHER_TYPE_VLAN) {
			
			struct vlan_hdr *vlan_hdr = (struct vlan_hdr *) eth_hdr + l3_hdr_offset;
			eth_proto = vlan_hdr->eth_proto;
			l3_hdr_offset += sizeof(struct vlan_hdr);

			// TODO check for QinQ
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

		DEBUG_printf1("\n");
		DEBUG_printf1("\n---END---\n");
		continue;

	resend_frame:
		;// bytes_written = send(, buf, bytes_read, int flags);
	}
	

	DEBUG_printf1("[INFO] rtr is stopped\n");
	return 0;
}



int start_routing() {
	
	//struct timeval recv_timeout = {0, 100000};
	int flag = 1;
	
	// Check if routing process is already running
	if (is_rtr_running) {
		return 0;
	}
	
	
	rtr_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(rtr_socket_fd < 0) {
		DEBUG_printf1("[ERROR] Failed to create rtr socket\n");
		return -1;				// TODO more error handling
	}
	
	//setsockopt(rtr_socket_fd, SOL_SOCKET, SO_RCVTIMEO , (char * )&recv_timeout, sizeof(recv_timeout));
	setsockopt(rtr_socket_fd, SOL_SOCKET, SO_REUSEADDR , (char * )&flag, sizeof(int));
	setsockopt(rtr_socket_fd, SOL_SOCKET, SO_REUSEPORT , (char * )&flag, sizeof(int));


	load_my_ip_addrs();



	
	is_rtr_running = 1;
	rtr_listen();

	return 0;
}

void stop_routing() {

	// Do nothing if routing process is not running
	if (!is_rtr_running) {
		return;
	}

	DEBUG_printf1("[INFO] Stopping rtr...\n");

	is_rtr_running = 0;
	close_rtr_socket();
}



int main() {
	start_routing();
	return 0;
}