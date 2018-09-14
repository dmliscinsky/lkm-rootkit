/*
 * Author: Daniel Liscinsky
 */



/**
 * 
 * 
 * The enum values are the default administrative distance for that source.
 */
enum route_source {
	CONNECTED = 0, // DIRECTLY CONNECTED INTERFACE
	STATIC = 1,
	UNKNOWN = 255, // Completely untrusted route, will not be used
};

/**
 * 
 */
struct route_entry {
	route_source rsrc; // The route source
	uint32_t network_addr;
	uint32_t netmask;
	


	unsigned char adm_dist; // The administrative distance of the route
};







//
10.5.0.3
10.4.0.3
10.1.0.2

struct route_entry entry_1 = {
	.rsrc = STATIC,
	.network_addr = 0x0A020000, //10.2.0.0
	.netmask = 0xFFFF0000,


	.adm_dist = .rsrc,
};
struct route_entry entry_21 = {
	.rsrc = STATIC,
	.network_addr = 0x0A020000, //10.3.0.0
	.netmask = 0xFFFF0000,


	.adm_dist = .rsrc,
};



//
10.4.0.6

//
10.4.0.12






//
10.3.0.6

//
10.3.0.12
