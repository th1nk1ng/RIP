#pragma once
class CRoutingDaemon
{
public:
	CRoutingDaemon(void);
	~CRoutingDaemon(void);

	typedef struct _RIPMessage{
		unsigned char command;
		unsigned char version;
		unsigned short unused;
		unsigned short address_family;
		unsigned short route_tag;
		unsigned int ip_address;
		unsigned int subnet_mask;
		unsigned int nexthop_ip_address;
		unsigned int metric;
	}RIPMessage;
};

