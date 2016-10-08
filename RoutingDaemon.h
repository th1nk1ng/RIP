#pragma once

class CRouterDlg{
}

class CRoutingDaemon
{
public:
	CRoutingDaemon(CRouterDlg *dlg);
	~CRoutingDaemon(void);

	typedef struct _RIPHeader{
		unsigned char command;
		unsigned char version;
		unsigned short unused;
	}RIPHeader;
	
	typedef struct _RIPMessage{
		unsigned short address_family;
		unsigned short route_tag;
		unsigned char ip_address[4];
		unsigned char subnet_mask[4];
		unsigned char nexthop_ip_address[4];
		unsigned int metric;
	}RIPMessage;

	int send(void);
	int receive(void);
	CRouterDlg *dlg;
	
private:
	void setHeaderAsRequest(RIPHeader *header);
	void setHeaderAsResponse(RIPHeader *header);
};

