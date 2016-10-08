#include "StdAfx.h"
#include "RoutingDaemon.h"
#include "RouterDlg.h"
#include "UDPLayer.h"
#include <vector>

using namespace std;


CRoutingDaemon::~CRoutingDaemon(void)
{
}


int CRoutingDaemon::send()
{
	CList<CRouterDlg::RoutingTable, CRouterDlg::RoutingTable&> *route_table = &(dlg->route_table);

	RIPHeader header;
	setHeaderAsRequest(&header);

	vector<RIPMessage> messageList;

	POSITION index;
	for(int i = 0; i < route_table->GetCount(); i++){
		RIPMessage newMessage;

		index = route_table->FindIndex(i);
		
		newMessage.address_family = htonl(0x0002);
		newMessage.route_tag = htonl(0x0001);
		memcpy(newMessage.ip_address, route_table->GetAt(index).Destnation, sizeof(char) * 4);
		memcpy(newMessage.subnet_mask, route_table->GetAt(index).Netmask, sizeof(char) * 4);
		memset((void*)newMessage.nexthop_ip_address, 0, sizeof(char) * 4);  // Only for linear topology
		newMessage.metric = route_table->GetAt(index).Metric;

		messageList.push_back(newMessage);
	}
	
	unsigned char ppayload[1480];
	memcpy(ppayload, (unsigned char *)&header, sizeof(RIPHeader));
	for(int i = 0; i < route_table->GetCount(); i++){
		memcpy(ppayload + sizeof(RIPHeader) + (sizeof(RIPMessage) * i), (unsigned char *)&(messageList.at(i)), sizeof(RIPMessage));
		
	}

	CRouterDlg.m_UDPLayer.Send((unsigned char *)ppayload, strlen((const char *)ppayload), 1);
	CRouterDlg.m_UDPLayer.Send((unsigned char *)ppayload, strlen((const char *)ppayload), 2);
}

int CRoutingDaemon::receive(void)
{
	return 0;
}


void CRoutingDaemon::setHeaderAsRequest(RIPHeader *header)
{
	header->command = 1;
	header->version = 2;
	header->unused = 0x0000;
}


void CRoutingDaemon::setHeaderAsResponse(RIPHeader *header)
{
	header->command = 2;
	header->version = 2;
	header->unused = 0x0000;
}
