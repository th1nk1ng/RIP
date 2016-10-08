//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Router.h"
#include "UDPLayer.h"


CUDPLayer::CUDPLayer(char* pName)
	: CBaseLayer(pName)
{
	ResetHeader();
}

CUDPLayer::~CUDPLayer()
{
}

void CUDPLayer::ResetHeader()
{
	m_sHeader.udp_sport = ntohs(UDP_PORT_SRC);
	m_sHeader.udp_dport = ntohs(UDP_PORT_SRC);
	m_sHeader.udp_ulen = 0;
	m_sHeader.udp_sum = 0;
	memset(m_sHeader.udp_data, 0, UDP_DATA_SIZE);
}

void CUDPLayer::SetSrcPort(unsigned short srcport)
{
	m_sHeader.udp_sport = ntohs(srcport);
}

u_long CUDPLayer::UDP_Checksum(u_short *buf, int len)
{
	int sum;
	for (sum = 0; len > 0; len -= 2)
	{
		sum += *buf++; // ��� ��Ʈ�� ����
	}

	// 32��Ʈ�� 16��Ʈ¥�� 2���� ����� ������
	sum = (sum >> 16) + (sum & 0xffff); 
	// ĳ������ ������ �Ŀ� ������ >> ���ο� ĳ���� ���õ�
	sum += (sum >> 16);

	//not�� �̿��Ͽ� checkSum �Ϸ�
	return ~sum;
}

BOOL CUDPLayer::Send(unsigned char* ppayload, int nlength, int dev_num)
{
	m_sHeader.udp_sum = 0;
	memset(m_sHeader.udp_data, 0, UDP_DATA_SIZE);

	//Checksum ���
	m_sHeader.udp_sum = UDP_Checksum((u_short*)&m_sHeader, UDP_HEADER_SIZE);
	m_sHeader.udp_ulen = ntohs(UDP_HEADER_SIZE + nlength);
	memcpy(m_sHeader.udp_data, ppayload, nlength);

	BOOL bSuccess = FALSE;
	bSuccess = mp_UnderLayer->Send((unsigned char*)&m_sHeader, (nlength + UDP_HEADER_SIZE), dev_num);
	return bSuccess;
}

BOOL CUDPLayer::Receive(unsigned char* ppayload, int dev_num)
{
	PUDP_HEADER pFrame = (PUDP_HEADER)ppayload;

	BOOL bSuccess = FALSE;
	//udp ��Ʈ��ȣ(520)�� Ȯ�� �� RIP ���̾�� �÷��ش�.
	if (pFrame->udp_dport == ntohs(UDP_PORT_SRC))
	{
		bSuccess = mp_aUpperLayer[0]->Receive( (unsigned char *)pFrame->udp_data, dev_num );
	}

	return bSuccess;
}
