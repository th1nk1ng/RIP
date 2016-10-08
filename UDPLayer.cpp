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
		sum += *buf++; // 모든 비트를 더함
	}

	// 32비트를 16비트짜리 2개로 나누어서 더해줌
	sum = (sum >> 16) + (sum & 0xffff); 
	// 캐리값을 시프팅 후에 더해줌 >> 새로운 캐리는 무시됨
	sum += (sum >> 16);

	//not을 이용하여 checkSum 완료
	return ~sum;
}

BOOL CUDPLayer::Send(unsigned char* ppayload, int nlength, int dev_num)
{
	m_sHeader.udp_sum = 0;
	memset(m_sHeader.udp_data, 0, UDP_DATA_SIZE);

	//Checksum 계산
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
	//udp 포트번호(520)를 확인 후 RIP 레이어로 올려준다.
	if (pFrame->udp_dport == ntohs(UDP_PORT_SRC))
	{
		bSuccess = mp_aUpperLayer[0]->Receive( (unsigned char *)pFrame->udp_data, dev_num );
	}

	return bSuccess;
}
