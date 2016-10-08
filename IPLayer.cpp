#include "StdAfx.h"
#include "IPLayer.h"
#include "RouterDlg.h"
CIPLayer::CIPLayer( char* pName ) : CBaseLayer( pName ) 
{ 
	ResetHeader();
}

CIPLayer::~CIPLayer() { }

// ip1 setting function
void CIPLayer::SetDstIP( unsigned char* ip )
{
	memcpy(Ip_header.Ip_dstAddressByte , ip , 4 );
}
void CIPLayer::SetSrcIP( unsigned char* ip ,int dev_num)
{
	if(dev_num == 1){
		memcpy(dev_1_ip_addr , ip , 4 );
	}
	else{
		memcpy(dev_2_ip_addr , ip , 4 );
	}
	memcpy(&Ip_header.Ip_srcAddress,ip,4);
}
unsigned char* CIPLayer::GetDstIP( )
{
	return Ip_header.Ip_dstAddressByte;
}
unsigned char* CIPLayer::GetSrcIP(int dev_num)
{
	if(dev_num == 1)
		return dev_1_ip_addr;
	return dev_2_ip_addr;
}

// ppayload == (unsigned char*)&Tcp_header
BOOL CIPLayer::Send(unsigned char* ppayload, int nlength,int dev_num)
{
	// IP 주소 셋팅은 Set 버튼을 눌렀을때 셋팅이 되었으므로 data와 전체 크기를 저장후 전송
	Ip_header.Ip_len = nlength;
	memcpy(Ip_header.Ip_data , ppayload , nlength);
	BOOL bSuccess = mp_UnderLayer->Send((unsigned char*)&Ip_header , IP_HEADER_SIZE + nlength,dev_num);
	return bSuccess;
}

BOOL CIPLayer::Receive(unsigned char* ppayload,int dev_num)
{
	PIpHeader pFrame = (PIpHeader)ppayload;
	unsigned char destip[4];
	memset(destip,0,4);
	memcpy(destip,pFrame->Ip_dstAddressByte,4);
	memcpy(((CRouterDlg *)GetUpperLayer(0))->currentIPSrc, pFrame->Ip_srcAddressByte, 4);
	int dev = ((CRouterDlg *)GetUpperLayer(0))->Routing(destip);
	if(dev != -1){
		((CRouterDlg *)GetUpperLayer(0))->m_ARPLayer->Send((unsigned char *)pFrame,
			(int)htons(pFrame->Ip_len) + IP_HEADER_SIZE,dev);
		return TRUE;
	}
	else
		return FALSE;
}

void CIPLayer::ResetHeader( )
{
		//ip1 reset
		Ip_header.Ip_version = 0x00;
		Ip_header.Ip_typeOfService = 0x00;
		Ip_header.Ip_len = 0x0000;
		Ip_header.Ip_id = 0x0000;		
		Ip_header.Ip_fragmentOffset = 0x0000;
		Ip_header.Ip_timeToLive = 0x00;
		Ip_header.Ip_protocol = 0x00;
		Ip_header.Ip_checksum = 0x0000;
		memset(Ip_header.Ip_srcAddressByte , 0 , 4);
		memset(Ip_header.Ip_dstAddressByte , 0 , 4);
		memset(Ip_header.Ip_data , 0 , IP_MAX_DATA);
}