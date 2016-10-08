// UDPLayer.h: interface for the CEthernetLayer class.
//
//////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "BaseLayer.h"
#include "IPLayer.h"
#define UDP_DATA_SIZE 65507
#define UDP_PORT_SRC 520
#define UDP_HEADER_SIZE 20
class CUDPLayer 
: public CBaseLayer
{
private:
	inline void		ResetHeader( );

public:
	CUDPLayer( char* pName );
	virtual ~CUDPLayer(); 

	BOOL	Receive( unsigned char* ppayload , int dev_num) ;
	//BOOL	Send( unsigned char* ppayload, int nlength);
	BOOL 	Send(unsigned char* ppayload, int nlength, int dev_num);
	void	SetSrcPort( unsigned short srcport ) ;
	
	u_long CUDPLayer::UDP_Checksum(u_short *usBuf,int iSize);

private:
	// UDP_HEADER Header
	typedef struct _UDP_HEADER {
		u_short	udp_sport;	// source port
		u_short udp_dport;	// destination port
		u_short udp_ulen;	// udp length
		u_short udp_sum;	// udp checksum
		u_char	udp_data[UDP_DATA_SIZE];
	} UDP_HEADER, *PUDP_HEADER ;

protected:
	UDP_HEADER	m_sHeader ;
};