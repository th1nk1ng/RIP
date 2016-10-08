// RouterDlg.h : ��� ����
//

#pragma once
#include "resource.h"
#include "ARPLayer.h"
#include "IPLayer.h"
#include "NILayer.h"
#include "EthernetLayer.h"
#include "UDPLayer.h"
#include "LayerManager.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "RoutTableAdder.h"

#define TICKING_CLOCK				1
#define UPDATE_TIMER				2
#define EXPIRATION_TIMER			3
#define GARBAGE_COLLECTION_TIMER	4
#define TICKING_INTERVAL			1000
#define UPDATE_INTERVAL				30000
#define EXPIRATION_INTERVAL			180000
#define GARBAGE_COLLECTION_INTERVAL	120000

#define RIP_VER_2					2
#define RIP_COMMAND_REQ	            1
#define RIP_COMMAND_RES			    2

#define RIP_HEADER_SIZE				16
#define MAX_HOP						16
// CRouterDlg ��ȭ ����
class CRouterDlg : public CDialog, public CBaseLayer
{
// �����Դϴ�.
public:
	CRouterDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_STATICROUTER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.


// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public: //layer
	CNILayer		*m_NILayer;
	CEthernetLayer	*m_EthernetLayer;
	CARPLayer		*m_ARPLayer;
	CIPLayer		*m_IPLayer;
	CLayerManager	 m_LayerMgr;
	CUDPLayer		*m_UDPLayer;

	pcap_if_t *Device1;
	pcap_if_t *Device2;
	CRoutTableAdder RtDlg;
public: 
	unsigned char *buf;
	int Routing(unsigned char destip[4]);
	pcap_if_t *Devices_1; //interface 0
	pcap_if_t *Devices_2; //interface 1

	typedef struct _RoutingTable{
		unsigned char Destination[4];
		unsigned char Netmask[4];
		unsigned char Gateway[4];
		unsigned char Flag;
		int Interface; //interface ��ȣ
		int Metric;
		int expirationTime;
		int garbageCollectionTime;
	}RoutingTableTuple,*RoutingTableTuplePtr;

	CList<RoutingTableTuple, RoutingTableTuple&> route_table;
	


	typedef struct _RIPMessage{
		unsigned short address_family;
		unsigned short route_tag;
		unsigned char ip_address[4];
		unsigned char subnet_mask[4];
		unsigned char nexthop_ip_address[4];
		unsigned int metric;
	}RIPMessage, *PRIPMessage;

	typedef struct _RIPHeader{
		unsigned char command;
		unsigned char version;
		unsigned short unused;
		unsigned int messageCount;
		RIPMessage messages[25];
	}RIPHeader, *PRIPHeader;
	
	
	unsigned char zeroNextHop[4];
	unsigned char generalNetmask[4];
	
	unsigned char currentIPSrc[4];
	int generateReplyRIPMessage(RIPHeader *header);
	void generateNewRIPMessage(RIPMessage *newMessage, 
	                           unsigned char ipAddress[4],
							   unsigned char netmask[4],
							   unsigned char nextHop[4],
							   unsigned int metric);
	int updateRouterTableTuples(RIPHeader *header, int dev_num);

	void setHeader(RIPHeader *header, unsigned char command);
	int sendRIP(void);
	BOOL Receive(unsigned char* ppayload, int dev_num);

	CCriticalSection sc;

public:
	CListCtrl ListBox_RoutingTable;
	CListCtrl ListBox_ARPCacheTable;
	CListCtrl ListBox_ARPProxyTable;
	afx_msg void OnBnClickedCacheDelete();
	afx_msg void OnBnClickedCacheDeleteAll();
	afx_msg void OnBnClickedProxyDelete();
	afx_msg void OnBnClickedProxyDeleteAll();
	afx_msg void OnBnClickedProxyAdd();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedNicSetButton();
	afx_msg void OnBnClickedRoutingAdd();
	afx_msg void OnBnClickedRoutingDelete();
	CComboBox m_nic1;
	CComboBox m_nic2;
	// NicList Set
	void setNicList(void);
	afx_msg void OnCbnSelchangeNic1Combo();
	void add_route_table(unsigned char dest[4],
		                 unsigned char netmask[4],
						 unsigned char gateway[4],
						 unsigned char flag,
						 //char Interface[100],
						 int Interface,
						 int metric);
	// UpdateRouteTable
	void UpdateRouteTable(void);
	afx_msg void OnCbnSelchangeNic2Combo();
	CIPAddressCtrl m_nic1_ip;
	CIPAddressCtrl m_nic2_ip;

	void OnTimer(UINT nIDEvent);
	afx_msg void OnLvnItemchangedRoutingTable(NMHDR *pNMHDR, LRESULT *pResult);
};