// RouterDlg.h : 헤더 파일
//

#pragma once
#include "resource.h"
#include "ARPLayer.h"
#include "IPLayer.h"
#include "NILayer.h"
#include "EthernetLayer.h"
#include "LayerManager.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "RoutTableAdder.h"
// CRouterDlg 대화 상자
class CRouterDlg : public CDialog, public CBaseLayer
{
// 생성입니다.
public:
	CRouterDlg(CWnd* pParent = NULL);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
	enum { IDD = IDD_STATICROUTER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
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
	pcap_if_t *Device1;
	pcap_if_t *Device2;
	CRoutTableAdder RtDlg;
public: 
	unsigned char *buf;
	int Routing(unsigned char destip[4]);
	pcap_if_t *Devices_1; //interface 0
	pcap_if_t *Devices_2; //interface 1
	typedef struct _RoutingTable{
		unsigned char Destnation[4];
		unsigned char Netmask[4];
		unsigned char Gateway[4];
		unsigned char Flag;
		int Interface; //interface 번호
		int Metric;
	}RoutingTable,*RoutingTablePtr;

	CList<RoutingTable,RoutingTable&> route_table;

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
	void add_route_table(unsigned char dest[4],unsigned char netmask[4],unsigned char gateway[4],unsigned char flag,char Interface[100],int metric);
	// UpdateRouteTable
	void UpdateRouteTable(void);
	afx_msg void OnCbnSelchangeNic2Combo();
	CIPAddressCtrl m_nic1_ip;
	CIPAddressCtrl m_nic2_ip;
};
