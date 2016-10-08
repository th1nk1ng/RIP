// RouterDlg.cpp : ���� ����
//
#include "stdafx.h"
#include "Router.h"
#include "RouterDlg.h"
#include "RoutTableAdder.h"
#include "ProxyTableAdder.h"
#include "IPLayer.h"
#include <vector>
#include "stdio.h"

using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// ���� ���α׷� ������ ���Ǵ� CAboutDlg ��ȭ �����Դϴ�.
class CAboutDlg : public CDialog
{
public:
	CAboutDlg();
	

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

// �����Դϴ�.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CRouterDlg ��ȭ ����
CRouterDlg::CRouterDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CRouterDlg::IDD, pParent), CBaseLayer("CRouterDlg")
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	//listIndex = -1;
	//ProxyListIndex = -1;
	// Layer ����
	m_NILayer = new CNILayer("NI");
	m_EthernetLayer = new CEthernetLayer("Ethernet");
	m_ARPLayer = new CARPLayer("ARP");
	m_IPLayer = new CIPLayer("IP");
	m_UDPLayer = new CUDPLayer("UDP");
	
	//// Layer �߰�										
	m_LayerMgr.AddLayer( this );				
	m_LayerMgr.AddLayer( m_NILayer );			
	m_LayerMgr.AddLayer( m_EthernetLayer );
	m_LayerMgr.AddLayer( m_ARPLayer );
	m_LayerMgr.AddLayer( m_IPLayer );
	m_LayerMgr.AddLayer( m_UDPLayer );
	
	//Layer����
	m_NILayer->SetUpperLayer(m_EthernetLayer);
	m_EthernetLayer->SetUpperLayer(m_IPLayer);
	m_EthernetLayer->SetUpperLayer(m_ARPLayer);
	m_EthernetLayer->SetUnderLayer(m_NILayer);
	m_ARPLayer->SetUnderLayer(m_EthernetLayer);
	m_ARPLayer->SetUpperLayer(m_IPLayer);
	m_IPLayer->SetUpperLayer(m_UDPLayer);
	m_IPLayer->SetUnderLayer(m_ARPLayer);
	m_UDPLayer->SetUnderLayer(m_IPLayer);
	m_UDPLayer->SetUpperLayer(this);
	this->SetUnderLayer(m_UDPLayer);
	//Layer ����
}

void CRouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_ROUTING_TABLE, ListBox_RoutingTable);
	DDX_Control(pDX, IDC_CACHE_TABLE, ListBox_ARPCacheTable);
	DDX_Control(pDX, IDC_PROXY_TABLE, ListBox_ARPProxyTable);
	DDX_Control(pDX, IDC_NIC1_COMBO, m_nic1);
	DDX_Control(pDX, IDC_NIC2_COMBO, m_nic2);
	DDX_Control(pDX, IDC_IPADDRESS1, m_nic1_ip);
	DDX_Control(pDX, IDC_IPADDRESS2, m_nic2_ip);
}

BEGIN_MESSAGE_MAP(CRouterDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_CACHE_DELETE, &CRouterDlg::OnBnClickedCacheDelete)
	ON_BN_CLICKED(IDC_CACHE_DELETE_ALL, &CRouterDlg::OnBnClickedCacheDeleteAll)
	ON_BN_CLICKED(IDC_PROXY_DELETE, &CRouterDlg::OnBnClickedProxyDelete)
	ON_BN_CLICKED(IDC_PROXY_DELETE_ALL, &CRouterDlg::OnBnClickedProxyDeleteAll)
	ON_BN_CLICKED(IDC_PROXY_ADD, &CRouterDlg::OnBnClickedProxyAdd)
	ON_BN_CLICKED(IDCANCEL, &CRouterDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_NIC_SET_BUTTON, &CRouterDlg::OnBnClickedNicSetButton)
	ON_BN_CLICKED(IDC_ROUTING_ADD, &CRouterDlg::OnBnClickedRoutingAdd)
	ON_BN_CLICKED(IDC_ROUTING_DELETE, &CRouterDlg::OnBnClickedRoutingDelete)
	ON_CBN_SELCHANGE(IDC_NIC1_COMBO, &CRouterDlg::OnCbnSelchangeNic1Combo)
	ON_CBN_SELCHANGE(IDC_NIC2_COMBO, &CRouterDlg::OnCbnSelchangeNic2Combo)
END_MESSAGE_MAP()


// CRouterDlg �޽��� ó����

BOOL CRouterDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// �ý��� �޴��� "����..." �޴� �׸��� �߰��մϴ�.

	// IDM_ABOUTBOX�� �ý��� ��� ������ �־�� �մϴ�.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// �� ��ȭ ������ �������� �����մϴ�. ���� ���α׷��� �� â�� ��ȭ ���ڰ� �ƴ� ��쿡��
	//  �����ӿ�ũ�� �� �۾��� �ڵ����� �����մϴ�.
	SetIcon(m_hIcon, TRUE);			// ū �������� �����մϴ�.
	SetIcon(m_hIcon, FALSE);		// ���� �������� �����մϴ�.

	// TODO: ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	// ListBox�� �ʱ� Colum�� ����
	ListBox_RoutingTable.InsertColumn(0,_T("Destination"),LVCFMT_CENTER,99,-1);
	ListBox_RoutingTable.InsertColumn(1,_T("NetMask"),LVCFMT_CENTER,120,-1);
	ListBox_RoutingTable.InsertColumn(2,_T("Gateway"),LVCFMT_CENTER,99,-1);
	ListBox_RoutingTable.InsertColumn(3,_T("Flag"),LVCFMT_CENTER,70,-1);
	ListBox_RoutingTable.InsertColumn(4,_T("Interface"),LVCFMT_CENTER,79,-1);
	ListBox_RoutingTable.InsertColumn(5,_T("Metric"),LVCFMT_CENTER,70,-1);

	ListBox_ARPCacheTable.InsertColumn(0,_T("IP address"),LVCFMT_CENTER,100,-1);
	ListBox_ARPCacheTable.InsertColumn(1,_T("Mac address"),LVCFMT_CENTER,120,-1);
	ListBox_ARPCacheTable.InsertColumn(2,_T("Type"),LVCFMT_CENTER,80,-1);
	//ListBox_ARPCacheTable.InsertColumn(3,_T("Time"),LVCFMT_CENTER,49,-1);

	ListBox_ARPProxyTable.InsertColumn(0,_T("Name"),LVCFMT_CENTER,60,-1);
	ListBox_ARPProxyTable.InsertColumn(1,_T("IP address"),LVCFMT_CENTER,120,-1);
	ListBox_ARPProxyTable.InsertColumn(2,_T("Mac address"),LVCFMT_CENTER,120,-1);

	memset(zeroNextHop, 0, sizeof(char) * 4);

	memset(generalNetmask, 0xff, sizeof(char) * 4);
	generalNetmask[3] = 0x0;

	memset(multicast, 0, sizeof(char) * 4);
	multicast[0] = 0xE0;
	multicast[3] = 0x09;

	SetTimer(TICKING_CLOCK, TICKING_INTERVAL, NULL);
	SetTimer(UPDATE_TIMER, UPDATE_INTERVAL, NULL);
	setNicList(); //NicList Setting
	return TRUE;  // ��Ŀ���� ��Ʈ�ѿ� �������� ������ TRUE�� ��ȯ�մϴ�.
}

void CRouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// ��ȭ ���ڿ� �ּ�ȭ ���߸� �߰��� ��� �������� �׸�����
//  �Ʒ� �ڵ尡 �ʿ��մϴ�. ����/�� ���� ����ϴ� MFC ���� ���α׷��� ��쿡��
//  �����ӿ�ũ���� �� �۾��� �ڵ����� �����մϴ�.

void CRouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // �׸��⸦ ���� ����̽� ���ؽ�Ʈ

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Ŭ���̾�Ʈ �簢������ �������� ����� ����ϴ�.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// �������� �׸��ϴ�.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// ����ڰ� �ּ�ȭ�� â�� ���� ���ȿ� Ŀ���� ǥ�õǵ��� �ý��ۿ���
//  �� �Լ��� ȣ���մϴ�.
HCURSOR CRouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CRouterDlg::OnBnClickedCacheDelete()
{
	//CacheDeleteAll��ư
	int index = -1;
	index = ListBox_ARPCacheTable.GetSelectionMark();
	if(index != -1){
		POSITION pos = m_ARPLayer->Cache_Table.FindIndex(index);
		m_ARPLayer->Cache_Table.RemoveAt(pos);
		m_ARPLayer->updateCacheTable();
	}
}

void CRouterDlg::OnBnClickedCacheDeleteAll()
{
	//CacheDeleteAll��ư
	m_ARPLayer->Cache_Table.RemoveAll();
	m_ARPLayer->updateCacheTable();
}
void CRouterDlg::OnBnClickedProxyDelete()
{
	//proxy delete��ư
	m_ARPLayer->Proxy_Table.RemoveAll();
	m_ARPLayer->updateProxyTable();
}

void CRouterDlg::OnBnClickedProxyDeleteAll()
{
	//proxy delete all ��ư
	int index = -1;
	index = ListBox_ARPProxyTable.GetSelectionMark();
	if(index != -1){
		POSITION pos = m_ARPLayer->Proxy_Table.FindIndex(index);
		m_ARPLayer->Proxy_Table.RemoveAt(pos);
		m_ARPLayer->updateProxyTable();
	}
}

void CRouterDlg::OnBnClickedProxyAdd()
{
	// proxy add ��ư
	CString str;
	unsigned char Ip[4];
	unsigned char Mac[8];
	ProxyTableAdder PDlg;
	if(	PDlg.DoModal() == IDOK)
	{
		str = PDlg.getName();
		memcpy(Ip , PDlg.getIp() , 4);
		memcpy(Mac , PDlg.getMac() , 6);

//		m_ARPLayer->InsertProxy(str,Ip,Mac);
	}
}

void CRouterDlg::OnBnClickedCancel()
{
	// ���� ��ư
	exit(0);
}

void CRouterDlg::OnBnClickedNicSetButton()
{
	LPADAPTER adapter = NULL;		// ��ī�忡 ���� ������ �����ϴ� pointer ����
	PPACKET_OID_DATA OidData;
	pcap_if_t *Devices;
	OidData = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA));
	OidData->Oid = 0x01010101;
	OidData->Length = 6;
	ZeroMemory(OidData->Data,6);
	char DeviceName1[512];
	char DeviceName2[512];
	char strError[256];
	if(pcap_findalldevs_ex( PCAP_SRC_IF_STRING, NULL , &Devices , strError) != 0) {
		printf("pcap_findalldevs_ex() error : %s\n", strError);
	}
	m_nic1.GetLBText(m_nic1.GetCurSel() , DeviceName1);	// �޺� �ڽ��� ���õ� Device�� �̸��� ����
	m_nic2.GetLBText(m_nic2.GetCurSel() , DeviceName2);
	while(Devices != NULL) {
		if(!strcmp(Devices->description,DeviceName1))
			Device1 = Devices;
		if(!strcmp(Devices->description,DeviceName2))
			Device2 = Devices;
		Devices = Devices->next;
	}
	// device����
	m_NILayer->SetDevice(Device1,1);
	m_NILayer->SetDevice(Device2,2);
	
	RtDlg.setDeviceList(Device1->description,Device2->description);
	//mac �ּ� ����
	adapter = PacketOpenAdapter((Device1->name+8));
	PacketRequest( adapter, FALSE, OidData);
	m_EthernetLayer->SetSourceAddress(OidData->Data,1);
	adapter = PacketOpenAdapter((Device2->name+8));
	PacketRequest( adapter, FALSE, OidData);
	m_EthernetLayer->SetSourceAddress(OidData->Data,2);
	//ip�ּ� ����
	// ��ī�忡 ���� �������� �о�� Combo �ڽ��� �߰��ϴ� �κ�
	unsigned char nic1_ip[4];
	unsigned char nic2_ip[4];
	m_nic1_ip.GetAddress((BYTE &)nic1_ip[0],(BYTE &)nic1_ip[1],(BYTE &)nic1_ip[2],(BYTE &)nic1_ip[3]);
	m_nic2_ip.GetAddress((BYTE &)nic2_ip[0],(BYTE &)nic2_ip[1],(BYTE &)nic2_ip[2],(BYTE &)nic2_ip[3]);
	m_IPLayer->SetSrcIP(nic1_ip,1);
	m_IPLayer->SetSrcIP(nic2_ip,2);
	// receive Thread start

	m_NILayer->StartReadThread();
	GetDlgItem(IDC_NIC_SET_BUTTON)->EnableWindow(0);
}

void CRouterDlg::OnBnClickedRoutingAdd()
{
	// router Table Add��ư
	if( RtDlg.DoModal() == IDOK ){
		RoutingTableTuple rt;
		memcpy(&rt.Destination,RtDlg.GetDestIp(),6);
		rt.Flag = RtDlg.GetFlag();
		memcpy(&rt.Gateway,RtDlg.GetGateway(),6);
		memcpy(&rt.Netmask,RtDlg.GetNetmask(),6);
		rt.Interface = RtDlg.GetInterface();
		rt.Metric = RtDlg.GetMetric();
		route_table.AddTail(rt);
		UpdateRouteTable();
	}
}

void CRouterDlg::OnBnClickedRoutingDelete()
{
	// router Table delete��ư
	int index = -1;
	index = ListBox_RoutingTable.GetSelectionMark();
	if(index != -1){
		POSITION pos = route_table.FindIndex(index);
		route_table.RemoveAt(pos);
		UpdateRouteTable();
	}
}

// NicList Set
void CRouterDlg::setNicList(void)
{
	pcap_if_t *Devices;
	char strError[256];
	if(pcap_findalldevs_ex( PCAP_SRC_IF_STRING, NULL , &Devices , strError) != 0) {
		printf("pcap_findalldevs_ex() error : %s\n", strError);
	}

	//set device_1
	while(Devices != NULL) {
		m_nic1.AddString(Devices->description);
		m_nic2.AddString(Devices->description);
		Devices = Devices->next;
	}
	m_nic1.SetCurSel(0);
	m_nic2.SetCurSel(1);
}	

void CRouterDlg::add_route_table(unsigned char dest[4],
	                             unsigned char netmask[4],
								 unsigned char gateway[4],
								 unsigned char flag,
								 //char Interface[100],
								 int Interface,
								 int metric)
{
	sc.Lock();
	RoutingTableTuple rt;
	memcpy(&rt.Destination,dest,4);
	memcpy(&rt.Netmask,netmask,4);
	memcpy(&rt.Gateway,gateway,4);
	rt.Flag = flag;
	//memcpy(&rt.Interface, Interface, 100);
	rt.Interface = Interface;
	rt.Metric = metric;
	route_table.AddTail(rt);
	UpdateRouteTable();
	sc.Unlock();
}

//UpdateRouteTable
void CRouterDlg::UpdateRouteTable(void)
{
	ListBox_RoutingTable.DeleteAllItems();
	CString dest,netmask,gateway,flag,Interface,metric;
	POSITION index;
	RoutingTableTuple entry; //head position
	for(int i=0;i<route_table.GetCount();i++){
		flag = "";
		index = route_table.FindIndex(i);
		entry = route_table.GetAt(index);
		dest.Format("%d.%d.%d.%d",entry.Destination[0],entry.Destination[1],entry.Destination[2],entry.Destination[3]);
		netmask.Format("%d.%d.%d.%d",entry.Netmask[0],entry.Netmask[1],entry.Netmask[2],entry.Netmask[3]);
		
		if(entry.Metric == 1) {
			gateway.Format("%s","�����");
		} else {
			gateway.Format("%d.%d.%d.%d",entry.Gateway[0],entry.Gateway[1],entry.Gateway[2],entry.Gateway[3]);
		}
		
		//gateway.Format("%d.%d.%d.%d",entry.Gateway[0],entry.Gateway[1],entry.Gateway[2],entry.Gateway[3]);
		if((entry.Flag & 0x01) == 0x01)
			flag += "U";
		if((entry.Flag & 0x02) == 0x02)
			flag += "G";
		if((entry.Flag & 0x04) == 0x04)
			flag += "H";
		Interface.Format("%d",entry.Interface);
		metric.Format("%d",entry.Metric);
		ListBox_RoutingTable.InsertItem(i,dest);
		ListBox_RoutingTable.SetItem(i,1,LVIF_TEXT,netmask,0,0,0,NULL);
		ListBox_RoutingTable.SetItem(i,2,LVIF_TEXT,gateway,0,0,0,NULL);
		ListBox_RoutingTable.SetItem(i,3,LVIF_TEXT,flag,0,0,0,NULL);
		ListBox_RoutingTable.SetItem(i,4,LVIF_TEXT,Interface,0,0,0,NULL);
		ListBox_RoutingTable.SetItem(i,5,LVIF_TEXT,metric,0,0,0,NULL);
	}
	ListBox_RoutingTable.UpdateWindow();
}

int CRouterDlg::Routing(unsigned char destip[4]) {
	POSITION index;
	RoutingTableTuple entry;
	RoutingTableTuple select_entry;
	entry.Interface = -2;
	select_entry.Interface = -2;
	unsigned char result[4];
	for(int i=0; i<route_table.GetCount(); i++) {
		index = route_table.FindIndex(i);
		entry = route_table.GetAt(index);

		/* select_entry�� �������� �ʴ� ��� */
		if(select_entry.Interface == -2){
			for(int j=0; j<4; j++)
				result[j] = destip[j] & entry.Netmask[j];

			/* destination�� ���� ��� */
			if(!memcmp(result,entry.Destination,4)){ 

				/* gateway�� ������ ��� */
				if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x02)){ 
					select_entry = entry;
					m_IPLayer->SetDstIP(entry.Gateway);
				}

				/* gateway�� �ƴ� ��� */
				else if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x00)){ 
					select_entry = entry;
					m_IPLayer->SetDstIP(destip);
				}
			}
		}
		/* �����ϴ� ��� */
		else { 
			for(int j=0; j<4; j++)
				result[j] = destip[j] & entry.Netmask[j];

			/* ���� select��Ʈ ���� 1�� ������ ���� ��� */
			if(memcmp(result,entry.Netmask,4)){ 
				for(int j=0; j<4; j++)
					result[j] = destip[j] & entry.Netmask[j];

				/* destation�� ���� ��� */
				if(!memcmp(result,entry.Destination,4)){ 

					/* gateway�� ������ ��� */
					if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x02)){ 
						select_entry = entry;
						m_IPLayer->SetDstIP(entry.Gateway);
					}

					/* gateway�� �ƴ� ��� */
					else if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x00)){ 
						select_entry = entry;
						m_IPLayer->SetDstIP(destip);
					}
				}
			}
			/* �� ���� ��� pass */
		}
	}
	return select_entry.Interface+1;
}

void CRouterDlg::OnTimer(UINT nIDEvent) 
{
	POSITION index;
	RoutingTableTuple entry; //head position
	switch(nIDEvent){
	case TICKING_CLOCK:
		for(int i=0;i<route_table.GetCount();i++){
			index = route_table.FindIndex(i);
			entry = route_table.GetAt(index);
			entry.expirationTime--;
			entry.garbageCollectionTime--;
			//hop�� 16���� �ٲ�.
			if( entry.expirationTime==0)
			{
				entry.Metric=16;
			}
			//���̺��� ����.
			if( entry.garbageCollectionTime==0)
			{
				route_table.RemoveAt(index);
				UpdateRouteTable();
			}
		}
		break;
	//�ֱ����� Ÿ�̸�, 30�ʸ��� ���� �޽����� ����.
	case UPDATE_TIMER:
		sendRIP();
		break;
	}
	CDialog::OnTimer(nIDEvent);
}

void CRouterDlg::OnCbnSelchangeNic1Combo()
{// ip�ּ� ����
}

void CRouterDlg::OnCbnSelchangeNic2Combo()
{ //ip �ּ� ����
}

int CRouterDlg::sendRIP()
{
	RIPHeader header;
	setHeader(&header, 1);

	sc.Lock();
	POSITION index;
	for(int i = 0; i < route_table.GetCount(); i++){
		RIPMessage newMessage;

		index = route_table.FindIndex(i);
		
		generateNewRIPMessage(&newMessage,
			                  route_table.GetAt(index).Destination,
							  route_table.GetAt(index).Netmask,
							  zeroNextHop,
							  route_table.GetAt(index).Metric);
		header.messages[header.messageCount++] = newMessage;
	}
	sc.Unlock();

	unsigned char ppayload[1480];
	int size = 0;

	memcpy(ppayload, (unsigned char*)route_table.GetCount(), sizeof(int));
	size += sizeof(int);

	memcpy(ppayload + sizeof(int), (unsigned char *)&header, sizeof(RIPHeader));
	size += sizeof(RIPHeader);

	unsigned char ppayload_copy[1480];
	memcpy(ppayload_copy, ppayload, size);

	RIPMessage leftMessage;
	generateNewRIPMessage(&leftMessage,
		                  m_IPLayer->dev_1_ip_addr,
						  generalNetmask,
						  zeroNextHop,
						  0);
	header.messages[header.messageCount++] = leftMessage;
	ppayload[size + sizeof(RIPMessage) + 1] = '\0';
	m_UDPLayer->Send((unsigned char *)ppayload, strlen((const char *)ppayload), 1);

	RIPMessage rightMessage;
	generateNewRIPMessage(&rightMessage,
		                  m_IPLayer->dev_2_ip_addr,
						  generalNetmask,
						  zeroNextHop,
						  0);
	header.messages[header.messageCount-1] = rightMessage;
	ppayload_copy[size + sizeof(RIPMessage) + 1] = '\0';
	m_UDPLayer->Send((unsigned char *)ppayload_copy, strlen((const char *)ppayload_copy), 2);
	
	return 0;
}

BOOL CRouterDlg::Receive(unsigned char* ppayload, int dev_num)
{
	PRIPHeader header = (PRIPHeader)ppayload;
	POSITION index;
	BOOL bSuccess = FALSE;

	if(header->version != RIP_VER_2)
		return FALSE;

	if(header->command == RIP_COMMAND_REQ){
		int size = 0;
	    RIPHeader newHeader;

		sc.Lock();
		size = generateReplyRIPMessage(&newHeader);
		if(dev_num == 1)
			memcpy(m_EthernetLayer->dev_1_mac_addr, multicast, sizeof(char) * 6);
		else
			memcpy(m_EthernetLayer->dev_2_mac_addr, multicast, sizeof(char) * 6);

		bSuccess = mp_UnderLayer->Send((unsigned char*)&newHeader, 
			                           RIP_HEADER_SIZE + ((size+1) * sizeof(RIPMessage)),
									   dev_num);
		sc.Unlock();
	} else if(header->command == RIP_COMMAND_RES){
		sc.Lock();
		updateRouterTableTuples(header, dev_num);
		sc.Unlock();
	}
}

int CRouterDlg::generateReplyRIPMessage(RIPHeader *header)
{
	setHeader(header, RIP_COMMAND_RES);
	for(int i = 0; i < 25; i++){
		memset((unsigned char*)&header->messages[i], 0, sizeof(RIPMessage));
	}

	sc.Lock();
	POSITION index;
	int size = 0;
	for(; size < route_table.GetCount(); size++){
		RIPMessage newMessage;

		index = route_table.FindIndex(size);
		
		if(!memcmp(currentIPSrc, route_table.GetAt(index).Destination, sizeof(char) * 4)){
			continue;
		}

		generateNewRIPMessage(&newMessage,
			                  route_table.GetAt(index).Destination,
							  route_table.GetAt(index).Netmask,
							  zeroNextHop,
							  route_table.GetAt(index).Metric);
		header->messages[header->messageCount++] = newMessage;
	}
	
	sc.Unlock();
	return size;
}

void CRouterDlg::updateRouterTableTuples(RIPHeader *header, int dev_num)
{
	int count = header->messageCount;
	for(int i = 0; i < count; i++){
		RIPMessage message = header->messages[i];
		
		if(!memcmp(message.ip_address, currentIPSrc, sizeof(char) * 4)){
			continue;
		}

		RoutingTableTuple newTuple;
		memcpy(newTuple.Destination, message.ip_address, sizeof(char) * 4);
		memcpy(newTuple.Netmask, message.subnet_mask, sizeof(char) * 4);
		memcpy(newTuple.Gateway, zeroNextHop, sizeof(char) * 4);
		newTuple.Metric = ntohl(message.metric) + 1;
		newTuple.Flag = 0;
		newTuple.Interface = dev_num;
		newTuple.expirationTime = EXPIRATION_INTERVAL;
		newTuple.garbageCollectionTime = GARBAGE_COLLECTION_INTERVAL;

		BOOL isNewTuple = TRUE;

		//Check is it new Tuple or not.
		for(int j = 0; j < route_table.GetCount(); j++){
			POSITION index;
			index = route_table.FindIndex(i);
			if(!memcmp(route_table.GetAt(index).Destination, message.ip_address, sizeof(char) * 4)){
				isNewTuple = FALSE;
				route_table.GetAt(index).Metric = newTuple.Metric;
				route_table.GetAt(index).expirationTime = EXPIRATION_INTERVAL;
				route_table.GetAt(index).garbageCollectionTime = GARBAGE_COLLECTION_INTERVAL;
				break;
			}
		}

		//Add to route_table if it is new tuple
		if(newTuple.Metric < MAX_HOP && isNewTuple)
		{
			route_table.AddTail(newTuple);
			UpdateRouteTable();
		}
	}
}
void CRouterDlg::generateNewRIPMessage(RIPMessage *newMessage, 
	                                   unsigned char ipAddress[4],
									   unsigned char netmask[4],
									   unsigned char nextHop[4],
									   unsigned int metric){
	newMessage->address_family = htons(2);
	newMessage->route_tag = htons(1);
	memcpy(newMessage->ip_address, ipAddress, sizeof(char) * 4);
	memcpy(newMessage->subnet_mask, netmask, sizeof(char) * 4);
	memcpy(newMessage->nexthop_ip_address, nextHop, sizeof(char) * 4);
	newMessage->metric = metric;
}

void CRouterDlg::setHeader(RIPHeader *header, unsigned char command)
{
	header->command = command;
	header->version = 2;
	header->unused = 0x0000;
	header->messageCount = 0;
}