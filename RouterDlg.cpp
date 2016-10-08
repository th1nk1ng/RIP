// RouterDlg.cpp : 구현 파일
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

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.
class CAboutDlg : public CDialog
{
public:
	CAboutDlg();
	

// 대화 상자 데이터입니다.
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
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


// CRouterDlg 대화 상자
CRouterDlg::CRouterDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CRouterDlg::IDD, pParent), CBaseLayer("CRouterDlg")
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	//listIndex = -1;
	//ProxyListIndex = -1;
	// Layer 생성
	m_NILayer = new CNILayer("NI");
	m_EthernetLayer = new CEthernetLayer("Ethernet");
	m_ARPLayer = new CARPLayer("ARP");
	m_IPLayer = new CIPLayer("IP");
	m_UDPLayer = new CUDPLayer("UDP");
	
	//// Layer 추가										
	m_LayerMgr.AddLayer( this );				
	m_LayerMgr.AddLayer( m_NILayer );			
	m_LayerMgr.AddLayer( m_EthernetLayer );
	m_LayerMgr.AddLayer( m_ARPLayer );
	m_LayerMgr.AddLayer( m_IPLayer );
	m_LayerMgr.AddLayer( m_UDPLayer );
	
	//Layer연결
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
	//Layer 생성
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


// CRouterDlg 메시지 처리기

BOOL CRouterDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
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

	// 이 대화 상자의 아이콘을 설정합니다. 응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	// ListBox에 초기 Colum을 삽입
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
	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
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

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다. 문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CRouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CRouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CRouterDlg::OnBnClickedCacheDelete()
{
	//CacheDeleteAll버튼
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
	//CacheDeleteAll버튼
	m_ARPLayer->Cache_Table.RemoveAll();
	m_ARPLayer->updateCacheTable();
}
void CRouterDlg::OnBnClickedProxyDelete()
{
	//proxy delete버튼
	m_ARPLayer->Proxy_Table.RemoveAll();
	m_ARPLayer->updateProxyTable();
}

void CRouterDlg::OnBnClickedProxyDeleteAll()
{
	//proxy delete all 버튼
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
	// proxy add 버튼
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
	// 종료 버튼
	exit(0);
}

void CRouterDlg::OnBnClickedNicSetButton()
{
	LPADAPTER adapter = NULL;		// 랜카드에 대한 정보를 저장하는 pointer 변수
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
	m_nic1.GetLBText(m_nic1.GetCurSel() , DeviceName1);	// 콤보 박스에 선택된 Device의 이름을 얻어옴
	m_nic2.GetLBText(m_nic2.GetCurSel() , DeviceName2);
	while(Devices != NULL) {
		if(!strcmp(Devices->description,DeviceName1))
			Device1 = Devices;
		if(!strcmp(Devices->description,DeviceName2))
			Device2 = Devices;
		Devices = Devices->next;
	}
	// device설정
	m_NILayer->SetDevice(Device1,1);
	m_NILayer->SetDevice(Device2,2);
	
	RtDlg.setDeviceList(Device1->description,Device2->description);
	//mac 주소 설정
	adapter = PacketOpenAdapter((Device1->name+8));
	PacketRequest( adapter, FALSE, OidData);
	m_EthernetLayer->SetSourceAddress(OidData->Data,1);
	adapter = PacketOpenAdapter((Device2->name+8));
	PacketRequest( adapter, FALSE, OidData);
	m_EthernetLayer->SetSourceAddress(OidData->Data,2);
	//ip주소 설정
	// 랜카드에 대한 정보들을 읽어와 Combo 박스에 추가하는 부분
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
	// router Table Add버튼
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
	// router Table delete버튼
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
			gateway.Format("%s","연결됨");
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

		/* select_entry가 존재하지 않는 경우 */
		if(select_entry.Interface == -2){
			for(int j=0; j<4; j++)
				result[j] = destip[j] & entry.Netmask[j];

			/* destination이 같은 경우 */
			if(!memcmp(result,entry.Destination,4)){ 

				/* gateway로 보내는 경우 */
				if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x02)){ 
					select_entry = entry;
					m_IPLayer->SetDstIP(entry.Gateway);
				}

				/* gateway가 아닌 경우 */
				else if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x00)){ 
					select_entry = entry;
					m_IPLayer->SetDstIP(destip);
				}
			}
		}
		/* 존재하는 경우 */
		else { 
			for(int j=0; j<4; j++)
				result[j] = destip[j] & entry.Netmask[j];

			/* 기존 select비트 보다 1의 개수가 많은 경우 */
			if(memcmp(result,entry.Netmask,4)){ 
				for(int j=0; j<4; j++)
					result[j] = destip[j] & entry.Netmask[j];

				/* destation이 같은 경우 */
				if(!memcmp(result,entry.Destination,4)){ 

					/* gateway로 보내는 경우 */
					if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x02)){ 
						select_entry = entry;
						m_IPLayer->SetDstIP(entry.Gateway);
					}

					/* gateway가 아닌 경우 */
					else if(((entry.Flag & 0x01) == 0x01) && ((entry.Flag & 0x02) == 0x00)){ 
						select_entry = entry;
						m_IPLayer->SetDstIP(destip);
					}
				}
			}
			/* 더 적을 경우 pass */
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
			//hop을 16으로 바꿈.
			if( entry.expirationTime==0)
			{
				entry.Metric=16;
			}
			//테이블에서 삭제.
			if( entry.garbageCollectionTime==0)
			{
				route_table.RemoveAt(index);
				UpdateRouteTable();
			}
		}
		break;
	//주기적인 타이머, 30초마다 갱신 메시지를 보냄.
	case UPDATE_TIMER:
		sendRIP();
		break;
	}
	CDialog::OnTimer(nIDEvent);
}

void CRouterDlg::OnCbnSelchangeNic1Combo()
{// ip주소 설정
}

void CRouterDlg::OnCbnSelchangeNic2Combo()
{ //ip 주소 설정
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