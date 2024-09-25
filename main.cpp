#include "pcap.h"
#include<iostream>
#include<WinSock2.h>
#include<iomanip>
#include<cstring>
#include<format>
#include<vector>
#include<ctime>
#include<queue>
#include<thread>
#include<mutex>
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define RO_DEFAULT 0x1
#define RO_STATIC 0x10
#define RO_DIRECT 0x100

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"WS2_32.lib")
using namespace std;
#pragma pack(1)
typedef struct FrameHeader_t {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
} FrameHeader_t;

typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
} IPHeader_t;

typedef struct Data_t {
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

typedef struct ARPData_t {
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
} ARPData_t;

typedef struct Packet_t {
	FrameHeader_t FrameHeader;
	union {
		IPHeader_t IPHeader;
		ARPData_t ARPData;
	} Data;
} Packet_t;

typedef struct ARRFrame_t {
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
} ARPFrame_t;

typedef struct RouterTable_t {
	DWORD IP;
	DWORD Mask;
	DWORD Next;
	WORD flag;
} RouterTable_t;

typedef struct ARPTable_t {
	clock_t time;
	int keep;
	DWORD IP;
	BYTE Mac[6];
} ARPTable_t;

#pragma pack()

mutex queueMutex;
queue<Packet_t*> msgQuene;
vector<RouterTable_t> routerTable;
vector<ARPTable_t> ARPTable;
vector<sockaddr_in> localAddrs;
BYTE deviceMAC[6];
DWORD deviceMask = 0x00FFFFFF;
pcap_t* adhandle;

void capPack(pcap_t* adhandle)
{
	Data_t* IPPacket;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			continue;
		//cout << header->ts.tv_sec << " " << header->ts.tv_usec << " len: " << header->len << endl;

		IPPacket = (Data_t*)pkt_data;
		BYTE* desMac = IPPacket->FrameHeader.DesMAC;
		BYTE* srcMac = IPPacket->FrameHeader.SrcMAC;
		string DesMAC = format("desMAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", desMac[0], desMac[1], desMac[2], desMac[3], desMac[4], desMac[5]);
		string SrcMAC = format("srcMAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
		cout << SrcMAC << "\t" << DesMAC
			<< "\ttype: 0x" << hex << ntohs(IPPacket->FrameHeader.FrameType)
			<< "\t\tlen: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;
	}
}


void sendARPReply(pcap_t* adhandle, DWORD sIP, BYTE sMAC[], DWORD requestIP, BYTE* requestMAC, BYTE dstMAC[])
{
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = dstMAC[i];
		ARPFrame.FrameHeader.SrcMAC[i] = sMAC[i];
		ARPFrame.SendHa[i] = sMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(2);
	ARPFrame.SendIP = sIP;
	ARPFrame.RecvIP = requestIP;
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
}

void sendARP(pcap_t* adhandle, DWORD sIP, BYTE sMAC[], DWORD requestIP, BYTE* requestMAC, bool waitReply = true)
{
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;
		ARPFrame.FrameHeader.SrcMAC[i] = sMAC[i];
		ARPFrame.SendHa[i] = sMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(1);
	ARPFrame.SendIP = sIP;
	ARPFrame.RecvIP = requestIP;
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	if (!waitReply)
		return;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			continue;
		//cout << header->ts.tv_sec << " " << header->ts.tv_usec << " len: " << header->len << endl;

		IPPacket = (ARPFrame_t*)pkt_data;
		WORD frameType = ntohs(IPPacket->FrameHeader.FrameType);
		if (frameType != 0x0806 || IPPacket->RecvIP != sIP || IPPacket->SendIP != requestIP)
			continue;
		for (int i = 0; i < 6; i++)
		{
			if (IPPacket->RecvHa[i] != sMAC[i])
				continue;
		}
		BYTE* sendHa = IPPacket->SendHa;
		BYTE* recvHa = IPPacket->RecvHa;
		ULONG sendIP = IPPacket->SendIP;
		ULONG recvIP = IPPacket->RecvIP;
		memcpy(requestMAC, sendHa, 6);
		return;
	}

}

bool isLocalIP(DWORD ip)
{
	for (auto& t : localAddrs)
	{
		if (ip == t.sin_addr.s_addr)
			return true;
	}
	return false;
}

RouterTable_t getRouteEntry(DWORD ip)
{
	auto it = routerTable.begin();
	RouterTable_t choose;
	choose.Mask = 0;
	while (it != routerTable.end())
	{
		if ((ip & it->Mask) == (it->IP & it->Mask) && it->Mask >= choose.Mask)
			choose = *it;
		it++;
	}
	return choose;
}

DWORD getSendIP(DWORD ip)
{
	RouterTable_t choose = getRouteEntry(ip);
	DWORD requestIP;
	if (choose.flag == RO_DIRECT)
	{
		requestIP = ip;
	}
	else
		requestIP = choose.Next;
	for (auto& t : localAddrs)
	{
		if ((requestIP & deviceMask) == (t.sin_addr.s_addr & deviceMask))
			return t.sin_addr.s_addr;
	}
	return localAddrs[0].sin_addr.s_addr;
}

bool getMAC(DWORD ip, BYTE MAC[])
{
	auto it = ARPTable.begin();
	for (; it != ARPTable.end(); it++)
	{
		if (it->IP == ip)
		{
			// 判断表项是否有效
			time_t local = clock();
			if (it->time + it->keep > local)
			{
				memcpy(MAC, it->Mac, 6);
				return true;
			}
			else
				break;
		}
	}
	if(it != ARPTable.end())
		ARPTable.erase(it);
	sendARP(adhandle, getSendIP(ip), deviceMAC, ip, nullptr, false);
	return false;
}

bool compMAC(BYTE MAC1[], BYTE MAC2[])
{
	for (int i = 0; i < 6; i++)
	{
		if (MAC1[i] != MAC2[i])
			return false;
	}
	return true;
}

void capData()
{
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	while (true)
	{
		Sleep(1);
		if ((res = pcap_next_ex(adhandle, &header, &pkt_data)) <= 0)
			continue;
		FrameHeader_t* frameHeader = (FrameHeader_t*)pkt_data;
		
		if (!compMAC(frameHeader->DesMAC, deviceMAC))
			continue;
		WORD frameType = ntohs(frameHeader->FrameType);
		if (frameType != 0x0800 && frameType != 0x0806)
			continue;
		if (frameType == 0x0800)
		{
			Data_t* IPPacket = (Data_t*)pkt_data;
			if (isLocalIP(IPPacket->IPHeader.SrcIP))
				continue;
			int len = ntohs(IPPacket->IPHeader.TotalLen);
			u_char* data = new u_char[len + sizeof(FrameHeader_t)];
			memcpy(data, pkt_data, len + sizeof(FrameHeader_t));
			{
				lock_guard<mutex> lock(queueMutex);
				msgQuene.push((Packet_t*)data);
			}
		}
		else if (frameType == 0x0806)
		{
			ARPFrame_t* ARPFrame = (ARPFrame_t*)pkt_data;
			if (isLocalIP(ARPFrame->SendIP))
				continue;
			u_char* data = new u_char[sizeof(ARPFrame_t)];
			memcpy(data, pkt_data, sizeof(ARPFrame_t));
			{
				lock_guard<mutex> lock(queueMutex);
				msgQuene.push((Packet_t*)data);
			}
		}
	}
}

uint16_t calcCheckSum(uint16_t* data, int size)
{
	uint32_t sum = 0;
	for (int i = 0; i < size / 2; i++)
	{
		sum += data[i];
		if (sum > 0xFFFF)
		{
			sum &= 0xFFFF;
			sum += 1;
		}
	}
	sum = ~sum;
	return sum;
}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;

	// 选择设备
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		cout << "获取设备失败: " << errbuf << endl;
		return 0;
	}
	for (d = alldevs; d; d = d->next)
	{
		cout << ++i << ". " << d->name << endl;
		if (d->description)
			cout << d->description << endl;
	}
	cout << "选择设备：" ;
	cin >> inum;
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
	cout << "正在监视设备：" << d->description << endl;
	pcap_freealldevs(alldevs);

	// 获取网卡IP地址
	char ip[INET_ADDRSTRLEN];
	pcap_addr_t* a;
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
			localAddrs.push_back(*((sockaddr_in*)(a->addr)));
	}
	if (localAddrs.size() == 0)
		cout << "获取IP地址失败" << endl;
	cout << "本机IP地址为：";
	for (auto& addr : localAddrs)
	{
		inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
		cout << ip << " ";
		ARPTable_t p = { clock(), 999999, (DWORD)(addr.sin_addr.s_addr)  };
		ARPTable.push_back(p);
	}
	cout << endl;

	// 添加默认路由
	{
		RouterTable_t t;
		t.IP = 0;
		t.Mask = 0;
		t.Next = 0x020101CE;
		t.flag = RO_DEFAULT;
		routerTable.push_back(t);
	}

	// 发送ARP请求获取网卡MAC地址
	DWORD deviceIP = localAddrs[0].sin_addr.S_un.S_addr;
	BYTE randMAC[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	sendARP(adhandle, deviceIP + 1, randMAC, deviceIP, deviceMAC);
	string deviceMACstr = format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", deviceMAC[0], deviceMAC[1], deviceMAC[2], deviceMAC[3], deviceMAC[4], deviceMAC[5]);
	cout << "设备MAC地址为:" << deviceMACstr << endl;
	for (auto& t : ARPTable)
	{
		memcpy(t.Mac, deviceMAC, 6);
	}
	cout << "请输入命令（add：添加路由表项；del：移除路由表项；show：展示路由表；exit：退出并捕获数据包）：" << endl;

	// 配置路由表项
	string command;
	while (true)
	{
		cin >> command;
		if (command == "add")
		{
			string IP, mask, next;
			cin >> IP >> mask >> next;
			RouterTable_t t;
			inet_pton(AF_INET, IP.c_str(), &t.IP);
			inet_pton(AF_INET, mask.c_str(), &t.Mask);
			if (next == "D" || next == "d")
			{
				t.flag = RO_DIRECT;
				t.Next = 0;
			}
			else
			{
				inet_pton(AF_INET, next.c_str(), &t.Next);
				t.flag = RO_STATIC;
			}
			routerTable.push_back(t);
		}
		else if (command == "show")
		{
			char output[INET_ADDRSTRLEN];
			int i = 0;
			for (auto& t : routerTable)
			{
				cout << i << " ";
				inet_ntop(AF_INET, &(t.IP), output, INET_ADDRSTRLEN);
				cout << output << " ";
				inet_ntop(AF_INET, &(t.Mask), output, INET_ADDRSTRLEN);
				cout << output << " ";
				if (t.flag == RO_DIRECT)
					cout << "Direct" << endl;
				else
				{
					inet_ntop(AF_INET, &(t.Next), output, INET_ADDRSTRLEN);
					cout << output << endl;
				}
				i++;
			}
		}
		else if (command == "del")
		{
			string delIP;
			cin >> delIP;
			auto it = routerTable.begin();
			for (; it != routerTable.end(); it++)
			{
				DWORD ip;
				inet_pton(AF_INET, delIP.c_str(), &ip);
				if (it->IP == ip)
					break;
			}
			if(it->flag)
			routerTable.erase(it);
		}
		else if (command == "exit")
			break;
	}
	thread cap(capData);
	// 处理IP数据包和ARP报文
	while (true)
	{
		Packet_t* packet;
		{
			lock_guard<mutex> lock(queueMutex);
			if (msgQuene.size() == 0)
				continue;
			packet = msgQuene.front();
			msgQuene.pop();
		}
		WORD frameType = ntohs(packet->FrameHeader.FrameType);
		DWORD recvIP;
		if (frameType == 0x0800)
		{
			// IP数据包需要判断捕获长度，并转发
			Data_t* IPPacket = (Data_t*)packet;
			recvIP = IPPacket->IPHeader.DstIP;
			int len = ntohs(IPPacket->IPHeader.TotalLen);
			RouterTable_t choose;
			choose = getRouteEntry(recvIP);
			if (calcCheckSum((uint16_t*)&IPPacket->IPHeader, sizeof(IPHeader_t)) != 0)
			{
				cout << "校验错误" << endl;
				continue;
			}
			IPPacket->IPHeader.Checksum = 0;
			IPPacket->IPHeader.TTL -= 1;
			IPPacket->IPHeader.Checksum = calcCheckSum((uint16_t*)&IPPacket->IPHeader, sizeof(IPHeader_t));
			if (choose.flag == RO_DIRECT)
			{
				bool ret = getMAC(IPPacket->IPHeader.DstIP, IPPacket->FrameHeader.DesMAC);
				if(ret)
					pcap_sendpacket(adhandle, (u_char*)packet, sizeof(FrameHeader_t) + len);
				if (ret) cout << "获取MAC地址成功 ";
				cout << "直接投递 ";
			}
			else if(compMAC(IPPacket->FrameHeader.DesMAC, deviceMAC))
			{
				bool ret = getMAC(choose.Next, IPPacket->FrameHeader.DesMAC);
				if(ret)
					pcap_sendpacket(adhandle, (u_char*)packet, sizeof(FrameHeader_t) + len);
				if (ret) cout << "获取MAC地址成功 ";
				cout << "路由转发 ";
			}
			char output[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(IPPacket->IPHeader.SrcIP), output, INET_ADDRSTRLEN);
			cout << "IP报文 " << "源IP：" << output << " ";
			inet_ntop(AF_INET, &recvIP, output, INET_ADDRSTRLEN);
			cout << "目的IP：" << output << " ";
			if (choose.flag == RO_DIRECT) {
				cout << "直接投递" << endl;
			}
			else
			{
				inet_ntop(AF_INET, &choose.Next, output, INET_ADDRSTRLEN);
				cout << "下一跳：" << output << endl;
			}
			u_char* data = (u_char*)packet;
			delete[] data;
		}
		else if (frameType == 0x0806)
		{
			// ARP报文需要判断是响应，加入ARP缓存
			ARPFrame_t* ARPFrame = (ARPFrame_t*)packet;
			int op = ARPFrame->Operation;
			if (op == ntohs(2))
			{
				ARPTable_t t;
				t.IP = ARPFrame->SendIP;
				memcpy(t.Mac, ARPFrame->SendHa, 6);
				t.time = clock();
				t.keep = 300000;
				ARPTable.push_back(t);
				char output[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &t.IP, output, INET_ADDRSTRLEN);
				string MACstr = format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", ARPFrame->SendHa[0], ARPFrame->SendHa[1], ARPFrame->SendHa[2], ARPFrame->SendHa[3], ARPFrame->SendHa[4], ARPFrame->SendHa[5]);
				cout << "收到ARP报文响应，添加ARP表项：" << output << " " << MACstr << endl;
				continue;
			}
		}
	}
	pcap_close(adhandle);
	return 0;
}
