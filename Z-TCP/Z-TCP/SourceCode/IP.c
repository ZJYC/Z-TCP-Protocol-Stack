
#include "DataTypeDef.h"
#include "IP.h"
#include "Ethernet.h"
#include "UDP.h"
#include "TCP.h"
#include "Socket.h"
#include "Basic.h"

IP  LocalIP = {0};
IP  GatewayIP = { 0 };
MAC ZeroMAC = {0x00,0x00, 0x00, 0x00, 0x00, 0x00};
IP  BrocastIP = {0};

static uint16_t prvIP_GetIdentify(void)
{
	return 1;
}

void IP_Init(uint8_t * str_LocalIP, uint8_t * str_GatewayIP) {
#if DHCP_EN /* 如果使能DHCP就不需要预装IP地址，会自动获取 */
	LocalIP = IP_Str2Int("0.0.0.0");
	GatewayIP = IP_Str2Int("0.0.0.0");
#else
	LocalIP = IP_Str2Int(str_LocalIP);
	GatewayIP = IP_Str2Int(str_GatewayIP);
#endif
	BrocastIP = IP_Str2Int("255.255.255.255");
}

/*
****************************************************
*  Function       : prvIP_PreProcessPacket
*  Description    : 预处理IP数据包，包括校验和、版本号和目标IP
*  Params         : pIP_Header:IP header pointer
*  Return         : 
					IP_PacketPass:The packet need to further process
					IP_PacketDelete:Just ignore this packet
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--14--51--17
					in the future I will add some new feature.This is just a simple framework.
*****************************************************
*/
static RES prvIP_PreProcessPacket(IP_Header * pIP_Header){
	uint16_t Checksum = DIY_ntohs(pIP_Header->CheckSum);
	if (IsCheckSumRight(pIP_Header) != RES_True)return IP_PacketDelete;
	//pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	//pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	if (IP_GetVersion(pIP_Header->VL) != IP_VersionIPV4)return IP_PacketDelete;
	if (DIY_ntohl(pIP_Header->DstIP.U32) == LocalIP.U32)return IP_PacketPass;
	if (DIY_ntohl(pIP_Header->DstIP.U32) == BrocastIP.U32)return IP_PacketPass;
	/* new for debug DHCP */
	if (LocalIP.U32 == 0)return IP_PacketPass;
	return IP_PacketDelete;
}

/*
****************************************************
*  Function       : IP_ProcessPacket
*  Description    : 受到带有IP协议的网络数据包，本函数首先检查本数据包，然后提交到更高层来处理
*  Params         : pIP_Header:pointer of IP Header
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--14--56--37
					Add a tunnel to UDP procotol
*****************************************************
*/
void IP_ProcessPacket(NeteworkBuff * pNeteorkBuff){
	Ethernet_Header * pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEth_Header->Buff;
	if (prvIP_PreProcessPacket(pIP_Header) == IP_PacketPass){
		if (pIP_Header->Protocol != IP_Protocol_UDP){
			IP ip = {0};
			ip.U32 = DIY_ntohl(pIP_Header->SrcIP.U32);
			ARP_AddItem(&ip, &pEth_Header->SrcMAC);
		}
		switch (pIP_Header->Protocol){
		case IP_Protocol_ICMP: {/* 目前只能相应PING */
			ICMP_ProcessPacket(pNeteorkBuff);
			break;
		}
		case IP_Protocol_IGMP:/*IGMP_ProcessPacket(pNeteworkBuff); */break;
		case IP_Protocol_TCP:{
			TCP_ProcessPacket(pNeteorkBuff);
			break;
		}
		case IP_Protocol_UDP:{
			UDP_ProcessPacket(pNeteorkBuff); break;
		}
		default:break;
		}
	}
}

/*
****************************************************
*  Function       : prvIP_FillPacket
*  Description    : 通常，高层协议想要发送数据，本函数负责填充大部分IP域。
*  Params         : pSocket:pointer of Socket
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--15--01--46
					Just a simple successful implement,Will add new feature in the future.
*****************************************************
*/
void prvIP_FillPacket(NeteworkBuff * pNeteworkBuff, IP * RemoteIP,uint8_t Protocol,uint32_t IpDataLen){
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	MAC Temp;
	/* IP */
	//pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	//pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	//pIP_Header->U_FO.U_FO_ALL = DIY_ntohs(pIP_Header->U_FO.U_FO_ALL);

	//pIP_Header->U_VL.S_VL_ALL.Version = IP_VersionIPV4;
	//pIP_Header->U_VL.S_VL_ALL.HeaderLen = IP_HeaderLen/4;
	pIP_Header->VL = IP_SetHeaderLenVersion(IP_HeaderLen, IP_VersionIPV4);
	pIP_Header->TOS = 0;
	pIP_Header->Identify = prvIP_GetIdentify();
	pIP_Header->Identify = DIY_ntohs(pIP_Header->Identify);
	pIP_Header->FO = 0;
	//pIP_Header->U_FO.S_FO_ALL.Offset = 0;
	pIP_Header->TTL = IP_TTL_MAX;
	pIP_Header->Protocol = Protocol;
	pIP_Header->DstIP.U32 = DIY_htonl(RemoteIP->U32);
	pIP_Header->SrcIP.U32 = DIY_htonl(LocalIP.U32);
	pIP_Header->TotalLen = DIY_ntohs(IpDataLen + IP_HeaderLen + IP_GetOptionSize());

	//pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	//pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	//pIP_Header->U_FO.U_FO_ALL = DIY_ntohs(pIP_Header->U_FO.U_FO_ALL);

	//pIP_Header->CheckSum = prvIP_GetCheckSum(pIP_Header);
	//pIP_Header->CheckSum = DIY_htons(pIP_Header->CheckSum);
	FillCheckSum(pIP_Header);
	/* ETH */
	Ethernet_FillPacket(pNeteworkBuff, EthernetType_IP, RemoteIP);
}
/* 获取IP数据包选项的大小 这里暂时不支持 */
uint32_t IP_GetOptionSize(void){
	return 0;
}
/* 获取IP数据包的大小：以太网头长度+IP头长度+IP选项长度+IP数据长度 */
uint32_t IP_GetPacketSize(uint32_t DataSize) {
	return EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize() + DataSize;
}

