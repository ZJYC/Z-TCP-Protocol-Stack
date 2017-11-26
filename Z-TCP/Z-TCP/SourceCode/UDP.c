#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "Basic.h"
#include "UDP.h"
#include "DHCP.h"
/* 
	UDP���ֽ�Ϊ��
*/

/* Ԥ����UDP���ݰ� */
static RES UDP_PreProcessPacket(NeteworkBuff * pNeteorkBuff){
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	/* ���˿��Ƿ�� */
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs(pUDP_Header->DstPort));
	if (pSocket == NULL)return RES_UDPPacketDeny;
	return RES_UDPPacketPass;
}
/* ���UDP���ݰ� */
void prvUDP_FillPacket(NeteworkBuff * pNeteorkBuff, IP * RemoteIP,uint16_t DstPort, uint16_t SrcPort,uint8_t * Data, uint32_t Len){
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint8_t * pUDP_Payload = (uint8_t*)&pUDP_Header->Buff;
	uint16_t LenTemp = 0, PayloadLen;

	pUDP_Header->DataLen = DIY_htons(Len + UDP_HEADE_LEN);
	pUDP_Header->DstPort = DIY_htons(DstPort);
	pUDP_Header->SrcPort = DIY_htons(SrcPort);
	memcpy(pUDP_Payload, Data, Len);
	/* IP�� */
	prvIP_FillPacket(pNeteorkBuff, RemoteIP, IP_Protocol_UDP, DIY_htons(pUDP_Header->DataLen));
}
/* ����UDP���ݰ� */
void UDP_ProcessPacket(NeteworkBuff * pNeteorkBuff){
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	/* Ԥ���� */
	if (UDP_PreProcessPacket(pNeteorkBuff) != RES_UDPPacketPass)return;
	/* �²�Э�� */
	switch (DIY_ntohs(pUDP_Header->DstPort))
	{
	case DHCP_CLIENT_PORT: {
		DHCP_ProcessPacket(pNeteorkBuff);
		break;
	}
		default:break;
	}

}
/* ��ȡUDP���ݰ��Ĵ�С */
uint32_t UDP_GetPacketSize(uint32_t DataLen){
	return EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize() + UDP_HEADE_LEN + DataLen;
}





