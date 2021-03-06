
#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"

#define EthernetType_IP		0x0800
#define EthernetType_ARP	0x0806

#define EthernetHeaderLen	14

#define EthernetPacketPass		0x01
#define EthernetPacketDelete	0x00

#pragma pack (1)
typedef struct Ethernet_Header_
{
	MAC DstMAC;
	MAC SrcMAC;
	uint16_t Type;
	uint8_t Buff;
}Ethernet_Header;
#pragma pack ()

void Ethernet_SendNetworkBuff(NeteworkBuff * pNeteorkBuff);
void Ethernet_TransmitPacket(NeteworkBuff * pNeteorkBuff);
void Ethernet_ProcessPacket(NeteworkBuff * pNeteorkBuff);
void Ethernet_FillPacket(NeteworkBuff * pNeteorkBuff, uint32_t Protocol, IP * RemoteIP);
void Ethernet_Init(uint8_t * str_LocalMAC);
void PHY_Ethernet_DriverRecv(uint8_t * Data, uint32_t Len);
void Ethernet_RecvNetworkBuff(uint8_t * Data, uint32_t Len);
void Ethernet_ReceivePacket(NeteworkBuff * pNeteorkBuff);

extern NeteworkBuff NeteorkBuffTemp;
extern MAC LocalMAC;
extern MAC BrocastMAC;

#ifdef __cplusplus
}
#endif


#endif
