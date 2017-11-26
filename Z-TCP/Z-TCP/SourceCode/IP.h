
#ifndef __IP_H__
#define __IP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Socket.h"

#define IP_VersionIPV4	4
#define	IP_Flags_DF		2
#define	IP_Flags_MF		1

#define IP_PacketDelete 0
#define IP_PacketPass	1

#define IP_HeaderLen	20

#define IP_Protocol_ICMP	1
#define IP_Protocol_IGMP	2
#define IP_Protocol_TCP		6
#define IP_Protocol_UDP		17

#define IP_VersionOffset	0x000F
#define IP_HeaderLenOffset	0x00F0
#define IP_TOS_Offset		0xFF00
#define IP_FlagsOffset		0x0007
#define IP_Offset_Offset	0xFFF8
#define IP_TTL_Offset		0x00FF
#define IP_Protocol_Offset	0xFF00

#define IP_TTL_MAX			64

#define IP_GetVersion(x)	(x >> 4)
#define IP_GetHeaderLen(x)	((x & 0x0f)*4)
#define IP_SetHeaderLenVersion(H,V)	((H)/4 | (V) << 4)

#pragma pack (1)
typedef struct IP_Header_
{
	uint8_t VL;
	uint8_t TOS;
	uint16_t TotalLen;
	uint16_t Identify;
	uint16_t FO;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t CheckSum;
	IP SrcIP;
	IP DstIP;
	uint8_t Buff;
}IP_Header;
#pragma pack ()

extern IP  LocalIP;
extern IP  BrocastIP;
extern MAC ZeroMAC;
extern IP  GatewayIP;

void IP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
void prvIP_FillPacket(NeteworkBuff * pNeteworkBuff, IP * RemoteIP, uint8_t Protocol, uint32_t IpDataLen);
uint32_t IP_GetOptionSize(void);
void IP_Init(uint8_t * str_LocalIP, uint8_t * str_GatewayIP);
#ifdef __cplusplus
}
#endif

#endif



