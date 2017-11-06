

#include "ARP.h"
#include "IP.h"
#include "Ethernet.h"
#include "heap_5.h"

ARP_Cache * pARP_Cache = 0x00;

void ARP_Init(void)
{
	uint8_t i;
	ADDR Address = { 0 };

	pARP_Cache = (ARP_Cache*)MM_Ops.Malloc(sizeof(ARP_Cache) * ARP_CACHE_CAPACITY);
	if (pARP_Cache != NULL)memset((uint8_t*)pARP_Cache,0x00, sizeof(ARP_Cache) * ARP_CACHE_CAPACITY);

	Address.RemoteIP = IP_Str2Int("192.168.120.1");
	Address.RemoteMAC = MAC_Str2Int("11:22:33:44:55:66");
	ARP_AddItem(&Address.RemoteIP, &Address.RemoteMAC);

	Address.RemoteIP = IP_Str2Int("255.255.255.255");
	Address.RemoteMAC = MAC_Str2Int("FF:FF:FF:FF:FF:FF");
	ARP_AddItem(&Address.RemoteIP, &Address.RemoteMAC);
}

uint8_t ARP_GetIP_ByMAC(MAC * mac,IP * ip, uint8_t * IndexOfCache)
{
	uint8_t i,*Buf1,*Buf2;

	Buf2 = (uint8_t*)mac;

	for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&pARP_Cache[i].MAC;

		if (pARP_Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(MAC)) == 0)
		{
			if (ip != NULL)*ip = pARP_Cache[i].IP;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	return ARP_False;
}

uint8_t ARP_GetMAC_ByIP(IP * ip, MAC * mac, uint8_t * IndexOfCache, uint8_t SendRequest)
{
	uint8_t i, *Buf1, *Buf2;

	Buf2 = (uint8_t*)ip;

	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&pARP_Cache[i].IP;

		if (pARP_Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(IP)) == 0)
		{
			if (mac != NULL)*mac = pARP_Cache[i].MAC;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	/* 找不到ip则发送ARP请求报文 */
	if (SendRequest != NULL)ARP_SendRequest(ip);
	return ARP_False;
}

void ARP_AddItem(IP * ip, MAC * mac)
{
	uint8_t IndexOfCache = 0,i;

	if (ARP_GetMAC_ByIP(mac, NULL, &IndexOfCache,NULL) == ARP_True)
	{
		pARP_Cache[IndexOfCache].TTL = ARP_TTL_MAX;
	}
	else
	{
		for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
		{
			if (pARP_Cache[i].Used == ARP_False)
			{
				pARP_Cache[i].Used = ARP_True;
				memcpy((uint8_t*)&pARP_Cache[i].IP, ip, sizeof(IP));
				memcpy((uint8_t*)&pARP_Cache[i].MAC, mac, sizeof(MAC));
				pARP_Cache[i].TTL = ARP_TTL_MAX;
				return;
			}
		}
	}
}

void ARP_TickTask(void)
{
	uint8_t i;
	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		if (pARP_Cache[i].Used == ARP_True)
		{
			pARP_Cache[i].TTL -= 1;
			if (pARP_Cache[i].TTL <= 0)
			{
				pARP_Cache[i].Used = ARP_False;
			}
			/* TTL较少到一半时自动发送ARP请求 */
			if (pARP_Cache[i].TTL <= ARP_TTL_MAX / 2)
			{
				ARP_SendRequest(&pARP_Cache[i].IP);
			}
		}
	}
}

static RES prvARP_PreProcesspacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header*pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;

	if (DIY_ntohs(pARP_Header->HardwareType) == ARP_HardwareType && 
		pARP_Header->HardwareLen == ARP_HardwareLen &&
		DIY_ntohs(pARP_Header->ProtocolType) == ARP_ProtocolType &&
		pARP_Header->ProtocolLen == ARP_ProtocolLen)
	{
		return RES_ARPPacketPass;
	}
	return RES_ARPPacketDeny;
}

static void ARP_SendRespon(NeteworkBuff * pOldNeteorkBuff)
{
	Ethernet_Header * pOldEthernet_Header = (Ethernet_Header*)&pOldNeteorkBuff->Buff;
	ARP_Header * pOldARP_Header = (ARP_Header*)&pOldEthernet_Header->Buff;

	NeteworkBuff * pNewNeteworkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + ARP_HeaderLen);

	Ethernet_Header * pNewEthernet_Header = (Ethernet_Header*)&pNewNeteworkBuff->Buff;
	ARP_Header * pNewARP_Header = (ARP_Header*)&pNewEthernet_Header->Buff;
	/* ETH */
	pNewEthernet_Header->DstMAC = pOldEthernet_Header->SrcMAC;
	pNewEthernet_Header->SrcMAC = LocalMAC;
	pNewEthernet_Header->Type = DIY_htons(EthernetType_ARP);
	/* ARP */
	pNewARP_Header->DstIP.U32 = pOldARP_Header->SrcIP.U32;
	pNewARP_Header->DstMAC = pOldARP_Header->SrcMAC;
	pNewARP_Header->SrcIP.U32 = DIY_htonl(LocalIP.U32);
	pNewARP_Header->SrcMAC = LocalMAC;
	pNewARP_Header->HardwareLen = ARP_HardwareLen;
	pNewARP_Header->HardwareType = DIY_htons(ARP_HardwareType);
	pNewARP_Header->Opcode = DIY_htons(ARP_OpcodeRespond);
	pNewARP_Header->ProtocolLen = ARP_ProtocolLen;
	pNewARP_Header->ProtocolType = DIY_htons(ARP_ProtocolType);
	/* TX */
	Ethernet_TransmitPacket(pNewNeteworkBuff);
}

void ARP_SendRequest(IP * TargetIP)
{
	NeteworkBuff * pNewNeteworkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + ARP_HeaderLen);
	Ethernet_Header * pNewEthernet_Header = (Ethernet_Header*)&pNewNeteworkBuff->Buff;
	ARP_Header * pNewARP_Header = (ARP_Header*)&pNewEthernet_Header->Buff;
	/* ETH */
	pNewEthernet_Header->DstMAC = BrocastMAC;
	pNewEthernet_Header->SrcMAC = LocalMAC;
	pNewEthernet_Header->Type = DIY_htons(EthernetType_ARP);
	/* ARP */
	pNewARP_Header->DstIP.U32 = DIY_htonl(TargetIP->U32);
	pNewARP_Header->DstMAC = ZeroMAC;
	pNewARP_Header->SrcIP.U32 = DIY_htonl(LocalIP.U32);
	pNewARP_Header->SrcMAC = LocalMAC;
	pNewARP_Header->HardwareLen = ARP_HardwareLen;
	pNewARP_Header->HardwareType = DIY_htons(ARP_HardwareType);
	pNewARP_Header->Opcode = DIY_htons(ARP_OpcodeRequest);
	pNewARP_Header->ProtocolLen = ARP_ProtocolLen;
	pNewARP_Header->ProtocolType = DIY_htons(ARP_ProtocolType);
	/* TX */
	Ethernet_TransmitPacket(pNewNeteworkBuff);
}

void ARP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header*pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;
	IP ip = { 0 };
	if (prvARP_PreProcesspacket(pNeteorkBuff) != RES_ARPPacketPass)return;

	if (DIY_ntohs(pARP_Header->Opcode) == ARP_OpcodeRequest)
	{
		ip.U32 = DIY_ntohl(pARP_Header->SrcIP.U32);
		ARP_AddItem(&ip, &pARP_Header->SrcMAC);
		ip.U32 = DIY_ntohl(pARP_Header->DstIP.U32);
		if(ip.U32 == LocalIP.U32)ARP_SendRespon(pNeteorkBuff);
	}
	if (DIY_ntohs(pARP_Header->Opcode) == ARP_OpcodeRespond)
	{
		ip.U32 = DIY_ntohl(pARP_Header->SrcIP.U32);
		ARP_AddItem(&ip, &pARP_Header->SrcMAC);
	}
}

RES ARP_IsIpExisted(IP * ip,uint32_t Timeout) {
	MAC mac = { 0 };

	if (ARP_GetMAC_ByIP(&ip, &mac, 0, 1) == ARP_False) {
		while (Timeout--) {
			Delay(1);
			if (ARP_GetMAC_ByIP(&ip, &mac, 0, 0) == ARP_True)return RES_True;
		}
		return RES_False;
	}
	return RES_True;
}

uint8_t DebugBuff1[] = 
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2a,
	0xff,0xff,0xff,0xff,0xff,0xff,0x01,0x02,
	0x03,0x04,0x05,0x06,0x08,0x06,0x00,0x01,
	0x08,0x00,0x06,0x04,0x00,0x01,0x01,0x02,
	0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,
	0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x08,
	0x09,0x00,
};
uint8_t DebugBuff2[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2a,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x06,0x00,0x01,
	0x08,0x00,0x06,0x04,0x00,0x02,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x07,0x08,0x09,0x00,
	0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,
	0x03,0x04,

};
uint8_t DebugBuff3[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2a,
	0xff,0xff,0xff,0xff,0xff,0xff,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x06,0x00,0x01,
	0x08,0x00,0x06,0x04,0x00,0x01,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x07,0x08,0x09,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,
	0x03,0x04,
};
uint8_t DebugBuff4[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2a,
	0x07,0x08,0x09,0x0a,0x0b,0x0c,0x01,0x02,
	0x03,0x04,0x05,0x06,0x08,0x06,0x00,0x01,
	0x08,0x00,0x06,0x04,0x00,0x02,0x01,0x02,
	0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,
	0x07,0x08,0x09,0x0a,0x0b,0x0c,0x07,0x08,
	0x09,0x00,
};

NeteworkBuff * pNeteorkBuff[] = 
{
	(NeteworkBuff*)DebugBuff1,
	(NeteworkBuff*)DebugBuff2,
	(NeteworkBuff*)DebugBuff3,
	(NeteworkBuff*)DebugBuff4,
};

static void prvARP_PrintfMAC(MAC * mac)
{
	uint8_t i = 0;
	for (i = 0; i < 6; i++)
	{
		printf("%02X ", mac->Byte[i]);
	}
}

static void prvARP_PrintfIP(IP * ip)
{
	int8_t i = 0;
	for (i = 3; i >= 0; i--)
	{
		printf("%X ", ip->U8[i]);
	}
}

void ARP_PrintTable(void)
{
	uint16_t i = 0;
	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		if (pARP_Cache[i].Used == ARP_True)
		{
			prvARP_PrintfIP(&pARP_Cache[i].IP);
			printf("    @    ");
			prvARP_PrintfMAC(&pARP_Cache[i].MAC);
			printf("\r\n");
		}
	}
}

void ARP_Test(void)
{
	uint8_t i = 0; IP ip = { 0,9,8,7 };

	for (i = 0; i < sizeof(pNeteorkBuff)/sizeof(pNeteorkBuff[0]); i++)
	{
		Ethernet_ProcessPacket(pNeteorkBuff[i]);
		MainLoop();
		ARP_PrintTable();
	}

	ARP_SendRequest(&ip);
	MainLoop();
}

