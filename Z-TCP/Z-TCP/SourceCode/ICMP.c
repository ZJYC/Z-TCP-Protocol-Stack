
#include "ICMP.h"
#include "IP.h"
#include "Ethernet.h"
#include "DHCP.h"
#include "UDP.h"

uint32_t ICMPLen[] = {
	17,12,0,
	18,12,0,
	13,15,0,
	14,15,0,
	3,36,0,
	0,8,1,
	8,8,1,
	11,36,0,
	5,36,0,
	4,36,0,
	15,8,0,
	16,8,0,
};
ICMP_CB_ ICMP_CB = { 0 };

static void prvICMP_FillPacket(NeteworkBuff * pNeteworkBuff, uint8_t * Data, uint16_t Len);
static NeteworkBuff * prvICMP_AllocPacket(uint16_t ICMP_Type);

static uint32_t prvICMP_GetPacketLen(uint16_t ICMP_Type) {
	uint32_t i = 0,Len = 0;
	uint32_t Type = (ICMP_Type & 0xFF00) >> 8;
	while (1) {//找到本消息的长度
		if (i < sizeof(ICMPLen)) {
			if (Type == ICMPLen[i]) {
				Len += ICMPLen[i + 1];
				break;
			}
			i += 3;
		}
	}
	//本消息由附加内容
	if (ICMPLen[i + 2]) {
		if ((Type == ((ECHO_Send & 0xFF00) >> 8)) || (Type == ((ECHO_Send & 0xFF00) >> 8))) {
			Len += ECHO_DATA_LEN;
		}
		if ((Type == ((ECHO_Reply & 0xFF00) >> 8)) || (Type == ((ECHO_Reply & 0xFF00) >> 8))) {
			Len += ICMP_CB.ECHO_LastDataLen;
		}
	}

	return Len;
}

void ICMP_ProcessPacket(NeteworkBuff * pNeteorkBuff) {
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;
	/* 目前只能处理ping报文 */
	uint16_t ICMP_Type = (pICMP_Header->Type << 8) | pICMP_Header->Code;
	switch (pICMP_Header->Type) {
	case (ECHO_Send & 0xFF00) >> 8: {/* 收到别人的ping */
		uint16_t DataLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen - 8;/* 数据长度 */
		ICMP_CB.ECHO_LastDataLen = DataLen;
		uint16_t ICMP_Len = prvICMP_GetPacketLen(ECHO_Reply);
		NeteworkBuff * pNeteworkBuff2 = prvICMP_AllocPacket(ECHO_Reply);
		ICMP_CB.ECHO_LastID = DIY_ntohs(*(uint16_t*)&pICMP_Header->Type2[0]);
		ICMP_CB.ECHO_LastSeq = DIY_ntohs(*(uint16_t*)&pICMP_Header->Type2[2]);
		prvICMP_FillPacket(pNeteworkBuff2, (uint8_t*)&pICMP_Header->Buff,DataLen);
		prvIP_FillPacket(pNeteworkBuff2, &pIP_Header->SrcIP, IP_Protocol_ICMP, ICMP_Len);
		Ethernet_TransmitPacket(pNeteworkBuff2);
		break; 
	}
	case (ECHO_Reply & 0xFF00) >> 8: {/* 收到ping回复 */
		uint16_t DataLen = pIP_Header->TotalLen - IP_HeaderLen - 8;/* 数据长度 */
		if (ICMP_CB.ECHO_LastID != DIY_ntohs(*(uint16_t*)&pICMP_Header->Type2[0]))return;
		if (ICMP_CB.ECHO_LastSeq != DIY_ntohs(*(uint16_t*)&pICMP_Header->Type2[2]))return;
		return;
		break;
	}
	default:break;
	}
}

static NeteworkBuff * prvICMP_AllocPacket(uint16_t ICMP_Type) {
	uint32_t Type = (ICMP_Type & 0xFF00) >> 8, Code = ICMP_Type & 0xFF;
	uint32_t ICMP_Len = prvICMP_GetPacketLen(ICMP_Type);
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirTx, IP_GetPacketSize(ICMP_Len));
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;

	pICMP_Header->Type = Type;
	pICMP_Header->Code = Code;

	return pNeteworkBuff;
}

static void prvICMP_FillPacket(NeteworkBuff * pNeteworkBuff,uint8_t * Data,uint16_t Len) {

	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;

	switch (pICMP_Header->Type) {
	case (ECHO_Send & 0xFF00) >> 8: {
		uint16_t DataLen = ECHO_DATA_LEN,i = 0;
		uint8_t * Buff = &pICMP_Header->Buff;
		uint16_t * Pointer = 0;
		//复制数据到ICMP
		for (i = 0; i < ECHO_DATA_LEN; i += sizeof(ECHO_DATA)) {
			memcpy(Buff, ECHO_DATA, sizeof(ECHO_DATA)); Buff += sizeof(ECHO_DATA);
		}
		Pointer = (uint16_t *)&pICMP_Header->Type2[0];
		ICMP_CB.ECHO_LastID = 0x1234;
		*Pointer = DIY_htons(ICMP_CB.ECHO_LastID);
		Pointer = (uint16_t *)&pICMP_Header->Type2[2];
		ICMP_CB.ECHO_LastSeq = 0x5678;
		*Pointer = DIY_htons(ICMP_CB.ECHO_LastSeq);
		break;
	}
	case (ECHO_Reply & 0xFF00) >> 8: {
		uint8_t * Buff = &pICMP_Header->Buff;
		uint16_t * Pointer = 0;
		memcpy(Buff, Data, Len);
		Pointer = (uint16_t *)&pICMP_Header->Type2[0];
		ICMP_CB.ECHO_LastID = 0x1234;
		*Pointer = DIY_htons(ICMP_CB.ECHO_LastID);
		Pointer = (uint16_t *)&pICMP_Header->Type2[2];
		ICMP_CB.ECHO_LastSeq = 0x5678;
		*Pointer = DIY_htons(ICMP_CB.ECHO_LastSeq);
		break;
	}
	default:break;
	}

}

/*
****************************************************
*  函数名         :
*  函数描述       :
*  参数           :
*  返回值         :
*  作者           : -5A4A5943-
*  历史版本       :
*****************************************************
*/

RES ICMP_Ping(IP ip) {
		uint32_t ICMP_Len = prvICMP_GetPacketLen(ECHO_Send);
		NeteworkBuff * pNeteworkBuff = prvICMP_AllocPacket(ECHO_Send);
		prvICMP_FillPacket(pNeteworkBuff, 0, 0);
		prvIP_FillPacket(pNeteworkBuff, &ip, IP_Protocol_ICMP, ICMP_Len);
		Ethernet_TransmitPacket(pNeteworkBuff);
}

uint8_t ICMP_PingSend[] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01,
	0xd0, 0x98, 0x00, 0x00, 0x00, 0x00, 0x01, 0x78,
	0xa8, 0xc0, 0x08, 0x00, 0x1a, 0xaa, 0x12, 0x34,
	0x56, 0x78, 0x5a, 0x4a, 0x59, 0x43, 0x2d, 0x00,
	0x5a, 0x4a, 0x59, 0x43, 0x2d, 0x00, 0x5a, 0x4a,
	0x59, 0x43, 
};

/*
void ICMP_Test() {
	IP ip = IP_Str2Int("192.168.120.1");
	uint32_t ICMP_Len = prvICMP_GetPacketLen(ECHO_Send);
	NeteworkBuff * pNeteworkBuff = prvICMP_AllocPacket(ECHO_Send);
	prvICMP_FillPacket(pNeteworkBuff,0,0);
	prvIP_FillPacket(pNeteworkBuff,&ip, IP_Protocol_ICMP, ICMP_Len);
	Ethernet_TransmitPacket(pNeteworkBuff);
	MainLoop();
	PHY_Ethernet_DriverRecv(ICMP_PingSend,sizeof(ICMP_PingSend));
	MainLoop();
	MainLoop();
	while (1);
}
*/