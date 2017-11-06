#include "IP.h"
#include "Ethernet.h"
#include "DHCP.h"
#include "UDP.h"

/* RFC1533 */
static uint32_t oplen[] = {
	pad,0,
	subnet_mask,4,
	dns,oplen_4n,
	log,oplen_4n,
	hostname,24,
	ifmtu,2,
	broadcast,1,
	staticrouter,oplen_8n,
	arptimeout,4,
	ntp,oplen_4n,
	leasetime,4,
	messagetype,1,
	serveid,4,
	end,0,
	request_ip,4,
	option_over,1,
	para_list,oplen_n,
	max_message_size,2,
	client_id,oplen_n
};

DHCP_CB_ DHCP_CB = { 0 };
uint8_t DHCP_OptinBuff[500] = { 0 };
uint32_t DHCP_OptinBuff_Len = 0;
uint8_t ClientID[] = { "ZJYC_ZJYC" };
uint8_t ParaList[] = {6,33};
uint8_t ConstCookie[] = { 99,130,83,99 };
uint8_t Chaddr[] = "123456";

/* ��ȡĳһ��ѡ������۳��� */
static uint32_t GetOpLen(opname name) {
	uint32_t i, len = sizeof(oplen) / sizeof(uint32_t) / 2;
	for (i = 0; i < len; i++) {
		if ((uint32_t)name == oplen[i * 2]) {
			return oplen[i * 2 + 1];
		}
	}
	return 0;
}

/*
****************************************************
*  ������         :DHCP_Init
*  ��������       :DHCP��ʼ��
*  ����           :
*  ����ֵ         :
*  ����           : -5A4A5943-
*  ��ʷ�汾       :
*****************************************************
*/

void DHCP_Init() {
	memcpy(&DHCP_CB.chaddr, &LocalMAC.Byte, sizeof(MAC));
	DHCP_CB.ciaddr.U32 = LocalIP.U32;
	DHCP_CB.CurState = DHCP_INIT;
	DHCP_CB.ClientId = ClientID;
	DHCP_CB.Xid = prvDHCP_GetRandom();
	memcpy(&DHCP_CB.chaddr, Chaddr, sizeof(Chaddr));
}

/*
****************************************************
*  ������         :prvDHCP_PreProcessPacket
*  ��������       :Ԥ�ȴ���DHCP���ݰ����ж�xid��
*  ����           :
*  ����ֵ         :
*  ����           : -5A4A5943-
*  ��ʷ�汾       :
*****************************************************
*/

static RES prvDHCP_PreProcessPacket(NeteworkBuff * pNeteorkBuff) {
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	DHCP_Header * pDHCP_Header = (DHCP_Header*)&pUDP_Header->Buff;

	if (DIY_htonl(DHCP_CB.Xid) != pDHCP_Header->xid)return RES_False;
	if (DHCP_CB.CurState == DHCP_INIT) {
		/* ... */
	}
	if (DHCP_CB.CurState == DHCP_SELECTING) {
		if (pDHCP_Header->op != BOOTREPLY)return RES_False;
	}

	return RES_True;
}

void DHCP_ProcessPacket(NeteworkBuff * pNeteorkBuff) {
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	DHCP_Header * pDHCP_Header = (DHCP_Header*)&pUDP_Header->Buff;
	/*  */
	if (prvDHCP_PreProcessPacket(pNeteorkBuff) == RES_False)return;

	if (DHCP_CB.CurState == DHCP_SELECTING) {
		DHCP_CB.ciaddr.U32 = DIY_ntohl(pDHCP_Header->yiaddr.U32);
		//DHCP_CB.siaddr.U32 = DIY_ntohl(pDHCP_Header->siaddr.U32);
		if (memcmp(DHCP_CB.chaddr, pDHCP_Header->chaddr, sizeof(DHCP_CB.chaddr)) != 0)return;
		prvDHCP_ProcessOptions(&pDHCP_Header->options);
		if (ARP_IsIpExisted(&DHCP_CB.ciaddr,10) == RES_True)return;
		DHCP_CB.CurState = DHCP_REQUES;
	}

}

static RES prvDHCP_ProcessOptions(uint8_t * Options) {
	uint32_t i = 0,OptionLen = 0;

	if (memcmp(Options, ConstCookie, 4) != 0)return RES_False;

	Options += 4;

	while (1) {
		switch (Options[i]) {
		case leasetime: {
			uint32_t Temp = 0;
			OptionLen = Options[i + 1];
			Temp = *(uint32_t*)(&Options[i + 2]);
			DHCP_CB.Lease = DIY_ntohl(Temp);
			i += 6;
			break;
		}
		case serveid: {
			DHCP_CB.ServeID = *(uint32_t*)(&Options[i + 2]);
			DHCP_CB.ServeID = DIY_ntohl(DHCP_CB.ServeID);
			i += 6;
			break;
		}
		case messagetype: {
			DHCP_CB.MessageType = Options[i + 2];
			i += 3;
			break;
		}
		case client_id: {
			uint32_t Len = Options[i + 1];
			if (memcmp(&Options[i + 2], DHCP_CB.ClientId , Len) != 0)return RES_False;
			i += 2 + Len;
			break;
		}
		case pad: {
			i++; break;
		}
		case end: {
			return RES_True;
			break;
		}
		default:break;
		}
	}
	return RES_True;
}

static uint32_t prvDHCP_SetSingleOption(uint8_t * OptionBuff,uint8_t Type, uint32_t Value) {
	uint32_t OpLen = GetOpLen(Type);
	*OptionBuff++ = Type;
	if (Type == client_id) {
		*OptionBuff++ = OpLen = sizeof(ClientID);
		memcpy(OptionBuff, (uint8_t*)Value, sizeof(ClientID));
	}
	if (Type == para_list) {
		*OptionBuff++ = OpLen = sizeof(ParaList);
		memcpy(OptionBuff, (uint8_t*)Value, sizeof(ParaList));
	}
	if ((Type != client_id) && (Type != para_list)) {
		/* ������4�����ڵ� */
		if (OpLen == 0) {
			/* end */
		}
		if (OpLen == 1) {
			*OptionBuff++ = OpLen;
			*OptionBuff = Value;
		}
		if (OpLen == 2) {
			*OptionBuff++ = OpLen;
			*(uint16_t*)OptionBuff = (uint16_t)Value;
		}
		if (OpLen == 4) {
			*OptionBuff++ = OpLen;
			*(uint32_t*)OptionBuff = (uint32_t)Value;
		}
		/* ���ȳ���4�� */
		if (OpLen > 4)memcpy(OptionBuff, (uint8_t*)Value, OpLen);
	}
	return OpLen == 0 ? 1 : (OpLen + 2);/* ��ѡ���ܳ��� */
}

static prvDHCP_GenerateOption(uint8_t* Buff,uint32_t * OptionLen) {
	/*
		must have:messagetype+coockie
	*/
	/* copy cookie */
	memcpy(Buff, ConstCookie, sizeof(ConstCookie));
	*OptionLen += sizeof(ConstCookie);

	if (DHCP_CB.CurState == DHCP_INIT) {
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), messagetype, DHCPDISCOVER);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), leasetime, DIY_htonl(100));
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), para_list, &ParaList);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), client_id, &ClientID);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), end,255);
	}
	if (DHCP_CB.CurState == DHCP_REQUES) {
		IP ip = { 0 };
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), messagetype, DHCPREQUEST);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), leasetime, DIY_htonl(100));
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), client_id, &ClientID);
		ip.U32 = DIY_htonl(DHCP_CB.ServeID);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), serveid, ip.U32);
		*OptionLen += prvDHCP_SetSingleOption((uint8_t*)(Buff + *OptionLen), end, 255);
	}
	/* *4 */
	*OptionLen = (*OptionLen % 4) ? (*OptionLen / 4 * 4 + 4) : *OptionLen;

	return;
}
/*
****************************************************
*  ������         :prvDHCP_GetRandom
*  ��������       :�����������xid...��
*  ����           :
*  ����ֵ         :
*  ����           : -5A4A5943-
*  ��ʷ�汾       :
*****************************************************
*/
static uint32_t prvDHCP_GetRandom() {
	return 0;
}
/*
****************************************************
*  ������         :prvDHCP_AllocPacket
*  ��������       :����һDHCP���ݰ���������Ԥ���
*  ����           :
*  ����ֵ         :���绺��
*  ����           : -5A4A5943-
*  ��ʷ�汾       :
*****************************************************
*/
static NeteworkBuff * prvDHCP_AllocPacket() {
	uint32_t OptionLen = 0; uint8_t Buff[100] = { 0 };
	/* based on currnt state.... */
	prvDHCP_GenerateOption(Buff,&OptionLen);
	/* DHCP_Header ͷ�����ȱ����ȥ1 */
	uint32_t DHCP_Len = OptionLen + sizeof(DHCP_Header) - 1;
	/* DHCP ��ΪUDP������ */
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirTx, UDP_GetPacketSize(DHCP_Len));
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	DHCP_Header * pDHCP_Header = (DHCP_Header*)&pUDP_Header->Buff;

	pUDP_Header->DataLen = DHCP_Len + UDP_HEADE_LEN;

	pDHCP_Header->htype = 1;
	pDHCP_Header->hlen = 6;
	pDHCP_Header->hops = 0;
	pDHCP_Header->secs = 0;
	pDHCP_Header->flags = 0;///???
	pDHCP_Header->xid = DIY_htonl(DHCP_CB.Xid);
	memcpy(&pDHCP_Header->chaddr, DHCP_CB.chaddr, sizeof(DHCP_CB.chaddr));
	/* ����ѡ��� */
	memcpy(&pDHCP_Header->options, Buff, OptionLen);

	return pNeteworkBuff;
}

/*
****************************************************
*  ������         :prvDHCP_FillPacket
*  ��������       :DHCP���ݰ����������
*  ����           :���绺��
*  ����ֵ         :
*  ����           : -5A4A5943-
*  ��ʷ�汾       :
*****************************************************
*/
static void prvDHCP_FillPacket(NeteworkBuff *pNeteworkBuff) {
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	DHCP_Header * pDHCP_Header = (DHCP_Header*)&pUDP_Header->Buff;

	switch (DHCP_CB.CurState)
	{
	case DHCP_INIT: {
		if (DHCP_CB.ciaddr.U32 == 0) {	/* have no ip address */
			pDHCP_Header->flags |= 0x80;/* we need servers to brocast any message */
		}
		pDHCP_Header->op = BOOTREQUEST;
		//BrocastIP
		prvUDP_FillPacket(pNeteworkBuff, &BrocastIP, \
			DHCP_SERVER_PORT,DHCP_CLIENT_PORT,(uint8_t*)pDHCP_Header,\
			pUDP_Header->DataLen - UDP_HEADE_LEN);
		break;
	}
	case DHCP_REQUES: {
		pDHCP_Header->op = BOOTREQUEST;
		pDHCP_Header->ciaddr.U32 = DIY_htonl(DHCP_CB.ciaddr.U32);
		prvUDP_FillPacket(pNeteworkBuff, &DHCP_CB.ServeID, \
			DHCP_SERVER_PORT, DHCP_CLIENT_PORT, (uint8_t*)pDHCP_Header, \
			pUDP_Header->DataLen - UDP_HEADE_LEN);
		break;
	}
	default:break;
	}

	

}

void DHCP_MainLoop() {
	switch (DHCP_CB.CurState) {
	case DHCP_INIT: {/* send discovery */
		NeteworkBuff * pNeteworkBuff = prvDHCP_AllocPacket();
		prvDHCP_FillPacket(pNeteworkBuff);
		Ethernet_TransmitPacket(pNeteworkBuff);
		DHCP_CB.CurState = DHCP_SELECTING;
		break;
	} 
	case DHCP_REQUES: {
		NeteworkBuff * pNeteworkBuff = prvDHCP_AllocPacket();
		prvDHCP_FillPacket(pNeteworkBuff);
		Ethernet_TransmitPacket(pNeteworkBuff);
		DHCP_CB.CurState = DHCP_BOUND;
		break;
	}
	default:break;
	}
}

/*
	**************************************************************************
	**************************************************************************
	**************************************************************************
*/
uint8_t DebugBuffXX_DHCP_Offer[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x124,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02,
	0x02, 0x02, 0x02, 0x02, 0x08, 0x00, 0x45, 0x00,
	0x01, 0x16, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x73, 0xd1, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01,
	0x01, 0x01, 0x00, 0x44, 0x00, 0x43, 0x01, 0x02,
	0xb4, 0x65, 0x02, 0x01, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x32,
	0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
	0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0xc0,
	0xa8, 0x78, 0x01, 0xff,
};
void DHCP_Test() {
	DHCP_MainLoop();
	MainLoop();
	MainLoop();
	Ethernet_ProcessPacket(DebugBuffXX_DHCP_Offer);
	MainLoop();
	MainLoop();
	DHCP_MainLoop();
	MainLoop();
	MainLoop();
}



