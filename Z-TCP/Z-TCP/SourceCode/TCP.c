
#include "IP.h"
#include "Ethernet.h"
#include "TCP.h"
#include "TCP_WIN.h"

/* 
	API应包括以下功能
	选项字段X
	校验X
	找到数据头X

	检查选项字段
	自身状态机制

*/

uint8_t TCP_OptionBuff[32] = { 0x00 };

static NeteworkBuff * prvTCP_AllocateEmptyPacket(TCP_Control * pTCP_Control, TCP_Header ** pTCP_Header);

static uint32_t prvTCP_GetRandom(void)
{
	return 0;
}

static uint16_t prvTCP_GetCheckSum(uint16_t * PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes)
{
	uint32_t cksum = 0;
	uint16_t TempDebug = 0;
	while (PseudoLenBytes)
	{
		TempDebug = *PseudoHeader++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		PseudoLenBytes -= 2;
	}
	while (DataLenBytes > 1)
	{
		TempDebug = *Data++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		DataLenBytes -= 2;
	}
	if (DataLenBytes)
	{
		TempDebug = (*(uint8_t *)Data); TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}

static RES prvTCP_ChecksumCalculate(IP_Header * pIP_Header,uint16_t * pCheckSum)
{
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;
	//Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	//if (pSocket == NULL)return RES_TCPPacketDeny;

	CheckSum = DIY_ntohs((pTCP_Header)->CheckSum);
	(pTCP_Header)->CheckSum = 0;
	PayloadLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen;
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_TCP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);
	CheckTemp = prvTCP_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pTCP_Header, PayloadLen);
	if (pCheckSum)*pCheckSum = CheckTemp;
	if (CheckTemp != CheckSum)return RES_TCPPacketDeny;
	return RES_TCPPacketPass;
}
/* 从接收包中获取数据地址和长度 */
static void prvGetDataBuff_LenRx(IP_Header * pIP_Header,uint8_t ** Buff,uint16_t * Len)
{
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;
	if(Len)*Len = IP_TotalLen - TCP_HeaderLen - IP_HeaderLen;
	if(Buff)*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}
/* 从要发送的包中获取数据地址，长度不能获取 */
static uint8_t * prvTCP_GetDataBuffToTx(TCP_Header * pTCP_Header)
{
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF) / 4;
	return (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}
/* 获取接受数据包的选项字段 */
static void prvGetOptionBuffRx(TCP_Header * pTCP_Header, uint8_t ** Option, uint16_t * OptionLen)
{
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;

	if(OptionLen)*OptionLen = TCP_HeaderLen - TCP_HEADE_LEN_MIN;
	if(Option)*Option = (uint8_t*)((uint32_t)pTCP_Header + TCP_HEADE_LEN_MIN);
}
/* 处理接受的选项字段 */
static void prvTCP_ProcessOptionRx(TCP_Control * pTCP_Control, uint8_t * Option, uint16_t Len)
{
	uint16_t i = 0,LenTemp = 0;
	uint32_t Value = 0;
	for (i = 0; i < Len;)
	{
		if (*Option == TOK_MSS)
		{
			LenTemp = *(Option + 1);
			Value = (*(Option + 2) << 8) + *(Option + 3);
			pTCP_Control->RemoteMSS = Value;
			Option += LenTemp;
			i += LenTemp;
		}
		if (*Option == TOK_WSOPT)
		{
			LenTemp = *(Option + 1);
			Value = *(Option + 2);
			pTCP_Control->RemoteWinScale = Value;
			Option += LenTemp;
			i += LenTemp;
		}
		if (*Option == TOK_NOP)
		{
			Option += 1;
			i += LenTemp;
		}
		if (*Option == TOK_NOP)
		{
			break;
		}
	}
}
/* 处理接受的窗口大小 */
static void prvTCP_ProcessWinsize(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	uint16_t Winsize = pTCP_Header->WinSize;
	if (Winsize != pTCP_Control->RemoteWinSize)
	{
		pTCP_Control->WIN_Change = 1;
		pTCP_Control->RemoteWinSize = Winsize;
	}
}

static void prvTCP_Handle_Established(TCP_Control * pTCP_Control)
{
	/* 创建TCP窗体 */
	if (pTCP_Control->pTCP_Win == 0)
	{
		pTCP_Control->pTCP_Win = prvTCPWin_NewWindows(pTCP_Control->LocalWinSize, pTCP_Control->RemoteWinSize);
		pTCP_Control->pTCP_Win->MSS = pTCP_Control->RemoteMSS;
		pTCP_Control->pTCP_Win->Sn = pTCP_Control->LocalSN;
	}
	else
	{

	}
}

static void prvTCP_Handle_SYN_Recv(TCP_Control * pTCP_Control, NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint8_t * Option = 0;
	uint16_t OptionLen = 0;
	pTCP_Control->RemoteSN = pTCP_Header->SN;
	pTCP_Control->RemoteWinSize = pTCP_Header->WinSize;

	prvGetOptionBuff(pNeteorkBuff, &Option, &OptionLen);
	prvTCP_ProcessOption(pTCP_Control, Option, OptionLen);
	//send SYN+ACK
	prvTCP_FillPacket(pTCP_Control, 0, 0);
}

static uint32_t prvTCP_ProcessSN_ACK_Num(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;

	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED)
	{
		if (pTCP_Control->LocalSN != pTCP_Header->AK)
		{
			if (pTCP_Control->LocalSN + 1 != pTCP_Header->AK)return;
		}
		pTCP_Control->RemoteSN = pTCP_Header->SN;
	}
	else
	{

	}
}
/* 计算要发送的选项字段大小 */
static uint32_t prvTCP_GetOptionSizeToTx(TCP_Control * pTCP_Control)
{
	uint32_t OptionSize = 0;

	if (pTCP_Control->MSS_Send == 0 || pTCP_Control->MSS_Change)
	{
		//pTCP_Control->MSS_Send = 1;
		//pTCP_Control->MSS_Change = 0;
		OptionSize += 4;
	}
//	if (pTCP_Control->WIN_Sent == 0 || pTCP_Control->WIN_Change)
//	{
//		//pTCP_Control->WIN_Sent = 1;
//		//pTCP_Control->WIN_Change = 0;
//		OptionSize += 4;
//	}
	if (pTCP_Control->TSOPT)OptionSize += 10;
	return OptionSize;
}
/* 计算要发送的数据大小 */
static uint32_t prvTCP_GetDataSizeToTx(TCP_Control * pTCP_Control)
{
	uint32_t DataLen = 0;

	if (pTCP_Control->pTCP_Win)
	{
		/* 需要发送的数据长度在Len中 */
		TCPWin_GetDataToTx(pTCP_Control->pTCP_Win,0,&DataLen,1);
	}
	else
	{
		DataLen = 0;
	}
	return DataLen;
}
/* 计算要发送的底层大小 */
static uint32_t prvTCP_GetLowLayerSizeToTx(TCP_Control * pTCP_Control)
{
	return EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize();
}
/* 获取要发送的包的总长度 */
static uint32_t prvTCP_GetPacketSizeToTx(TCP_Control * pTCP_Control)
{
	uint32_t OptionLen = prvTCP_GetOptionSizeToTx(pTCP_Control);
	uint32_t DataLen = prvTCP_GetDataSizeToTx(pTCP_Control);
	uint32_t LLSize = prvTCP_GetLowLayerSizeToTx(pTCP_Control);
	uint32_t WholePacketSize = OptionLen + DataLen + LLSize + TCP_HEADE_LEN_MIN;

	return WholePacketSize;
}

static uint32_t prvTCP_GetTCPLen(TCP_Control * pTCP_Control)
{
	uint32_t OptionLen = prvTCP_GetOptionSizeToTx(pTCP_Control);
	uint32_t DataLen = prvTCP_GetDataSizeToTx(pTCP_Control);
	uint32_t WholePacketSize = OptionLen + DataLen + TCP_HEADE_LEN_MIN;
	return WholePacketSize;
}

static void prvTCP_FillWinSizeToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	pTCP_Header->WinSize = DIY_htons(pTCP_Control->LocalWinSize);
}

static void prvTCP_FillOptionToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	uint8_t * pOption = &pTCP_Header->Option , OptionLen = 0;

	if (pTCP_Control->MSS_Send == NULL || pTCP_Control->MSS_Change)
	{
		pTCP_Control->MSS_Send = 1;
		pTCP_Control->MSS_Change = 0;
		pOption[OptionLen + 0] = (uint8_t)TOK_MSS;
		pOption[OptionLen + 1] = 4;
		pOption[OptionLen + 2] = pTCP_Control->LocalMSS / 256;
		pOption[OptionLen + 3] = pTCP_Control->LocalMSS % 256;
		OptionLen += 4;
	}

//	if (pTCP_Control->WIN_Sent == NULL || pTCP_Control->WIN_Change)
//	{
//		pTCP_Control->WIN_Sent = 1;
//		pTCP_Control->WIN_Change = 0;
//		pOption[OptionLen + 0] = (uint8_t)TOK_WSOPT;
//		pOption[OptionLen + 1] = 3;
//		pOption[OptionLen + 2] = pTCP_Control->LocalWinScale;
//		pOption[OptionLen + 3] = TOK_NOP;
//		OptionLen += 4;
//	}
	/* 以后再加吧 */
}

static void prvTCP_FillDataToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	uint8_t * Buff = prvTCP_GetDataBuffToTx(pTCP_Header);
	uint8_t * Data = 0;
	uint32_t Len = 0;

	TCPWin_GetDataToTx(pTCP_Control->pTCP_Win,&Data,&Len,0);
	memcpy((uint8_t*)Buff, (uint8_t*)Data, Len);

}

void TCP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEth_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header *)&pIP_Header->Buff;
	Socket * pSocket = 0;
	TCP_Control * pTCP_Control = 0;
	uint8_t Flags = pTCP_Header->Flags;;
	RES res = 0;

	if (prvTCP_ChecksumCalculate(pIP_Header,0) != RES_TCPPacketPass)return;
	pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	if (pSocket) { pTCP_Control = pSocket->pTCP_Control; }else return;

	if (prvTCP_IpPortRx(pTCP_Control, pTCP_Header, pIP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_FlagsRx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_SN_ACK_Rx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_OptionWinsizeRx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_DataRx(pTCP_Control, pTCP_Header, pIP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_StateMachine(pTCP_Control, pTCP_Header) == RES_TCPPacketRespond)
	{
		uint32_t TCP_PacketLen = prvTCP_GetTCPLen(pTCP_Control);
		/* 预算数据包大小，并提前申请内存 */
		NeteworkBuff * pNeteorkBuff = prvTCP_AllocateEmptyPacket(pTCP_Control, &pTCP_Header, &pIP_Header);
		prvTCP_DataTx(pTCP_Control, pTCP_Header);
		prvTCP_OptionWinsizeTx(pTCP_Control, pTCP_Header);
		prvTCP_SN_ACK_Tx(pTCP_Control, pTCP_Header);
		prvTCP_FlagsTx(pTCP_Control, pTCP_Header);
		prvTCP_ChecksumTx(pTCP_Header,pIP_Header);
		prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP, TCP_PacketLen);
		Ethernet_TransmitPacket(pNeteorkBuff);
	}
}

static NeteworkBuff * prvTCP_AllocateEmptyPacket(TCP_Control * pTCP_Control, TCP_Header ** ppTCP_Header, IP_Header ** ppIP_Header)
{
	NeteworkBuff * pNeteorkBuff = Network_New(NetworkBuffDirTx, prvTCP_GetPacketSizeToTx(pTCP_Control));
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	(pTCP_Header)->SrcPort = DIY_ntohs(pTCP_Control->LocalPort);
	(pTCP_Header)->DstPort = DIY_ntohs(pTCP_Control->RemotePort);
	(pTCP_Header)->HeaderLen = ((prvTCP_GetOptionSizeToTx(pTCP_Control) + TCP_HEADE_LEN_MIN)/4) << 4;

	pIP_Header->SrcIP.U32 = LocalIP.U32;
	pIP_Header->DstIP.U32 = pTCP_Control->RemoteIP.U32;

	if (ppTCP_Header)*ppTCP_Header = pTCP_Header;
	if (ppIP_Header)*ppIP_Header = pIP_Header;

	return pNeteorkBuff;
}

static RES prvTCP_IpPortRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header, IP_Header * pIP_Header)
{
	if (pTCP_Control->RemoteIP.U32 == 0)
	{
		pTCP_Control->RemoteIP.U32 = DIY_ntohl(pIP_Header->SrcIP.U32);
	}
	else
	{
		if (pTCP_Control->RemoteIP.U32 != pIP_Header->SrcIP.U32)return RES_TCPPacketDeny;
	}

	if (pTCP_Control->RemotePort == 0)
	{
		pTCP_Control->RemotePort = DIY_ntohs(pTCP_Header->SrcPort);
	}
	return RES_TCPPacketPass;
}

static RES prvTCP_FlagsRx(TCP_Control * pTCP_Control,TCP_Header * pTCP_Header)
{
	switch (pTCP_Control->State)
	{
		case TCP_STATE_LISTEN:
		{
			if (pTCP_Header->Flags == TCP_FLAG_SYN)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_SYN_RECV:
		{
			if (pTCP_Header->Flags == TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_SYN_SENT:
		{
			if (pTCP_Header->Flags == TCP_FLAG_SYN | TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		default:break;
	}
	return RES_TCPPacketDeny;
}

static RES prvTCP_SN_ACK_Rx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	if (pTCP_Control->LocalSN_Informed)
	{
		if (pTCP_Header->AK != pTCP_Control->LocalSN)return RES_TCPPacketDeny;
	}
	if (pTCP_Control->RemoteSN_Knowed)
	{
		if(pTCP_Header->SN == pTCP_Control->RemoteSN)return RES_TCPPacketDeny;
	}
	if (!pTCP_Control->RemoteSN_Knowed)
	{
		pTCP_Control->RemoteSN_Knowed = 1;
		pTCP_Control->RemoteSN = pTCP_Header->SN;
	}
	return RES_TCPPacketPass;
}

static RES prvTCP_OptionWinsizeRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	uint8_t * Option = 0;
	uint32_t OptionLen = 0;

	prvGetOptionBuffRx(pTCP_Header,&Option,&OptionLen);
	prvTCP_ProcessOptionRx(pTCP_Control, Option, OptionLen);
	prvTCP_ProcessWinsize(pTCP_Control, pTCP_Header);
	return RES_TCPPacketPass;;
}

static RES prvTCP_DataRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header, IP_Header * pIP_Header)
{
	uint8_t * Data = 0;
	uint32_t DataLen = 0;
	if (pTCP_Control->State > TCP_STATE_ESTABLISHED)
	{
		prvGetDataBuff_LenRx(pIP_Header, &Data, &DataLen);
		TCPWin_AddRxData(pTCP_Control->pTCP_Win, Data, DataLen);
	}
	return RES_TCPPacketPass;
}

static RES prvTCP_StateMachine(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	if (pTCP_Control->State == TCP_STATE_CLOSED)
	{
		pTCP_Control->State = TCP_STATE_SYN_SENT;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_LISTEN)
	{
		pTCP_Control->State = TCP_STATE_SYN_RECV;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_RECV)
	{
		pTCP_Control->State = TCP_STATE_ESTABLISHED;
		pTCP_Control->HSF = 1;
		return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_SENT)
	{
		pTCP_Control->State = TCP_STATE_ESTABLISHED;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED)
	{
		prvTCP_Handle_Established(pTCP_Control);
	}
	/* 如果有数据需要发送，则值为RES_TCPPacketRespond */
}

static RES prvTCP_DataTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	if (pTCP_Control->State > TCP_STATE_ESTABLISHED)
	{
		prvTCP_FillDataToTx(pTCP_Control, pTCP_Header);
	}
}

static RES prvTCP_OptionWinsizeTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	prvTCP_FillOptionToTx(pTCP_Control, pTCP_Header);
	prvTCP_FillWinSizeToTx(pTCP_Control, pTCP_Header);
}

static RES prvTCP_SN_ACK_Tx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	pTCP_Header->SN = DIY_htonl(pTCP_Control->LocalSN);
	if (pTCP_Control->State < TCP_STATE_ESTABLISHED)
	{
		pTCP_Control->LocalSN += 1;
		pTCP_Control->RemoteSN += 1;
		if (pTCP_Control->RemoteSN_Knowed)pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0)
	{
		pTCP_Control->LocalSN += 1;
	}
	pTCP_Control->LocalSN_Informed = 1;
}

static RES prvTCP_FlagsTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
	if (pTCP_Control->State == TCP_STATE_SYN_RECV)
	{
		pTCP_Header->Flags |= TCP_FLAG_ACK | TCP_FLAG_SYN;
		return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0)
	{
		pTCP_Control->HSF = 1;
		pTCP_Header->Flags |= TCP_FLAG_ACK;
		return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_SENT)
	{
		pTCP_Header->Flags |= TCP_FLAG_SYN;
	}
}

static RES prvTCP_ChecksumTx(TCP_Header * pTCP_Header,IP_Header * pIP_Header)
{
	uint16_t CheckSum = 0;
	prvTCP_ChecksumCalculate(pIP_Header, &CheckSum);
	pTCP_Header->CheckSum = DIY_htons(CheckSum);
}

uint8_t DebugBuffXX_1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x66, 0xb8, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x4e, 0x22, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
};

uint8_t DebugBuffXX_2[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x66, 0xbe, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0x00, 0x64, 0x65, 0xbb, 0x00, 0x00, 0x02, 0x04, 0x00, 0x0a
};

uint8_t DebugBuffXX_3[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x66, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x07, 0x08, 0x09, 0x00, 0x04, 0xd2, 0x1e, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, 0x12, 0x00, 0x5a, 0x65, 0xb4, 0x00, 0x00, 0x02, 0x04, 0x00, 0x0a

};
NeteworkBuff * DebugNeteworkBuff = (NeteworkBuff*)DebugBuffXX_1;

#include "TCP_Task.h"

void TCP_Test(void)
{
	NeteworkBuff * DebugNeteworkBuff = 0;
	ADDR addr = {0};
	addr.LocalPort = 1234;
	Socket * pSocket = prvSocket_New(&addr,IP_Protocol_TCP);
	Socket_Listen(pSocket);

	DebugNeteworkBuff = (NeteworkBuff*)DebugBuffXX_2;
	Ethernet_ProcessPacket(DebugNeteworkBuff);
	MainLoop();
	DebugNeteworkBuff = (NeteworkBuff*)DebugBuffXX_3;
	Ethernet_ProcessPacket(DebugNeteworkBuff);
	MainLoop();
}





