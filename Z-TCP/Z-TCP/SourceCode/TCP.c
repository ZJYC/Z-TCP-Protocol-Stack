
#include "IP.h"
#include "Ethernet.h"
#include "TCP.h"
#include "TCP_WIN.h"

/* 
	有待改善：
		1、SCAK选项字的处理，当前是不支持的。
*/

static NeteworkBuff * prvTCP_AllocateEmptyPacket(TCP_Control * pTCP_Control, TCP_Header ** pTCP_Header);

static uint32_t prvTCP_GetRandom(void){
	return 0;
}

uint32_t TCP_GetInitSN(void){
	return 10;
}

/* 从接收包中获取数据地址和长度 */
static void prvGetDataBuff_LenRx(IP_Header * pIP_Header,uint8_t ** Buff,uint16_t * Len){
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = TCP_GetHeaderLen(pTCP_Header->HeaderLen);
	if(Len)*Len = IP_TotalLen - TCP_HeaderLen - IP_HeaderLen;
	if(Buff)*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}
/* 从要发送的包中获取数据地址，长度不能获取 */
static uint8_t * prvTCP_GetDataBuffToTx(TCP_Header * pTCP_Header){
	uint16_t TCP_HeaderLen = TCP_GetHeaderLen(pTCP_Header->HeaderLen);
	return (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}
/* 获取接受数据包的选项字段 */
static void prvGetOptionBuffRx(TCP_Header * pTCP_Header, uint8_t ** Option, uint16_t * OptionLen){
	uint16_t TCP_HeaderLen = TCP_GetHeaderLen(pTCP_Header->HeaderLen);
	if(OptionLen)*OptionLen = TCP_HeaderLen - TCP_HEADE_LEN_MIN;
	if(Option)*Option = (uint8_t*)((uint32_t)pTCP_Header + TCP_HEADE_LEN_MIN);
}
/* 处理接受的选项字段 */
static void prvTCP_ProcessOptionRx(TCP_Control * pTCP_Control, uint8_t * Option, uint16_t Len){
	uint16_t i = 0,LenTemp = 0;
	uint32_t Value = 0;
	for (i = 0; i < Len;){
		switch (*Option) {
		/* MSS选项字段 */
		case TOK_MSS: {
			LenTemp = *(Option + 1);
			Value = (*(Option + 2) << 8) + *(Option + 3);
			pTCP_Control->RemoteMSS = Value;
			Option += LenTemp;
			i += LenTemp;
			break;
		}
		/* 窗口放大因子 */
		case TOK_WSOPT: {
			LenTemp = *(Option + 1);
			Value = *(Option + 2);
			pTCP_Control->RemoteWinScale = Value;
			Option += LenTemp;
			i += LenTemp;
			break;
		}
		/* NOP选项 */
		case TOK_NOP: {
			LenTemp = 1;
			Option += 1;
			i += LenTemp;
			break;
		}
		/* 允许SACK */
		case TOK_SACK_Per: {
			LenTemp = *(Option + 1);
			pTCP_Control->RemoteSACK = 1;
			i += LenTemp;
			break;
		}
		default:break;
		}
	}
}
/* 处理接受的窗口大小 */
static void prvTCP_ProcessWinsize(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	uint16_t Winsize = DIY_ntohs(pTCP_Header->WinSize);
	if (Winsize != pTCP_Control->RemoteWinSize){
		pTCP_Control->WIN_Change = 1;
		pTCP_Control->RemoteWinSize = Winsize;
	}
}
/* 连接建立之后的处理函数 */
static RES prvTCP_Handle_Established(TCP_Control * pTCP_Control,uint32_t Ack){ 
	/* 创建TCP窗体 */
	if (pTCP_Control->pTCP_Win == 0){/* 创建窗体并填入MSS、SN、对方的接受能力 */
		uint32_t LocalWinSize = pTCP_Control->LocalWinSize * (1 << pTCP_Control->LocalWinScale);
		uint32_t RemoteWinSize = pTCP_Control->RemoteWinSize * (1 << pTCP_Control->RemoteWinScale);
		pTCP_Control->pTCP_Win = TCPWin_NewWindows(LocalWinSize, RemoteWinSize);
		pTCP_Control->pTCP_Win->MSS = pTCP_Control->RemoteMSS;
		pTCP_Control->pTCP_Win->Sn = pTCP_Control->LocalSN;
		printf("Create Windows Rx : %d Tx : %d \r\n", LocalWinSize, RemoteWinSize);
		return RES_TCPPacketPass;
	}
	else{
		/* 更新对方接收能力 */
		pTCP_Control->pTCP_Win->TxCapacity = pTCP_Control->RemoteWinSize * (1 << pTCP_Control->RemoteWinScale);
		/* 有人在等待应答 */
		if (pTCP_Control->pTCP_Win->pSegment_Wait){
			TCPWin_AckNormal(pTCP_Control->pTCP_Win,Ack);
			return RES_TCPPacketPass;
		}
		return RES_TCPPacketRespond;
	}
}
/*  */
static void prvTCP_Handle_SYN_Recv(TCP_Control * pTCP_Control, NeteworkBuff * pNeteorkBuff){
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

static uint32_t prvTCP_ProcessSN_ACK_Num(NeteworkBuff * pNeteorkBuff){
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;

	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED){
		if (pTCP_Control->LocalSN != pTCP_Header->AK){
			if (pTCP_Control->LocalSN + 1 != pTCP_Header->AK)return;
		}
		pTCP_Control->RemoteSN = pTCP_Header->SN;
	}
	else{ ; }
}
/* 计算要发送的选项字段大小 */
static uint32_t prvTCP_GetOptionSizeToTx(TCP_Control * pTCP_Control){
	uint32_t OptionSize = 0;
	if (pTCP_Control->MSS_Send == 0 || pTCP_Control->MSS_Change)OptionSize += 4;
	if (pTCP_Control->WIN_Sent == 0 || pTCP_Control->WIN_Change)OptionSize += 4;
	if (pTCP_Control->TSOPT)OptionSize += 12;
	if (pTCP_Control->LocalSACK)OptionSize += 4;
	if (OptionSize % 4 != 0)OptionSize = OptionSize / 4 * 4 + 4;
	return OptionSize;
}
/* 计算要发送的数据大小 */
static uint32_t prvTCP_GetDataSizeToTx(TCP_Control * pTCP_Control){
	uint32_t DataLen = 0;
	if (pTCP_Control->pTCP_Win){
		/* 需要发送的数据长度在Len中 */
		TCPWin_GetDataToTx(pTCP_Control->pTCP_Win,0,&DataLen,1);
	}
	else{
		DataLen = 0;
	}
	return DataLen;
}
/* 计算要发送的底层大小 */
static uint32_t prvTCP_GetLowLayerSizeToTx(TCP_Control * pTCP_Control){
	return EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize();
}
/* 获取要发送的包的总长度 */
static uint32_t prvTCP_GetPacketSizeToTx(TCP_Control * pTCP_Control){
	uint32_t OptionLen = prvTCP_GetOptionSizeToTx(pTCP_Control);
	uint32_t DataLen = prvTCP_GetDataSizeToTx(pTCP_Control);
	uint32_t LLSize = prvTCP_GetLowLayerSizeToTx(pTCP_Control);
	uint32_t WholePacketSize = OptionLen + DataLen + LLSize + TCP_HEADE_LEN_MIN;
	return WholePacketSize;
}

static uint32_t prvTCP_GetTCPLen(TCP_Control * pTCP_Control){
	uint32_t OptionLen = prvTCP_GetOptionSizeToTx(pTCP_Control);
	uint32_t DataLen = prvTCP_GetDataSizeToTx(pTCP_Control);
	uint32_t WholePacketSize = OptionLen + DataLen + TCP_HEADE_LEN_MIN;
	return WholePacketSize;
}

static void prvTCP_FillWinSizeToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	pTCP_Header->WinSize = DIY_htons(pTCP_Control->LocalWinSize);
}

static void prvTCP_FillOptionToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	/* Wireshark让我把NOP放在前面，其实我也不知道为什么 */
	/* 要4字节对齐的原因是TCP头部长度只能是4的倍数 */
	uint8_t * pOption = &pTCP_Header->Option , OptionLen = 0;

	if (pTCP_Control->MSS_Send == NULL || pTCP_Control->MSS_Change){
		pTCP_Control->MSS_Send = 1;
		pTCP_Control->MSS_Change = 0;
		pOption[OptionLen + 0] = (uint8_t)TOK_MSS;
		pOption[OptionLen + 1] = 4;
		pOption[OptionLen + 2] = pTCP_Control->LocalMSS / 256;
		pOption[OptionLen + 3] = pTCP_Control->LocalMSS % 256;
		OptionLen += 4;
	}
	if (pTCP_Control->WIN_Sent == NULL || pTCP_Control->WIN_Change){
		pTCP_Control->WIN_Sent = 1;
		pTCP_Control->WIN_Change = 0;
		pOption[OptionLen + 0] = TOK_NOP;
		pOption[OptionLen + 1] = (uint8_t)TOK_WSOPT;
		pOption[OptionLen + 2] = 3;
		pOption[OptionLen + 3] = pTCP_Control->LocalWinScale;
		OptionLen += 4;
	}
	if (pTCP_Control->LocalMSS) {
		pOption[OptionLen + 0] = TOK_NOP;
		pOption[OptionLen + 1] = TOK_NOP;
		pOption[OptionLen + 2] = (uint8_t)TOK_SACK_Per;
		pOption[OptionLen + 3] = 2;
		OptionLen += 4;
	}
	if (pTCP_Control->TSOPT) {/* 时间戳暂时伪造 */
		pOption[OptionLen + 0] = TOK_NOP;
		pOption[OptionLen + 1] = TOK_NOP;
		pOption[OptionLen + 2] = (uint8_t)TOK_TSOPT;
		pOption[OptionLen + 3] = 10;
		pOption[OptionLen + 4] = 'Z';
		pOption[OptionLen + 5] = 'J';
		pOption[OptionLen + 6] = 'Y';
		pOption[OptionLen + 7] = 'C';
		pOption[OptionLen + 8] = 'Z';
		pOption[OptionLen + 9] = 'J';
		pOption[OptionLen + 10] = 'Y';
		pOption[OptionLen + 11] = 'C';
		OptionLen += 12;
	}

	/* 以后再加吧 */
}

static void prvTCP_FillDataToTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header,uint32_t * TxLen){
	uint8_t * Buff = prvTCP_GetDataBuffToTx(pTCP_Header);
	uint8_t * Data = 0;
	uint32_t Len = 0;
	TCPWin_GetDataToTx(pTCP_Control->pTCP_Win,&Data,&Len,0);
	memcpy((uint8_t*)Buff, (uint8_t*)Data, Len);
	if (TxLen)*TxLen = Len;
}

void TCP_ProcessPacket(NeteworkBuff * pNeteorkBuff){
	Ethernet_Header * pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEth_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header *)&pIP_Header->Buff;
	Socket * pSocket = 0;
	TCP_Control * pTCP_Control = 0;
	uint8_t Flags = pTCP_Header->Flags;;
	RES res = 0;
	uint32_t RxLen = 0,TxLen = 0;
	/* 首先检查本地端口是否打开 */
	pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	if (pSocket) { pTCP_Control = pSocket->pTCP_Control; }else return;
	/* 记录对方的IP和端口号 */
	if (prvTCP_IpPortRx(pTCP_Control, pTCP_Header, pIP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_FlagsRx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_SN_ACK_Rx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_OptionWinsizeRx(pTCP_Control, pTCP_Header) != RES_TCPPacketPass)return;
	if (prvTCP_DataRx(pTCP_Control, pTCP_Header, pIP_Header,&RxLen) != RES_TCPPacketPass)return;
	if (prvTCP_StateMachine(pTCP_Control, pTCP_Header) == RES_TCPPacketRespond || RxLen){
		uint32_t TCP_PacketLen = prvTCP_GetTCPLen(pTCP_Control);
		/* 预算数据包大小，并提前申请内存 */
		NeteworkBuff * pNeteorkBuff = prvTCP_AllocateEmptyPacket(pTCP_Control, &pTCP_Header);
		prvTCP_DataTx(pTCP_Control, pTCP_Header,&TxLen);
		prvTCP_OptionWinsizeTx(pTCP_Control, pTCP_Header);
		prvTCP_SN_ACK_Tx(pTCP_Control, pTCP_Header,RxLen,TxLen);
		prvTCP_FlagsTx(pTCP_Control, pTCP_Header,TxLen);
		prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP, TCP_PacketLen);
		Ethernet_TransmitPacket(pNeteorkBuff);
	}
}

static NeteworkBuff * prvTCP_AllocateEmptyPacket(TCP_Control * pTCP_Control, TCP_Header ** ppTCP_Header){
	NeteworkBuff * pNeteorkBuff = Network_New(NetworkBuffDirTx, prvTCP_GetPacketSizeToTx(pTCP_Control));
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	(pTCP_Header)->SrcPort = DIY_ntohs(pTCP_Control->LocalPort);
	(pTCP_Header)->DstPort = DIY_ntohs(pTCP_Control->RemotePort);
	(pTCP_Header)->HeaderLen = ((prvTCP_GetOptionSizeToTx(pTCP_Control) + TCP_HEADE_LEN_MIN)/4) << 4;
	if (ppTCP_Header)*ppTCP_Header = pTCP_Header;
	return pNeteorkBuff;
}

static RES prvTCP_IpPortRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header, IP_Header * pIP_Header){
	if (pTCP_Control->RemoteIP.U32 == 0){
		pTCP_Control->RemoteIP.U32 = DIY_ntohl(pIP_Header->SrcIP.U32);
	}
	else{
		if (pTCP_Control->RemoteIP.U32 != DIY_ntohl(pIP_Header->SrcIP.U32))return RES_TCPPacketDeny;
	}
	if (pTCP_Control->RemotePort == 0){
		pTCP_Control->RemotePort = DIY_ntohs(pTCP_Header->SrcPort);
	}
	return RES_TCPPacketPass;
}
/* 接收 标志处理 */
static RES prvTCP_FlagsRx(TCP_Control * pTCP_Control,TCP_Header * pTCP_Header){
	if (pTCP_Header->Flags == TCP_FLAG_FIN | TCP_FLAG_ACK){
		return RES_TCPPacketPass;
	}
	switch (pTCP_Control->State){
		case TCP_STATE_LISTEN:{
			if (pTCP_Header->Flags == TCP_FLAG_SYN)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_SYN_RECV:{
			if (pTCP_Header->Flags == TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_SYN_SENT:{
			if (pTCP_Header->Flags == TCP_FLAG_SYN | TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_ESTABLISHED:{
			/* 建立连接以后必须带着ACK */
			if (pTCP_Header->Flags & TCP_FLAG_ACK)return RES_TCPPacketPass;
			//if (pTCP_Header->Flags | TCP_FLAG_FIN)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_LAST_ACK:{
			if (pTCP_Header->Flags & TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_FIN_WAIT1:{
			if (pTCP_Header->Flags & TCP_FLAG_ACK)return RES_TCPPacketPass;
			break;
		}
		case TCP_STATE_FIN_WAIT2:{
			if (pTCP_Header->Flags & TCP_FLAG_FIN)return RES_TCPPacketPass;
			break;
		}
		default:break;
	}
	return RES_TCPPacketDeny;
}

/* 此处只能比较SN和ACK，而不能改变 */
/* pTCP_Header里面的数据为网络字序，需要转换为主机字序 */
/* 我们是否需要判断对方的SN号？还是只需要记录？ */
static RES prvTCP_SN_ACK_Rx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	/* 我们已将本地SN通知于对方 */
	if (pTCP_Control->LocalSN_Informed){
		/* pTCP_Control->LocalSN是我们期望的ACK号，他在发送时做了加法*/
		/* 我们暂时不考虑SACK，因为SACK比较复杂 */
		if (DIY_ntohl(pTCP_Header->AK) != pTCP_Control->LocalSN)return RES_TCPPacketDeny;
	}
	/* 已知晓对方SN */
	//if (pTCP_Control->RemoteSN_Knowed)
	//{
	//	if(DIY_ntohl(pTCP_Header->SN) == pTCP_Control->RemoteSN)return RES_TCPPacketDeny;
	//}
	//if (!pTCP_Control->RemoteSN_Knowed)
	//{
	pTCP_Control->RemoteSN_Knowed = 1;
	pTCP_Control->RemoteSN = DIY_ntohl(pTCP_Header->SN);
	//}
	return RES_TCPPacketPass;
}

static RES prvTCP_OptionWinsizeRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	uint8_t * Option = 0;
	uint32_t OptionLen = 0;
	prvGetOptionBuffRx(pTCP_Header,&Option,&OptionLen);
	prvTCP_ProcessOptionRx(pTCP_Control, Option, OptionLen);
	prvTCP_ProcessWinsize(pTCP_Control, pTCP_Header);
	return RES_TCPPacketPass;;
}

static RES prvTCP_DataRx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header, IP_Header * pIP_Header,uint32_t * RxLen){
	uint8_t * Data = 0;
	uint32_t DataLen = 0;
	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED){
		prvGetDataBuff_LenRx(pIP_Header, &Data, &DataLen);
		TCPWin_AddRxData(pTCP_Control->pTCP_Win, Data, DataLen, DIY_ntohl(pTCP_Header->SN));
		if (RxLen) {/* 接收到数据，接收窗口已更改 */
			*RxLen = DataLen;pTCP_Control->WIN_Change = 1;
		}
	}
	else{
		if (RxLen)*RxLen = 0;
	}
	return RES_TCPPacketPass;
}

static RES prvTCP_StateMachine(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	RES res = 0;
	TCP_Header TCP_Heade = { 0x00 };
	if (pTCP_Header == NULL)pTCP_Header = &TCP_Heade;

	if (pTCP_Control->State <= TCP_STATE_ESTABLISHED){
		if (pTCP_Header->Flags & TCP_FLAG_FIN){
			pTCP_Control->FIN_Recv = 1;
			if (TCPWin_RxFinished(pTCP_Control->pTCP_Win)){
				pTCP_Control->State = TCP_STATE_CLOSE_WAIT;
				if (TCPWin_TxFinished(pTCP_Control))pTCP_Control->State = TCP_STATE_LAST_ACK;
				return RES_TCPPacketRespond;
			}
		}
	}

	/* 用户希望关闭 */
	if (pTCP_Control->UsrClose){
		if (TCPWin_TxFinished(pTCP_Control->pTCP_Win)){/* 发送已完成 */
			pTCP_Control->FIN_Sent = 1;
			pTCP_Control->State = TCP_STATE_FIN_WAIT1;
			pTCP_Control->UsrClose = 0;
			return RES_TCPPacketRespond;
		}
	}

	if (pTCP_Control->State == TCP_STATE_CLOSED){
		pTCP_Control->State = TCP_STATE_SYN_SENT;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_LISTEN){
		pTCP_Control->State = TCP_STATE_SYN_RECV;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_RECV){
		pTCP_Control->State = TCP_STATE_ESTABLISHED;
		pTCP_Control->HSF = 1;
		//return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_SENT){
		printf("Recv SYN...\r\n");
		prvTCP_Handle_Established(pTCP_Control, DIY_ntohl(pTCP_Header->AK));
		pTCP_Control->State = TCP_STATE_ESTABLISHED;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED){
		res = prvTCP_Handle_Established(pTCP_Control,DIY_ntohl(pTCP_Header->AK));
		return res;
	}
	if (pTCP_Control->State == TCP_STATE_LAST_ACK){
		if (pTCP_Header->Flags & (TCP_FLAG_ACK)){
			pTCP_Control->State = TCP_STATE_CLOSED;
			return RES_TCPPacketPass;
		}
	}

	if (pTCP_Control->State == TCP_STATE_ClOSING){
		if (pTCP_Header->Flags & (TCP_FLAG_ACK)){
			pTCP_Control->State = TCP_STATE_TIME_WAIT;
		}
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT2){
		if (pTCP_Header->Flags & (TCP_FLAG_FIN)){
			pTCP_Control->State = TCP_STATE_TIME_WAIT;
		}
	}
	if (pTCP_Control->State == TCP_STATE_TIME_WAIT){
		//pTCP_Control->State = TCP_STATE_CLOSED;
		return RES_TCPPacketRespond;
	}
	if (pTCP_Control->State == TCP_STATE_CLOSE_WAIT){
		if (TCPWin_TxFinished(pTCP_Control->pTCP_Win)){
			pTCP_Control->State = TCP_STATE_LAST_ACK;
			return RES_TCPPacketRespond;
		}
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT1){
		if (pTCP_Header->Flags == (TCP_FLAG_FIN)){
			pTCP_Control->State = TCP_STATE_ClOSING;
			return RES_TCPPacketRespond;
		}
		if (pTCP_Header->Flags == (TCP_FLAG_FIN | TCP_FLAG_ACK)){
			pTCP_Control->State = TCP_STATE_TIME_WAIT;
			return RES_TCPPacketRespond;
		}
		if (pTCP_Header->Flags == (TCP_FLAG_ACK)){
			pTCP_Control->State = TCP_STATE_FIN_WAIT2;
			return RES_TCPPacketPass;
		}
	}
	return RES_TCPPacketPass;
	/* 如果有数据需要发送，则值为RES_TCPPacketRespond */
}

static RES prvTCP_DataTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header,uint32_t * TxLen){
	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED){
		prvTCP_FillDataToTx(pTCP_Control, pTCP_Header,TxLen);
	}
}

static RES prvTCP_OptionWinsizeTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header){
	prvTCP_FillOptionToTx(pTCP_Control, pTCP_Header);
	prvTCP_FillWinSizeToTx(pTCP_Control, pTCP_Header);
}

/* 此处会改变SN和ACK的数值 */
static RES prvTCP_SN_ACK_Tx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header, uint32_t RxLen, uint32_t TxLen){
	pTCP_Header->SN = DIY_htonl(pTCP_Control->LocalSN);
	if (pTCP_Control->State < TCP_STATE_ESTABLISHED){
		/* 在建立连接之前，增量为 1 */
		pTCP_Control->LocalSN += 1;
		if (pTCP_Control->RemoteSN_Knowed){
			pTCP_Control->RemoteSN += 1;
			pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
		}
	}
	/* 连接已经建立 */
	else{
		/* 暂时先别管保活信号了 */
		pTCP_Control->LocalSN += TxLen;
		pTCP_Control->RemoteSN += RxLen;
		pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
	}
	if (pTCP_Control->State == TCP_STATE_TIME_WAIT){
		pTCP_Control->RemoteSN += 1;
		pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT1){
		pTCP_Control->LocalSN += 1;
		//pTCP_Control->RemoteSN += 1;
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT2){
		pTCP_Control->RemoteSN += 1;
	}
	/* 连接已建立，但是握手没完成，欠对方一个ACK */
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0){
		pTCP_Control->RemoteSN += 1;
		//pTCP_Control->LocalSN += 1;
		pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
	}
	pTCP_Control->LocalSN_Informed = 1;
}

static RES prvTCP_FlagsTx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header,uint32_t TxLen){
	if (pTCP_Control->State == TCP_STATE_SYN_RECV){
		pTCP_Header->Flags |= TCP_FLAG_ACK | TCP_FLAG_SYN;
		return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0){
		pTCP_Control->HSF = 1;
		pTCP_Header->Flags |= TCP_FLAG_ACK;
		return RES_TCPPacketPass;
	}
	if (pTCP_Control->State == TCP_STATE_SYN_SENT){
		pTCP_Header->Flags |= TCP_FLAG_SYN;
	}
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
		if(TxLen)pTCP_Header->Flags |= TCP_FLAG_PSH;
	}
	if (pTCP_Control->State == TCP_STATE_CLOSE_WAIT){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
	}
	if (pTCP_Control->State == TCP_STATE_LAST_ACK){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
		pTCP_Header->Flags |= TCP_FLAG_FIN;
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT1){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
		pTCP_Header->Flags |= TCP_FLAG_FIN;
	}
	if (pTCP_Control->State == TCP_STATE_ClOSING){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
	}
	if (pTCP_Control->State == TCP_STATE_TIME_WAIT){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
	}
	if (pTCP_Control->State == TCP_STATE_FIN_WAIT2){
		pTCP_Header->Flags |= TCP_FLAG_ACK;
	}
}
/* 主动发起连接，由Socket_Connect调用 */
void TCP_Connect(TCP_Control * pTCP_Control){
	pTCP_Control->State = TCP_STATE_CLOSED;
	prvTCP_StateMachine(pTCP_Control,0);
	{
		TCP_Header * pTCP_Header = 0;
		uint32_t TxLen = 0, RxLen = 0;
		uint32_t TCP_PacketLen = prvTCP_GetTCPLen(pTCP_Control);
		/* 预算数据包大小，并提前申请内存 */
		NeteworkBuff * pNeteorkBuff = prvTCP_AllocateEmptyPacket(pTCP_Control, &pTCP_Header);
		prvTCP_DataTx(pTCP_Control, pTCP_Header, &TxLen);
		prvTCP_OptionWinsizeTx(pTCP_Control, pTCP_Header);
		prvTCP_SN_ACK_Tx(pTCP_Control, pTCP_Header, RxLen, TxLen);
		prvTCP_FlagsTx(pTCP_Control, pTCP_Header, TxLen);
		prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP, TCP_PacketLen);
		Ethernet_TransmitPacket(pNeteorkBuff);
	}
	printf("Send SYN...\r\n");
}

void TCP_Close(TCP_Control * pTCP_Control){
	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED){
		pTCP_Control->UsrClose = 1;
		prvTCP_StateMachine(pTCP_Control, 0);
		{
			TCP_Header * pTCP_Header = 0;
			uint32_t TxLen = 0, RxLen = 0;
			uint32_t TCP_PacketLen = prvTCP_GetTCPLen(pTCP_Control);
			/* 预算数据包大小，并提前申请内存 */
			NeteworkBuff * pNeteorkBuff = prvTCP_AllocateEmptyPacket(pTCP_Control, &pTCP_Header);
			prvTCP_DataTx(pTCP_Control, pTCP_Header, &TxLen);
			prvTCP_OptionWinsizeTx(pTCP_Control, pTCP_Header);
			prvTCP_SN_ACK_Tx(pTCP_Control, pTCP_Header, RxLen, TxLen);
			prvTCP_FlagsTx(pTCP_Control, pTCP_Header, TxLen);
			prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP, TCP_PacketLen);
			Ethernet_TransmitPacket(pNeteorkBuff);
		}
	}
}
/* 发送数据，返回已经发送的数据量，发送之前要确保连接已经建立 */
/*2017--11--24--10--27--31(ZJYC):  今日から日本語を使う  */
uint32_t TCP_SendData(TCP_Control * pTCP_Control,uint8_t * Data,uint32_t DataLen){
	TCP_Header * pTCP_Header = 0;
	uint32_t TxLen = 0, RxLen = 0,Send = 0;
	uint32_t TCP_PacketLen = 0;
	/* 计算对方的接受能力 */
	pTCP_Control->pTCP_Win->TxCapacity = pTCP_Control->RemoteWinSize * (1 << pTCP_Control->RemoteWinScale);
	Send = TCPWin_AddTxData(pTCP_Control->pTCP_Win,Data,DataLen);
	TCP_PacketLen = prvTCP_GetTCPLen(pTCP_Control);
	/* 预算数据包大小，并提前申请内存 */
	NeteworkBuff * pNeteorkBuff = prvTCP_AllocateEmptyPacket(pTCP_Control, &pTCP_Header);
	prvTCP_DataTx(pTCP_Control, pTCP_Header, &TxLen);
	prvTCP_OptionWinsizeTx(pTCP_Control, pTCP_Header);
	/* 本着收到数据立即确认的原则，不应存在未确认对方数据的情况 だから ここに RxLen=0*/
	prvTCP_SN_ACK_Tx(pTCP_Control, pTCP_Header, RxLen, TxLen);
	prvTCP_FlagsTx(pTCP_Control, pTCP_Header, TxLen);
	prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP, TCP_PacketLen);
	Ethernet_TransmitPacket(pNeteorkBuff);
	return Send;
}

uint8_t DebugBuffXX_1[] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3a,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x66, 0xbe, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00,
	0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02,
	0x00, 0x64, 0x65, 0x57, 0x00, 0x00, 0x02, 0x04,
	0x00, 0x0a,
};

uint8_t DebugBuffXX_3[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3a,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x66, 0xbe, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00,
	0x00, 0x65, 0x00, 0x00, 0x00, 0x0b, 0x60, 0x10,
	0x00, 0x64, 0x65, 0x3d, 0x00, 0x00, 0x02, 0x04,
	0x00, 0x0a,
};

uint8_t DebugBuffXX_4[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3d,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x66, 0xbb, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00,
	0x00, 0x65, 0x00, 0x00, 0x00, 0x0b, 0x50, 0x18,
	0x00, 0x64, 0x66, 0x73, 0x00, 0x00, 0x41, 0x42,
	0x43, 0x44, 0x45, 0x46, 0x47,
};

uint8_t DebugBuffXX_6[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3f,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x31, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x66, 0xb9, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00,
	0x00, 0x6c, 0x00, 0x00, 0x00, 0x0b, 0x50, 0x18,
	0x00, 0x64, 0x6d, 0x62, 0x00, 0x00, 0x31, 0x32,
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
};

uint8_t DebugBuffXX_8[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3a,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x66, 0xbe, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00,
	0x00, 0x75, 0x00, 0x00, 0x00, 0x0b, 0x50, 0x18,
	0x00, 0x64, 0xc3, 0xa5, 0x00, 0x00, 0x5a, 0x4a,
	0x59, 0x43,
};

uint8_t DebugBuffXX_11[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x3a,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x2c,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xbe,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x64,0x00,0x00,0x00,0x0b,0x60,0x12,
	0x00,0x64,0x65,0x3c,0x00,0x00,0x02,0x04,
	0x00,0x0a,
};

uint8_t DebugBuffXX_14[] = 
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x36,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xc2,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x65,0x00,0x00,0x00,0x0f,0x50,0x10,
	0x00,0x64,0x77,0x4b,0x00,0x00,
};

uint8_t DebugBuffXX_16[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x36,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xc2,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x65,0x00,0x00,0x00,0x15,0x50,0x10,
	0x00,0x64,0x77,0x45,0x00,0x00,
};

uint8_t DebugBuffXX_18[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x36,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xc2,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x65,0x00,0x00,0x00,0x1b,0x50,0x10,
	0x00,0x64,0x77,0x3f,0x00,0x00,
};
uint8_t DebugBuffXX_19[] =
{ 
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x36,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xc2,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x65,0x00,0x00,0x00,0x1c,0x50,0x10,
	0x00,0x64,0x77,0x3e,0x00,0x00,
};
uint8_t DebugBuffXX_20[] =
{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x36,
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0a,0x0b,0x0c,0x08,0x00,0x45,0x00,
	0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,
	0x66,0xc2,0x07,0x08,0x09,0x00,0x01,0x02,
	0x03,0x04,0x1e,0xd2,0x04,0xd2,0x00,0x00,
	0x00,0x65,0x00,0x00,0x00,0x1c,0x50,0x11,
	0x00,0x64,0x77,0x3d,0x00,0x00,

};
NeteworkBuff * DebugNeteworkBuff[] = 
{ 
	/* 如下测试被动连接 */
	//(NeteworkBuff*)DebugBuffXX_1,
	//(NeteworkBuff*)DebugBuffXX_3,
	//(NeteworkBuff*)DebugBuffXX_4,
	//(NeteworkBuff*)DebugBuffXX_6,
	//(NeteworkBuff*)DebugBuffXX_8,
	/* 如下测试主动连接 */
	(NeteworkBuff*)DebugBuffXX_11,
};

#include "TCP_Task.h"
/*
void TCP_Test_Rx(void)
{
	uint8_t i = 0;
	ADDR addr = {0};
	addr.LocalPort = 1234;
	Socket * pSocket = prvSocket_New(&addr,IP_Protocol_TCP);
	Socket_Listen(pSocket);
	while (1)
	{
		Ethernet_ProcessPacket(DebugNeteworkBuff[i++]);
		MainLoop();
		if (i >= sizeof(DebugNeteworkBuff) / sizeof(DebugNeteworkBuff[0]))break;
	}
	{
		uint8_t DataRecv[100] = { 0 }, RecvLen = 0;
		Socket_Recv(pSocket, DataRecv, &RecvLen);
		i++;
	}
	i++;
}

void TCP_Test_Tx(void)
{
	ADDR addr = 
	{
		{0,9,8,7},{0,0,0,0},
		{7,8,9,10,11,12},{0,0,0,0,0,0},
		7890,1234,
	};

	uint8_t i = 0;
	uint8_t * Str1 = "QWER";
	uint8_t * Str2 = "ZXCVBN";
	uint8_t * Str3 = "!@#$%^";
	ARP_AddItem(&addr.RemoteIP, &addr.RemoteMAC);
	Socket * pSocket = prvSocket_New(&addr, IP_Protocol_TCP);
	Socket_Config(pSocket, TCP_MSS,15);
	Socket_Config(pSocket, TCP_WIN_SIZE, 50);
	Socket_Config(pSocket, TCP_WIN_SCALE, 0);
	Socket_Config(pSocket, TCP_INIT_SN, 0);
	TCP_Connect(pSocket->pTCP_Control);
	MainLoop();
	while (1)
	{
		Ethernet_ProcessPacket(DebugNeteworkBuff[i++]);
		MainLoop();
		if (i >= sizeof(DebugNeteworkBuff) / sizeof(DebugNeteworkBuff[0]))break;
	}
	Socket_Send(pSocket, Str1,strlen(Str1));
	MainLoop();
	Ethernet_ProcessPacket((NeteworkBuff*)DebugBuffXX_14);

	Socket_Send(pSocket, Str2, strlen(Str2));
	MainLoop();
	Ethernet_ProcessPacket((NeteworkBuff*)DebugBuffXX_16);

	Socket_Send(pSocket, Str3, strlen(Str3));
	MainLoop();
	Ethernet_ProcessPacket((NeteworkBuff*)DebugBuffXX_18);

	Socket_Close(pSocket);
	MainLoop();

	Ethernet_ProcessPacket((NeteworkBuff*)DebugBuffXX_19);
	Ethernet_ProcessPacket((NeteworkBuff*)DebugBuffXX_20);
	MainLoop();
}
*/










