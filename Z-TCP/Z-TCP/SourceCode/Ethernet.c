
#include "Ethernet.h"
#include "IP.h"
#include "ARP.h"
#include "Basic.h"
#include "TCP_Task.h"

MAC LocalMAC = { 0 };
MAC BrocastMAC = {0};
/* 在使用任何以太网功能之前调用 */
void Ethernet_Init(void) {
	LocalMAC = MAC_Str2Int("00:0c:29:59:fd:21");
	BrocastMAC = MAC_Str2Int("FF:FF:FF:FF:FF:FF");
}
/* 硬件发送数据 */
static void PHY_Ethernet_DriverSend(uint8_t * Data,uint32_t Len)
{
	uint16_t i = 0;
	printf("\r\n");
	for (i = 0; i < Len; i++)
	{
		if (i % 8 == 0)printf("\r\n");
		printf("%02X ", Data[i]);
	}
	printf("\r\n");
}
/* 硬件接收数据 */
static void PHY_Ethernet_DriverRecv(uint8_t * Data,uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirRx, Len);
	memcpy((uint8_t*)&pNeteworkBuff->Buff, Data, Len);
	pNeteworkBuff->Ready = True;
	tcb.Ethernet_Rx_Packet += 1;
}
/* 通过文件想协议栈输入模拟数据 */
void Ethernet_RecvNetworkBuff(uint8_t * Data, uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirRx, Len);
	memcpy(&pNeteworkBuff->Buff, Data, Len);
	Ethernet_ReceivePacket(pNeteworkBuff);
}
/* 调用硬件接口来发送网络缓存 */
void Ethernet_SendNetworkBuff(NeteworkBuff * pNeteorkBuff)
{
	if (pNeteorkBuff == NULL)return;
	PHY_Ethernet_DriverSend((uint8_t*)&pNeteorkBuff->Buff, pNeteorkBuff->BuffLen);
}
/* 将网络缓存标记为可发送状态 */
void Ethernet_TransmitPacket(NeteworkBuff * pNeteorkBuff)
{
	/* Has already add to header TX,But the ready flag is not true,Now set it to true */
	if (pNeteorkBuff == NULL)return;
	pNeteorkBuff->Ready = True;
	tcb.Ethernet_Tx_Packet += 1;
}
void Ethernet_ReceivePacket(NeteworkBuff * pNeteorkBuff)
{
	if (pNeteorkBuff == NULL)return;
	pNeteorkBuff->Ready = True;
	tcb.Ethernet_Rx_Packet += 1;
}
/* 处理以太网数据包 */
void Ethernet_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = 0x00; 
	RES res = RES_True;
	if (pNeteorkBuff == NULL)return RES_False;
	pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;

	/* 硬件自动计算CRC */
	if (prvEthernetFilter(pNeteorkBuff) == RES_EthernetPacketPass)
	{
		if (pEth_Header->Type == DIY_ntohs(EthernetType_ARP))
		{
			ARP_ProcessPacket(pNeteorkBuff);
		}
		if (pEth_Header->Type == DIY_ntohs(EthernetType_IP))
		{
			IP_ProcessPacket(pNeteorkBuff);
		}
	}
}
/* 以太网层过滤 */
static RES prvEthernetFilter(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	/* 目标是本机MAC？？ */
	if (memcmp((uint8_t*)&pEth_Header->DstMAC,(uint8_t*)&LocalMAC,sizeof(MAC)) == 0)
	{
		return RES_EthernetPacketPass;
	}
	else/* 广播MAC？？ */
	if (memcmp((uint8_t*)&pEth_Header->DstMAC, (uint8_t*)&BrocastMAC, sizeof(MAC)) == 0)
	{
		return RES_EthernetPacketPass;
	}
	else
	{
		return RES_EthernetPacketDeny;
	}
	return RES_EthernetPacketDeny;
}
/* 填充以太网包 */
void Ethernet_FillPacket(NeteworkBuff * pNeteorkBuff, uint32_t Protocol, IP * RemoteIP)
{
	MAC DstMAC = { 0x00 };
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	/* 尝试获取本IP对应的MAC地址，否则发送ARP请求 */
	ARP_GetMAC_ByIP(RemoteIP, &DstMAC, NULL,1);
	pEthernet_Header->SrcMAC = LocalMAC;
	pEthernet_Header->DstMAC = DstMAC;
	pEthernet_Header->Type = DIY_htons(Protocol);
}










