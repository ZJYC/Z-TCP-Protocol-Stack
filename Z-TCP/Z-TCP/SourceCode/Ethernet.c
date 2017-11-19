
#include "Ethernet.h"
#include "IP.h"
#include "ARP.h"
#include "Basic.h"
#include "TCP_Task.h"

MAC LocalMAC = { 0 };
MAC BrocastMAC = {0};
/* ��ʹ���κ���̫������֮ǰ���� */
void Ethernet_Init(void) {
	LocalMAC = MAC_Str2Int("00:0c:29:59:fd:21");
	BrocastMAC = MAC_Str2Int("FF:FF:FF:FF:FF:FF");
}
/* Ӳ���������� */
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
/* Ӳ���������� */
static void PHY_Ethernet_DriverRecv(uint8_t * Data,uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirRx, Len);
	memcpy((uint8_t*)&pNeteworkBuff->Buff, Data, Len);
	pNeteworkBuff->Ready = True;
	tcb.Ethernet_Rx_Packet += 1;
}
/* ͨ���ļ���Э��ջ����ģ������ */
void Ethernet_RecvNetworkBuff(uint8_t * Data, uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirRx, Len);
	memcpy(&pNeteworkBuff->Buff, Data, Len);
	Ethernet_ReceivePacket(pNeteworkBuff);
}
/* ����Ӳ���ӿ����������绺�� */
void Ethernet_SendNetworkBuff(NeteworkBuff * pNeteorkBuff)
{
	if (pNeteorkBuff == NULL)return;
	PHY_Ethernet_DriverSend((uint8_t*)&pNeteorkBuff->Buff, pNeteorkBuff->BuffLen);
}
/* �����绺����Ϊ�ɷ���״̬ */
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
/* ������̫�����ݰ� */
void Ethernet_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = 0x00; 
	RES res = RES_True;
	if (pNeteorkBuff == NULL)return RES_False;
	pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;

	/* Ӳ���Զ�����CRC */
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
/* ��̫������� */
static RES prvEthernetFilter(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	/* Ŀ���Ǳ���MAC���� */
	if (memcmp((uint8_t*)&pEth_Header->DstMAC,(uint8_t*)&LocalMAC,sizeof(MAC)) == 0)
	{
		return RES_EthernetPacketPass;
	}
	else/* �㲥MAC���� */
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
/* �����̫���� */
void Ethernet_FillPacket(NeteworkBuff * pNeteorkBuff, uint32_t Protocol, IP * RemoteIP)
{
	MAC DstMAC = { 0x00 };
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	/* ���Ի�ȡ��IP��Ӧ��MAC��ַ��������ARP���� */
	ARP_GetMAC_ByIP(RemoteIP, &DstMAC, NULL,1);
	pEthernet_Header->SrcMAC = LocalMAC;
	pEthernet_Header->DstMAC = DstMAC;
	pEthernet_Header->Type = DIY_htons(Protocol);
}










