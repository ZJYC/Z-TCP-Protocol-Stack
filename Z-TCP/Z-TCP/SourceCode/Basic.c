
#include "Basic.h"
#include "IP.h"
#include "TCP.h"
#include "UDP.h"
#include "Ethernet.h"

/*2017--05--15--15--35--08(ZJYC): ���ֹ���CRCУ����   */

/* ����ȷ��Ϊ���������ڲ�������ת��Ϊ�������� */
static uint16_t prv_GetCheckSum(uint16_t * PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes)
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
/* ����ȷ��Ϊ���������ڲ�������ת��Ϊ�������� */
static uint16_t prvTCP_ChecksumCalculate(IP_Header * pIP_Header)
{
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;

	CheckSum = DIY_ntohs((pTCP_Header)->CheckSum);
	(pTCP_Header)->CheckSum = 0;
	/* ֻ��ͨ��IP�ܳ��ȼ�ȥIPͷ��ȷ��TCP������ */
	PayloadLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen;	/* ��������ת��Ϊ�������� */
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_TCP << 16 | PayloadLen;			/* �������� */
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);					/* ת��Ϊ�������� */
	CheckTemp = prv_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pTCP_Header, PayloadLen);
	return CheckTemp;
}
/* ����ȷ��Ϊ���������ڲ�������ת��Ϊ�������� */
static uint16_t prvUDP_ChecksumCalculate(IP_Header * pIP_Header)
{
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;
	pUDP_Header->CheckSum = 0;
	/* pUDP_Header->DataLen����UDPͷ�������� */
	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);			/* ��������ת��Ϊ�������� */
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;	/* �������� */
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);			/* ת��Ϊ�������� */
	CheckTemp = prv_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pUDP_Header, PayloadLen);
	return CheckTemp;
}
/* ����ȷ��Ϊ���������ڲ�������ת��Ϊ�������� */
static uint16_t prvIP_GetCheckSum(IP_Header * pIP_Header)
{
	uint16_t HeaderLen = 0, TempDebug = 0;
	uint16_t * pHeader = (uint16_t *)pIP_Header;
	uint32_t cksum = 0;
	HeaderLen = IP_GetHeaderLen(pIP_Header->VL);
	pIP_Header->CheckSum = 0;

	while (HeaderLen > 1)
	{
		TempDebug = *pHeader++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		HeaderLen -= 2;
	}
	if (HeaderLen)
	{
		TempDebug = (*(uint8_t *)pHeader); TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	cksum = (uint16_t)(~cksum);

	return cksum;
}
/* У��IP�㼰���ϣ�Ŀǰֻ��TCP/UDP */
RES IsCheckSumRight(IP_Header * pIP_Header)
{
	uint16_t Temp = 0;
	Temp = DIY_htons(pIP_Header->CheckSum);
	if (Temp == prvIP_GetCheckSum(pIP_Header))
	{
		if (pIP_Header->Protocol == IP_Protocol_TCP)
		{
			TCP_Header * pTCP_Header = (TCP_Header *)&pIP_Header->Buff;
			Temp = DIY_htons(pTCP_Header->CheckSum);
			if (Temp == prvTCP_ChecksumCalculate(pIP_Header))return RES_True;
		}
		if (pIP_Header->Protocol == IP_Protocol_UDP)
		{
			UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
			Temp = DIY_htons(pUDP_Header->CheckSum);
			if (Temp == prvUDP_ChecksumCalculate(pIP_Header))return RES_True;
		}
	}
	return RES_False;
}
/* ���IP�㼰���ϵ�У��� */
void FillCheckSum(IP_Header * pIP_Header)
{
	uint16_t Temp = 0;

	if (pIP_Header->Protocol == IP_Protocol_TCP)
	{
		TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
		Temp = prvTCP_ChecksumCalculate(pIP_Header);
		pTCP_Header->CheckSum = DIY_htons(Temp);
	}
	if (pIP_Header->Protocol == IP_Protocol_UDP)
	{
		UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
		Temp = prvUDP_ChecksumCalculate(pIP_Header); DIY_htons(pUDP_Header->CheckSum);
		pUDP_Header->CheckSum = DIY_htons(Temp);
	}
	Temp = prvIP_GetCheckSum(pIP_Header);
	pIP_Header->CheckSum = DIY_htons(Temp);
}














