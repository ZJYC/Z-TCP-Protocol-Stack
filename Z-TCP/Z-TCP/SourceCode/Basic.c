
#include "Basic.h"
#include "IP.h"
#include "TCP.h"
#include "UDP.h"

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
	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	HeaderLen = pIP_Header->U_VL.S_VL_ALL.HeaderLen * 4;
	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
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


















