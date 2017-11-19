
#include "Basic.h"
#include "IP.h"
#include "TCP.h"
#include "UDP.h"
#include "ICMP.h"
#include "Ethernet.h"

/*2017--05--15--15--35--08(ZJYC): 着手构建CRC校验树   */

void Delay(uint32_t Len) {
	uint32_t i = 0;
	while (Len--) {
		i = 100000;
		while (i--);
	}
}

/* 必须确保为网络字序，内部会自行转换为主机字序 */
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
/* 必须确保为网络字序，内部会自行转换为主机字序 */
static uint16_t prvTCP_ChecksumCalculate(IP_Header * pIP_Header)
{
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;

	CheckSum = DIY_ntohs((pTCP_Header)->CheckSum);
	(pTCP_Header)->CheckSum = 0;
	/* 只能通过IP总长度减去IP头来确定TCP包长度 */
	PayloadLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen;	/* 网络字序转换为主机字序 */
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_TCP << 16 | PayloadLen;			/* 主机字序 */
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);					/* 转换为网络字序 */
	CheckTemp = prv_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pTCP_Header, PayloadLen);
	return CheckTemp;
}
/* 必须确保为网络字序，内部会自行转换为主机字序 */
static uint16_t prvUDP_ChecksumCalculate(IP_Header * pIP_Header)
{
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;
	pUDP_Header->CheckSum = 0;
	/* pUDP_Header->DataLen包含UDP头部和数据 */
	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);			/* 网络字序转换为主机字序 */
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;	/* 主机字序 */
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);			/* 转换为网络字序 */
	CheckTemp = prv_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pUDP_Header, PayloadLen);
	return CheckTemp;
}
/* 必须确保为网络字序，内部会自行转换为主机字序 */
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

static uint16_t prvICMP_GetCheckSum(IP_Header * pIP_Header) {
	ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;
	uint32_t PayloadLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen;
	uint8_t * Buff = &pICMP_Header->Type;
	uint16_t Checksum = 0;
	pICMP_Header->Checksum = 0x00;

	Checksum = prv_GetCheckSum(0,0, Buff, PayloadLen);

	return Checksum;
}

/* 校验IP层及以上，目前只有TCP/UDP/ICMP */
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
		if (pIP_Header->Protocol == IP_Protocol_ICMP) {
			ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;
			Temp = DIY_htons(pICMP_Header->Checksum);
			if (Temp == prvICMP_GetCheckSum(pIP_Header))return RES_True;
		}
	}
	return RES_False;
}
/* 填充IP层及以上的校验和 */
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
	if (pIP_Header->Protocol == IP_Protocol_ICMP) {
		ICMP_Header * pICMP_Header = (ICMP_Header*)&pIP_Header->Buff;
		Temp = prvICMP_GetCheckSum(pIP_Header);
		pICMP_Header->Checksum = DIY_htons(Temp);
	}
	Temp = prvIP_GetCheckSum(pIP_Header);
	pIP_Header->CheckSum = DIY_htons(Temp);
}
/* input '192.168.0.1' -> {192,168,0,1} */
IP IP_Str2Int(const char * Str)
{
	uint8_t i = 0, temp[3] = {0},t = 0,m = 0;
	uint32_t ip = 0; IP res = {0};

	uint8_t SepChar = '.';

	while (1)
	{
		if ((Str[i] >= '0') && (Str[i] <= '9')) { temp[t++] = Str[i] - 0x30; }
		if ((Str[i] == SepChar) || (Str[i] == 0)) {
			if (t == 3) { ip |= (temp[2] + temp[1] * 10 + temp[0] * 100) << m * 8; }
			if (t == 2) { ip |= (temp[0] * 10 + temp[1]) << m * 8; }
			if (t == 1) { ip |= (temp[0]) << m * 8; }
			m++; t = 0;
		}
		if (Str[i] == 0)break;
		i++;
	}
	res.U32 = ip;
	return res;
}

uint8_t prvUppercase(uint8_t input)
{
	if ((input >= 97) && (input <= 122)) {
		return input - 'a' + 'A';
	}
	return input;
}

uint8_t prvLowercase(uint8_t input)
{
	if ((input >= 65) && (input <= 90)) {
		return input - 'A' + 'a';
	}
	return input;
}

uint8_t prvIsMacChar(uint8_t input)
{
	return ((input >= 65) && (input <= 90)) || \
		((input >= 97) && (input <= 122)) || \
		((input >= 48) && (input <= 57));
}

uint8_t prvGetNum(uint8_t input)
{
	if ((input >= 48) && (input <= 57)) {
		return input - 48;
	}
	if ((input >= 65) && (input <= 90)) {
		return input - 'A' + 0x0A;
	}
	if ((input >= 97) && (input <= 122)) {
		return input - 'a' + 0x0A;
	}
	return input;
}

/* input 'AA:BB:CC:DD:EE:FF' ->{0xaa,0xbb,0xcc,0xdd,0xee,0xff} */
MAC MAC_Str2Int(const char * Str)
{
	MAC res = { 0 };
	uint8_t i = 0, temp[2] = { 0 },t = 0,m = 0;

	uint8_t SepChar = ':';

	while (1)
	{
		if (prvIsMacChar(Str[i])) { temp[t++] = prvGetNum(Str[i]); }
		if ((Str[i] == SepChar) || (Str[i] == 0)) {
			if (t == 2) { t = temp[0] << 4 | temp[1]; }
			if (t == 1) { t = temp[0]; }
			res.Byte[m] = t;
			m++; t = 0;
		}
		if (Str[i] == 0)break;
		i++;
	}
	return res;
}

void PrintfMAC(MAC * mac)
{
	uint8_t i = 0;
	for (i = 0; i < 6; i++)
	{
		printf("%02X", mac->Byte[i]);
		if (i != 5)printf(":");
	}
}

void PrintfIP(IP * ip)
{
	int8_t i = 0;
	for (i = 3; i >= 0; i--)
	{
		printf("%d", ip->U8[i]);
		if (i)printf(".");
	}
}














