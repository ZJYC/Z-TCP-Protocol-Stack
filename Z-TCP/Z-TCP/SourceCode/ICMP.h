#ifndef __ICMP_H__
#define __ICMP_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Basic.h"

#define ECHO_DATA_LEN	(16)
#define ECHO_DATA		("ZJYC-")

	typedef enum ICMP_Type_ {
		//Destination Unreachable Message
		DUM_Net = 0x0300,//net unreachable
		DUM_Host = 0x0301,//host unreachable
		DUM_Poto = 0x0302,//protocol unreachable
		DUM_Port = 0x0303,//port unreachable
		DUM_Df = 0x0304,//fragmentation needed and DF set
		DUM_Route = 0x0305,//source route failed
		//Time Exceeded Message
		TEM_TTL = 0x1100,//time to live exceeded in transit
		TEM_FRT = 0x1101,//fragment reassembly time exceeded
		//Parameter Problem Message
		PPM_Point = 0x1200,//pointer indicates the error
		//Source Quench Message
		SQM_XX = 0x0400,
		//Redirect Message
		RM_Net = 0x0500,//Redirect datagrams for the Network
		RM_Host = 0x0501,//Redirect datagrams for the Host
		RM_Ser = 0x0502,//Redirect datagrams for the Type of Service and Network
		RM_SerHost = 0x0503,//Redirect datagrams for the Type of Service and Host
		//Echo or Echo Reply Message
		ECHO_Send = 0x0800,//for echo message
		ECHO_Reply = 0x0000,//
		//Timestamp or Timestamp Reply Message
		TS_Send = 0x1300,//for timestamp message
		TS_Reply = 0x1400,//
		//Information Request or Information Reply Message
		Inf_Req = 0x1500,//for information request message
		Inf_Reply = 0x1600, //for information reply message
		//address mask req or send
		AM_Req = 0x1700,//req
		AM_Reply = 0x1800,//reply
	}ICMP_Type;

#pragma pack (1)
	typedef struct ICMP_Header_ {//±¨ÎÄÍ·
		uint8_t Type;
		uint8_t Code;
		uint16_t Checksum;
		uint8_t Type2[4];
		uint8_t Buff;
	}ICMP_Header;

	typedef struct _ICMP_CB_ {
		uint16_t ECHO_LastID;
		uint16_t ECHO_LastSeq;
		uint16_t ECHO_LastDataLen;
	}ICMP_CB_;

#pragma pack ()

	void ICMP_Test();
	void ICMP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
	RES ICMP_Ping(IP ip);

#ifdef __cplusplus
}
#endif
#endif