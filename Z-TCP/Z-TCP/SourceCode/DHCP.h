#ifndef __DHCP_H__
#define __DHCP_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <windows.h>

#include "DataTypeDef.h"
#include "Basic.h"

#define DHCP_SERVER_PORT	(67)
#define DHCP_CLIENT_PORT	(68)
#define ConstOptionHead	99,130,83,99
#define oplen_4n	'*'
#define oplen_8n	'&'
#define oplen_n		'#'

#define BOOTREQUEST	(1)
#define BOOTREPLY	(2)

#define DHCP_INIT	(1)
#define DHCP_SELECTING	(2)
#define DHCP_CHECKIP	(8)/* 需要检查服务器提供的IP是否被其他人使用 */
#define DHCP_REQUES	(3)
#define DHCP_PREBOUND (7)
#define DHCP_BOUND	(4)
#define DHCP_RENEW	(5)
#define DHCP_REBIND	(6)

	typedef enum ValueMessageType_ {
		DHCPDISCOVER = 1,
		DHCPOFFER = 2,
		DHCPREQUEST = 3,
		DHCPDECLINE = 4,
		DHCPACK = 5,
		DHCPNAK = 6,
		DHCPRELEASE = 7
	}ValueMessageType;

	typedef enum op_name_ {
		pad = 0,
		subnet_mask = 1,
		router = 3,
		dns = 6,
		log = 7,
		hostname = 12,
		ifmtu = 26,
		broadcast = 28,
		staticrouter = 33,
		arptimeout = 35,
		ntp = 42,
		request_ip = 50,
		leasetime = 51,
		option_over = 52,
		messagetype = 53,
		serveid = 54,
		para_list = 55,
		max_message_size = 57,
		client_id = 61,
		end = 255
	}opname;
#pragma pack (1)
	typedef struct DHCP_Header_ {
		uint8_t		op;/* 1=bootrequest 2=bootreply */
		uint8_t		htype;/* 1 */
		uint8_t		hlen;/* 6 */
		uint8_t		hops;/* used by relay agent */
		uint32_t	xid;/* Transaction ID */
		uint16_t	secs;/*  */
		uint16_t	flags;/* broadcast flag + ,,, */
		IP			ciaddr;/* Client IP address */
		IP			yiaddr;/* ’your’ (client) IP address */
		IP			siaddr;/*  */
		IP			giaddr;/*  */
		uint8_t		chaddr[16];
		uint8_t		sname[64];
		uint8_t		file[128];
		uint8_t		options;
	}DHCP_Header;
#pragma pack ()
	typedef struct DHCP_CB__ {
		uint8_t CurState;/* D O R A */
		uint32_t Xid;
		uint8_t chaddr[16];
		IP		ciaddr;
		IP		siaddr;
		uint32_t Lease;
		uint8_t MessageType;
		uint32_t ServeID;
		uint8_t * ClientId;
	}DHCP_CB_;

	void DHCP_Init();
	DWORD  WINAPI DHCP_MainTask(LPVOID lpParam);
	void DHCP_Test();
#define DHCP_Delay		Sleep


#ifdef __cplusplus
}
#endif
#endif
