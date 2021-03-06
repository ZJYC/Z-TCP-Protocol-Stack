
#ifndef __TCP_H__
#define __TCP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Basic.h"
#include "TCP_WIN.h"

#define TCP_FLAG_CWR	(1<<7)
#define TCP_FLAG_ECE	(1<<6)
#define TCP_FLAG_URG	(1<<5)
#define TCP_FLAG_ACK	(1<<4)
#define TCP_FLAG_PSH	(1<<3)
#define TCP_FLAG_RST	(1<<2)
#define TCP_FLAG_SYN	(1<<1)
#define TCP_FLAG_FIN	(1<<0)

#define TCP_HEADE_LEN_MIN	(20)	

#define TCP_GetHeaderLen(x)	(((x) >> 4)*4)

#pragma pack (1)

typedef enum TCP_Option_
{
	TOK_EOL = 0,
	TOK_NOP = 1,
	TOK_MSS = 2,
	TOK_WSOPT = 3,
	TOK_SACK_Per = 4,
	TOK_SACK = 5,
	TOK_TSOPT = 8,
}TCP_Option;

typedef enum TCP_State_
{
	TCP_STATE_CLOSED = 0,
	TCP_STATE_LISTEN,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECV,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_CLOSE_WAIT,	/* 被动  FIN接收 */
	TCP_STATE_LAST_ACK,		/* 被动  FIN发送 */
	TCP_STATE_FIN_WAIT1,	/* 主动  FIN发送 */
	TCP_STATE_ClOSING,		/* 主动  FIN接收 */
	TCP_STATE_FIN_WAIT2,	/* 主动  ACK接收 */
	TCP_STATE_TIME_WAIT,	/* 主动  FIN接收 */
}TCP_State;
typedef struct TCP_Header_
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t SN;
	uint32_t AK;
	uint8_t HeaderLen;
	uint8_t Flags;
	uint16_t WinSize;
	uint16_t CheckSum;
	uint16_t Urgent;
	uint8_t Option;
}TCP_Header;
typedef struct TCP_Control_
{
	TCP_State State;
	uint16_t RemotePort;
	uint16_t LocalPort;
	IP       RemoteIP;
	/* 滑动窗口 */
	uint32_t RemoteMSS;
	uint32_t RemoteWinSize;
	uint8_t  RemoteWinScale;
	uint32_t LocalMSS;
	uint32_t LocalWinSize;
	uint8_t  LocalWinScale;
	uint32_t LocalSN;
	uint32_t RemoteSN;
	/* *** */
	uint32_t FIN_Sent : 1;/* 我们发送了FIN标志 */
	uint32_t FIN_Recv : 1;/* 接收到对方的FIN */
	uint32_t SYN_Sent : 1;/*  */
	uint32_t MSS_Send : 1;/* 已告知对方本地MSS */
	uint32_t WIN_Sent : 1;/* 已告知对方本地窗口 */
	uint32_t WIN_Change : 1;/* 本地窗口发生更改 */
	uint32_t MSS_Change : 1;/* 本地MSS发生更改 */
	uint32_t TSOPT : 1;			/* 时间戳选项 */
	uint32_t RemoteSN_Knowed : 1;/* 已知晓对方的SN */
	uint32_t LocalSN_Informed : 1;/* 已将本地SN通知对方 */
	uint32_t HSF : 1;/* 握手完成 */
	uint32_t UsrClose : 1;/* 用户希望主动关闭 */
	uint32_t RemoteSACK : 1;/* 对方允许SACK */
	uint32_t LocalSACK : 1;/* 本地允许SACK */
	TCP_Win * pTCP_Win;/* TCP窗体 */
}TCP_Control;
#pragma pack ()


#ifdef __cplusplus
}
#endif

#endif
