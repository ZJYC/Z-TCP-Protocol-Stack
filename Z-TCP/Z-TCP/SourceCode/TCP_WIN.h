#ifndef __TCP_WIN_H__
#define __TCP_WIN_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "DataTypeDef.h"

	typedef struct Segment_
	{
		struct Segment_ * Next;	/* 链表 */
		uint32_t Len;			/* 本段数据长度 */
		uint32_t SnStart;		/* 本段SN号 */
		uint8_t Buff;			/* 本段数据 */
	}Segment;

	typedef struct TCP_Win_
	{
		Segment * pSegment_Tx;	/* 发送段链 */
		Segment * pSegment_Rx;	/* 接收段链 */
		Segment * pSegment_Pri;	/* 优先传送段链 */
		Segment * pSegment_Wait;/* 等待应答段链 */

		uint32_t MSS;
		uint32_t Sn;

		uint8_t * TxBuff;
		uint32_t TxBuffLen;
		uint32_t TxCapacity;/* 远程接收能力 */
		uint8_t * RxBuff;
		uint32_t RxCapacity;/* 本地接收缓冲 */
		uint32_t RxBuffLen;
		uint32_t RxStreamBeginSN;/* 一次数据流开始的SN号 */
	}TCP_Win;


#ifdef __cplusplus
}
#endif
#endif
