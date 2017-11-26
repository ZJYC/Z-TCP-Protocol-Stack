#ifndef __TCP_WIN_H__
#define __TCP_WIN_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "DataTypeDef.h"

	typedef struct Segment_
	{
		struct Segment_ * Next;	/* ���� */
		uint32_t Len;			/* �������ݳ��� */
		uint32_t SnStart;		/* ����SN�� */
		uint8_t Buff;			/* �������� */
	}Segment;

	typedef struct TCP_Win_
	{
		Segment * pSegment_Tx;	/* ���Ͷ��� */
		Segment * pSegment_Rx;	/* ���ն��� */
		Segment * pSegment_Pri;	/* ���ȴ��Ͷ��� */
		Segment * pSegment_Wait;/* �ȴ�Ӧ����� */

		uint32_t MSS;
		uint32_t Sn;

		uint8_t * TxBuff;
		uint32_t TxBuffLen;
		uint32_t TxCapacity;/* Զ�̽������� */
		uint8_t * RxBuff;
		uint32_t RxCapacity;/* ���ؽ��ջ��� */
		uint32_t RxBuffLen;
		uint32_t RxStreamBeginSN;/* һ����������ʼ��SN�� */
	}TCP_Win;


#ifdef __cplusplus
}
#endif
#endif
