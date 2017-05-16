
#include "DataTypeDef.h"
#include "TCP_WIN.h"
#include "heap_5.h"
#include "TCP.h"

static Segment * prvTCPWin_NewSegment(uint8_t * Buff, uint32_t Len,uint32_t SnStart)
{
	Segment * pSegment = (Segment*)MM_Ops.Malloc(sizeof(Segment));

	if (pSegment) 
	{
		memset((uint8_t*)pSegment,0x00,sizeof(Segment));
		pSegment->Buff = Buff;
		pSegment->Len = Len;
		pSegment->SnStart = SnStart;
		pSegment->SnEnd = SnStart + Len;
		return pSegment;
	}
	return NULL;
}

static uint32_t prvTCPWin_GetCount(Segment * pSegment)
{
	uint32_t Counter = 0;
	Segment * SegmentTemp = pSegment;
	while (SegmentTemp->Next)
	{
		Counter++;
		SegmentTemp = SegmentTemp->Next;
	}
	return Counter;
}

static void prvTCPWin_DelSegmentFrom(Segment * pSegmentHead, Segment * pSegment)
{
	while (pSegmentHead->Next != pSegment && pSegmentHead->Next)pSegmentHead = pSegmentHead->Next;
	if (pSegmentHead->Next)
	{
		pSegmentHead->Next = pSegment->Next;
		pSegment->Next = 0;
	}
}

static void prvTCPWin_DelSegment(Segment * pSegment)
{
	MM_Ops.Free((uint8_t*)pSegment);
}

static void prvTCPWin_AddSegmentToEnd(Segment * pSegmentHead, Segment * pSegment)
{
	while (pSegmentHead->Next)pSegmentHead = pSegmentHead->Next;
	if (!pSegmentHead->Next)pSegmentHead->Next = pSegment;
}

TCP_Win * TCPWin_NewWindows(uint32_t WinSizeRx, uint32_t WinSizeTx)
{

	TCP_Win * pTCP_Win = (TCP_Win*)MM_Ops.Malloc(sizeof(TCP_Win));
	if (pTCP_Win)
	{
		memset((uint8_t*)pTCP_Win,0x00, sizeof(TCP_Win));
		pTCP_Win->TxBuff = MM_Ops.Malloc(WinSizeTx);
		pTCP_Win->RxBuff = MM_Ops.Malloc(WinSizeRx);
		if (pTCP_Win->TxBuff && pTCP_Win->TxBuff)
		{
			memset(pTCP_Win->TxBuff, 0x00, WinSizeTx);
			memset(pTCP_Win->RxBuff, 0x00, WinSizeRx);

			pTCP_Win->TxCapacity = WinSizeTx;
			pTCP_Win->RxCapacity = WinSizeRx;
			//pTCP_Win->pSegment_Pri = prvTCPWin_NewSegment(0,0,0);
			//pTCP_Win->pSegment_Rx = prvTCPWin_NewSegment(0, 0, 0);
			//->pSegment_Tx = prvTCPWin_NewSegment(0, 0, 0);
			//pTCP_Win->pSegment_Wait = prvTCPWin_NewSegment(0, 0, 0);
		}
	}
	return pTCP_Win;
}

static Segment * prvTCPWin_FindSnEndFromHeader(Segment * pSegment,uint32_t Sn)
{
	while (pSegment->Next)
	{
		if (pSegment->SnEnd == Sn)return pSegment;
		pSegment = pSegment->Next;
	}
	return NULL;
}

static Segment * prvTCPWin_FindSnStartFromHeader(Segment * pSegment, uint32_t Sn)
{
	while (pSegment->Next)
	{
		if (pSegment->SnStart == Sn)return pSegment;
		pSegment = pSegment->Next;
	}
	return NULL;
}

static Segment * prvTCPWin_FindMaxSnStartFromHeader(Segment * pSegment)
{
	uint32_t MaxSn = 0x00;
	Segment * pSegmentMaxSn = 0x00;

	pSegment = pSegment->Next;

	while (pSegment)
	{
		if (pSegment->SnStart > MaxSn)
		{
			MaxSn = pSegment->SnStart;
			pSegmentMaxSn = pSegment;
		}
		pSegment = pSegment->Next;
	}
	return pSegmentMaxSn;
}

static Segment * prvTCPWin_FindMinSnStartFromHeader(Segment * pSegment)
{
	uint32_t MaxSn = 0xffffffff;
	Segment * pSegmentMaxSn = 0x00;

	pSegment = pSegment->Next;

	while (pSegment)
	{
		if (pSegment->SnStart < MaxSn)
		{
			MaxSn = pSegment->SnStart;
			pSegmentMaxSn = pSegment;
		}
		pSegment = pSegment->Next;
	}
	return pSegmentMaxSn;
}

static Segment * prvTCPWin_FindSnLessThanStartFromHeader(Segment * pSegment, uint32_t Sn)
{
	while (pSegment->Next)
	{
		if (pSegment->SnStart <= Sn)return pSegment;
		pSegment = pSegment->Next;
	}
	return NULL;
}

static Segment * prvTCPWin_FindMinSnNotLessThanStartFromHeader(Segment * pSegment, uint32_t Sn)
{
	uint32_t MaxSn = 0xffffffff;
	Segment * pSegmentMaxSn = 0x00;

	pSegment = pSegment->Next;

	while (pSegment)
	{
		if (pSegment->SnStart < MaxSn && pSegment->SnStart > Sn)
		{
			MaxSn = pSegment->SnStart;
			pSegmentMaxSn = pSegment;
		}
		pSegment = pSegment->Next;
	}
	return pSegmentMaxSn;
}

void TCPWin_AckNormal(TCP_Win * pTCP_Win,uint32_t Sn)
{
	Segment * pSegment_Wait = prvTCPWin_FindSnEndFromHeader(pTCP_Win->pSegment_Wait, Sn);
	if (pSegment_Wait)
	{
		prvTCPWin_DelSegmentFrom(pTCP_Win->pSegment_Wait, pSegment_Wait);
		prvTCPWin_DelSegment(pSegment_Wait);
	}
}
/* 添加数据到窗体 */
void TCPWin_AddTxData(TCP_Win * pTCP_Win, uint8_t * Data, uint32_t Len)
{
	uint8_t * Buff = 0;
	Segment * pSegment = 0;
	uint32_t SegmentLen = 0;
	memcpy((uint8_t*)pTCP_Win->TxBuff, (uint8_t*)Data,Len);
	pTCP_Win->TxBuffLen = Len;
	Buff = pTCP_Win->TxBuff;

	while (pTCP_Win->TxBuffLen)
	{
		if (pTCP_Win->TxBuffLen >= pTCP_Win->MSS){SegmentLen = pTCP_Win->MSS;}
		else { SegmentLen = pTCP_Win->TxBuffLen; }
		pTCP_Win->TxBuffLen -= SegmentLen;
		pSegment = prvTCPWin_NewSegment(Buff, SegmentLen, pTCP_Win->Sn);
		prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Tx, pSegment);
	}
}

Segment * TCPWin_GetDataLenFromSegmentHeader(Segment * pSegmentHead,uint8_t ** Data,uint32_t * Len)
{
	if (pSegmentHead->Next)
	{
		if (Data)*Data = pSegmentHead->Next->Buff;
		if (Len)*Len = pSegmentHead->Next->Len;
		return pSegmentHead->Next;
	}
	if (Data)*Data = 0;
	if (Len)*Len = 0;
	return NULL;
}

void TCPWin_GetDataToTx(TCP_Win * pTCP_Win,uint8_t ** Data,uint32_t * Len,uint8_t Peek)
{
	uint32_t SegmentWaitCounter = 0, SegmentWin = pTCP_Win->TxCapacity / pTCP_Win->MSS;
	Segment * pSegment = 0;
	if(pTCP_Win->pSegment_Wait)SegmentWaitCounter = prvTCPWin_GetCount(pTCP_Win->pSegment_Wait);
	else SegmentWaitCounter = 0;
	
	/* 还可继续发送数据 */
	if (SegmentWin > SegmentWaitCounter)
	{
		/* 存在优先组 */
		if (pTCP_Win->pSegment_Pri)
		{
			pSegment = TCPWin_GetDataLenFromSegmentHeader(pTCP_Win->pSegment_Pri,Data,Len);
			/* 从优先组移至等待组 */
			if (!Peek && pSegment)
			{
				prvTCPWin_DelSegmentFrom(pTCP_Win->pSegment_Pri, pSegment);
				prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Wait, pSegment);
			}
		}
		else
		{
			/* 有数据要发送 */
			if (pTCP_Win->pSegment_Tx)
			{
				pSegment = TCPWin_GetDataLenFromSegmentHeader(pTCP_Win->pSegment_Tx, Data, Len);
				/* 从TX组移至等待组 */
				if (!Peek && pSegment)
				{
					prvTCPWin_DelSegmentFrom(pTCP_Win->pSegment_Tx, pSegment);
					prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Wait, pSegment);
				}
			}
			*Len = 0;
		}
	}
}
/* 把接受的数据保存在窗体 */
void TCPWin_AddRxData(TCP_Win * pTCP_Win, uint8_t * RxData, uint32_t RxLen,uint32_t Sn)
{
	Segment * pSegment = 0;

	if (pTCP_Win->RxStreamBeginSN)
	{
		/* 数据流进行中 */
		uint8_t * StorageLocate = (uint8_t *)(pTCP_Win->RxBuff + (Sn - pTCP_Win->RxStreamBeginSN));
		memcpy(StorageLocate, RxData, RxLen);
		pSegment = prvTCPWin_NewSegment(StorageLocate, RxLen, Sn);
		prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Rx, pSegment);
		/* 记录接受数据长度 */
		pTCP_Win->RxBuffLen = RxLen;
	}
	else
	{
		/* 还没有数据流 */
		pTCP_Win->RxStreamBeginSN = Sn;
		/* 复制数据到缓冲区 */
		memcpy(pTCP_Win->RxBuff,RxData,RxLen);
		/* 创建控制块 */
		pSegment = prvTCPWin_NewSegment(pTCP_Win->RxBuff, RxLen, Sn);
		prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Rx,pSegment);
		/* 记录接受数据长度 */
		pTCP_Win->RxBuffLen = RxLen;
	}
}

void TCPWin_RxHasHole(TCP_Win * pTCP_Win,uint32_t **SACK,uint32_t *SACKLen)
{
	Segment * pSegmentHeader = pTCP_Win->pSegment_Rx;
	Segment * pSegmentFirst = pSegmentHeader->Next;
	Segment * pSegmentTemp = 0;
	Segment * MaxSnSegment = prvTCPWin_FindMaxSnStartFromHeader(pSegmentHeader);
	Segment * MinSnSegment = prvTCPWin_FindMinSnStartFromHeader(pSegmentHeader);
	uint32_t SackIndex = 0, MaxSn = MaxSnSegment->SnStart, MinSn = MinSnSegment->SnStart, TempSn = MinSn;

	if (pSegmentFirst)
	{
		pSegmentTemp = prvTCPWin_FindSnStartFromHeader(pSegmentHeader, TempSn);
		if (pSegmentTemp)
		{
			TempSn = pSegmentTemp->SnEnd;
			if (SackIndex % 2 == 1 && SACK)*SACK[SackIndex++] = TempSn;
		}
		else
		{
			if (SackIndex % 2 == 0 && SACK)*SACK[SackIndex++] = TempSn;
			pSegmentTemp = prvTCPWin_FindMinSnNotLessThanStartFromHeader(pSegmentHeader, TempSn);
			TempSn = pSegmentTemp->SnStart;
		}
	}
	if (SACKLen)*SACKLen = SackIndex;
}

void TCPWin_GiveUsrRxData(TCP_Win * pTCP_Win,uint8_t ** Data,uint32_t * DataLen)
{
	uint32_t SACK[100] = { 0 };
	Segment * pSegmentHeader = pTCP_Win->pSegment_Rx;
	Segment * MinSnSegment = prvTCPWin_FindMinSnStartFromHeader(pSegmentHeader);
	uint32_t MinSn = MinSnSegment->SnStart;

	TCPWin_RxHasHole(pTCP_Win, &SACK,0);
	
	if (SACK[0] > MinSn)
	{
		memcpy(*Data, MinSnSegment->Buff, (SACK[0] - MinSn));
		*DataLen = SACK[0] - MinSn;
	}

}



