
#include "DataTypeDef.h"
#include "TCP_WIN.h"
#include "heap_5.h"
#include "TCP.h"
/* ����һ�µĶΣ��������ݺ�SN������ */
static Segment * prvTCPWin_NewSegment(uint8_t * Buff, uint32_t Len,uint32_t SnStart)
{
	uint32_t WholeLen = sizeof(Segment) + Len;
	Segment * pSegment = (Segment*)MM_Ops.Malloc(WholeLen);

	if (pSegment) 
	{
		memset((uint8_t*)pSegment,0x00, WholeLen);
		memcpy(&pSegment->Buff, Buff,Len);
		pSegment->Len = Len;
		pSegment->SnStart = SnStart;
		return pSegment;
	}
	return NULL;
}
/* ���������� */
static uint32_t prvTCPWin_GetCountFromHeader(Segment ** pSegmentHeader)
{
	uint32_t Counter = 0;
	Segment * SegmentTemp = *pSegmentHeader;

	while (1)
	{
		if (SegmentTemp)
		{
			Counter++;
			SegmentTemp = SegmentTemp->Next;
		}
		else break;
	}

	return Counter;
}
/* ������� */
static void prvTCPWin_DelSegmentFrom(Segment ** pSegmentHead, Segment * pSegment)
{
	Segment * SegmentTemp = *pSegmentHead;

	if (SegmentTemp == NULL)return;

	if (SegmentTemp == pSegment)
	{
		*pSegmentHead = pSegment->Next;
		return;
	}

	while (SegmentTemp->Next != pSegment && SegmentTemp->Next)
	{
		SegmentTemp = SegmentTemp->Next;
	}
	/* SegmentTemp->Next����pSegment */
	if (SegmentTemp->Next)
	{
		SegmentTemp->Next = pSegment->Next;
		pSegment->Next = 0;
	}
}
/* �ͷ����� */
static void prvTCPWin_DelSegment(Segment * pSegment)
{
	MM_Ops.Free((uint8_t*)pSegment);
}
/* ������� */
static void prvTCPWin_AddSegmentToEnd(Segment ** pSegmentHead, Segment * pSegment)
{
	Segment * SegmentTemp = *pSegmentHead;

	if (SegmentTemp == NULL)
	{
		*pSegmentHead = pSegment;
		return;
	}
	while (SegmentTemp->Next)SegmentTemp = SegmentTemp->Next;
	SegmentTemp->Next = pSegment;
}
/* ����һ���� */
TCP_Win * TCPWin_NewWindows(uint32_t WinSizeRx, uint32_t WinSizeTx)
{

	TCP_Win * pTCP_Win = (TCP_Win*)MM_Ops.Malloc(sizeof(TCP_Win));
	if (pTCP_Win)
	{
		memset((uint8_t*)pTCP_Win,0x00, sizeof(TCP_Win));
		pTCP_Win->TxCapacity = WinSizeTx;
		pTCP_Win->RxCapacity = WinSizeRx;
	}
	return pTCP_Win;
}
/* Ѱ��SN�� */
static Segment * prvTCPWin_FindSnEndFromHeader(Segment ** pSegmentHeader,uint32_t Sn)
{
	Segment * SegmentTemp = *pSegmentHeader;

	while (1)
	{
		if (SegmentTemp == NULL)return NULL;
		if ((SegmentTemp->SnStart + SegmentTemp->Len) == Sn)return SegmentTemp;
		SegmentTemp = SegmentTemp->Next;
	}
	return NULL;
}
/* Ѱ��SN�� */
static Segment * prvTCPWin_FindSnStartFromHeader(Segment ** pSegmentHeader, uint32_t Sn)
{
	Segment * SegmentTemp = *pSegmentHeader;

	while (1)
	{
		if (SegmentTemp == NULL)return NULL;
		if (SegmentTemp->SnStart == Sn)return SegmentTemp;
		SegmentTemp = SegmentTemp->Next;
	}

	return NULL;
}
/* Ѱ�����SN�� */
static Segment * prvTCPWin_FindMaxSnStartFromHeader(Segment ** pSegmentHeader)
{
	Segment * SegmentTemp = *pSegmentHeader;
	uint32_t MaxSn = 0x00;
	Segment * pSegmentMaxSn = 0x00;

	while (1)
	{
		if (SegmentTemp == NULL)break;
		if (SegmentTemp->SnStart > MaxSn)
		{
			MaxSn = SegmentTemp->SnStart;
			pSegmentMaxSn = SegmentTemp;
		}
		SegmentTemp = SegmentTemp->Next;
	}

	return pSegmentMaxSn;
}
/* Ѱ����СSN�� */
static Segment * prvTCPWin_FindMinSnStartFromHeader(Segment ** pSegmentHeader)
{
	Segment * SegmentTemp = *pSegmentHeader;
	uint32_t MaxSn = 0xffffffff;
	Segment * pSegmentMinSn = 0x00;

	while (1)
	{
		if (SegmentTemp == NULL)break;
		if (SegmentTemp->SnStart < MaxSn)
		{
			MaxSn = SegmentTemp->SnStart;
			pSegmentMinSn = SegmentTemp;
		}
		SegmentTemp = SegmentTemp->Next;
	}

	return pSegmentMinSn;
}
/* �Ҹо��˺���û�������尡 */
static Segment * prvTCPWin_FindSnLessThanStartFromHeader(Segment ** pSegmentHeader, uint32_t Sn)
{
	Segment * SegmentTemp = *pSegmentHeader;

	while (1)
	{
		if (SegmentTemp == NULL)break;
		if (SegmentTemp->SnStart <= Sn)return SegmentTemp;
		SegmentTemp = SegmentTemp->Next;
	}

	return NULL;
}
/* ��С��������С��SN�� */
static Segment * prvTCPWin_FindMinSnNotLessThanStartFromHeader(Segment ** pSegmentHeader, uint32_t Sn)
{
	Segment * SegmentTemp = *pSegmentHeader;
	uint32_t MaxSn = 0xffffffff;
	Segment * pSegmentMaxSn = 0x00;

	while (1)
	{
		if (SegmentTemp == NULL)break;
		if (SegmentTemp->SnStart < MaxSn && SegmentTemp->SnStart > Sn)
		{
			MaxSn = SegmentTemp->SnStart;
			pSegmentMaxSn = SegmentTemp;
		}
		SegmentTemp = SegmentTemp->Next;
	}

	return pSegmentMaxSn;
}
/* ����һ����Ӧ�� */
void TCPWin_AckNormal(TCP_Win * pTCP_Win,uint32_t Sn){
	/* ��ȡ�ȴ�Ӧ���� */
	Segment * pSegment_Wait = prvTCPWin_FindSnEndFromHeader(&pTCP_Win->pSegment_Wait, Sn);
	if (pSegment_Wait){
		prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Wait, pSegment_Wait);
		prvTCPWin_DelSegment(pSegment_Wait);
	}
}
/* ������ݵ����壬���������ʽ����pSegment_Tx�� */
uint32_t TCPWin_AddTxData(TCP_Win * pTCP_Win, uint8_t * Data, uint32_t Len){
	Segment * pSegment = 0;
	uint32_t SegmentLen = 0,i = 0,Send = 0;
	while (Len){
		/* ȷ��һ���κ��е������� */
		if (Len >= pTCP_Win->MSS){SegmentLen = pTCP_Win->MSS;}
		else { SegmentLen = Len; }
		Len -= SegmentLen;
		/* ������ݵ����Ͷ��� */
		pSegment = prvTCPWin_NewSegment((uint8_t *)(Data + i), SegmentLen, pTCP_Win->Sn + i);
		prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Tx, pSegment);
		i += SegmentLen; pTCP_Win->TxCapacity -= SegmentLen; Send += SegmentLen;
		/* Ԥ�ƶԷ����ջ��彫���������Ѿ����͵����ݸ��� */
		if (pTCP_Win->TxCapacity <= pTCP_Win->MSS)break;
	}
	return Send;
}
/* ��ͷ����ȡ���ݼ��䳤�� */
Segment * TCPWin_GetDataLenFromSegmentHeader(Segment ** pSegmentHeader,uint8_t ** Data,uint32_t * Len)
{
	Segment * SegmentTemp = *pSegmentHeader;

	if (SegmentTemp == NULL)
	{
		if(Len)*Len = 0;
		return NULL;
	}

	if (Data)*Data = &SegmentTemp->Buff;
	if (Len)*Len = SegmentTemp->Len;

	return SegmentTemp;
}
/* ��ȡ�����ܳ��� */
uint32_t TCPWin_GetTotalDataLenFromHeader(Segment ** pSegmentHeader)
{
	Segment * SegmentTemp = *pSegmentHeader;
	uint32_t TotalLen = 0;

	while (1)
	{
		if (SegmentTemp == NULL)break;
		TotalLen += SegmentTemp->Len;
		SegmentTemp = SegmentTemp->Next;
	}
	return TotalLen;
}
/* ��ȡ��һ��Ҫ���͵����� */
void TCPWin_GetDataToTx(TCP_Win * pTCP_Win,uint8_t ** Data,uint32_t * Len,uint8_t Peek)
{
	/* SegmentWinΪ���ڴ�С */
	uint32_t SegmentWaitCounter = 0, SegmentWin = pTCP_Win->TxCapacity / pTCP_Win->MSS;
	Segment * pSegment = 0;
	if(pTCP_Win->pSegment_Wait)SegmentWaitCounter = prvTCPWin_GetCountFromHeader(&pTCP_Win->pSegment_Wait);
	else SegmentWaitCounter = 0;
	
	/* ���ɼ����������� */
	if (SegmentWin > SegmentWaitCounter)
	{
		/* ���������� */
		if (pTCP_Win->pSegment_Pri)
		{
			pSegment = TCPWin_GetDataLenFromSegmentHeader(&pTCP_Win->pSegment_Pri,Data,Len);
			/* �������������ȴ��� */
			if (!Peek && pSegment)
			{
				prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Pri, pSegment);
				prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Wait, pSegment);
			}
		}
		else
		{
			/* ������Ҫ���� */
			if (pTCP_Win->pSegment_Tx)
			{
				pSegment = TCPWin_GetDataLenFromSegmentHeader(&pTCP_Win->pSegment_Tx, Data, Len);
				/* ��TX�������ȴ��� */
				if (!Peek && pSegment)
				{
					prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Tx, pSegment);
					prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Wait, pSegment);
				}
			}
		}
	}
	//if (Len)*Len = 0;
}
/* �ѽ��ܵ����ݱ����ڴ��壬���������ʽ������pSegment_Rx */
void TCPWin_AddRxData(TCP_Win * pTCP_Win, uint8_t * RxData, uint32_t RxLen,uint32_t Sn)
{
	Segment * pSegment = 0;
	/* �����µĶβ����䱣�� */
	pSegment = prvTCPWin_NewSegment(RxData, RxLen, Sn);
	prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Rx, pSegment);
	pTCP_Win->RxCapacity -= RxLen;
}
/* ��ȡ����ʣ������ */
uint32_t TCPWin_GetRemainCapacity(TCP_Win * pTCP_Win)
{
	//return pTCP_Win->RxCapacity - TCPWin_GetTotalDataLenFromHeader(&pTCP_Win->pSegment_Rx);
	return pTCP_Win->RxCapacity;
}
/* ���ҽ���ȱ�� */
void TCPWin_RxHasHole(TCP_Win * pTCP_Win,uint32_t **SACK,uint32_t *SACKLen)
{
	Segment * pSegmentTemp = 0;
	Segment * MaxSnSegment = prvTCPWin_FindMaxSnStartFromHeader(&pTCP_Win->pSegment_Rx);
	Segment * MinSnSegment = prvTCPWin_FindMinSnStartFromHeader(&pTCP_Win->pSegment_Rx);
	uint32_t SackIndex = 0, MaxSn = MaxSnSegment->SnStart, MinSn = MinSnSegment->SnStart, TempSn = MinSn;

	while(1)
	{
		if (TempSn >= MaxSn)break;
		pSegmentTemp = prvTCPWin_FindSnStartFromHeader(&pTCP_Win->pSegment_Rx, TempSn);
		if (pSegmentTemp)
		{
			TempSn = pSegmentTemp->SnStart + pSegmentTemp->Len;
		}
		else
		{
			pSegmentTemp = prvTCPWin_FindMinSnNotLessThanStartFromHeader(&pTCP_Win->pSegment_Rx, TempSn);
			if(SACK)*SACK[SackIndex++] = TempSn;
			if(SACK)*SACK[SackIndex++] = pSegmentTemp->SnStart;
			TempSn = pSegmentTemp->SnStart;
		}
	}
	if (SACKLen)*SACKLen = SackIndex;
}
/* �жϽ����Ƿ���� */
uint8_t TCPWin_RxFinished(TCP_Win * pTCP_Win)
{
	uint32_t SACKLen = 0;
	TCPWin_RxHasHole(pTCP_Win,0, &SACKLen);
	if (SACKLen)return 0;
	return 1;
}
/* �жϷ����Ƿ���� */
uint8_t TCPWin_TxFinished(TCP_Win * pTCP_Win)
{
	if (pTCP_Win->pSegment_Tx || pTCP_Win->pSegment_Wait || pTCP_Win->pSegment_Pri)return 0;
	return 1;
}
/* �����յ����������û����� */
void TCPWin_GiveUsrRxData(TCP_Win * pTCP_Win,uint8_t * Data,uint32_t * DataLen)
{
	/* Ѱ�����Sn�� */
	Segment * MinSnSegment = prvTCPWin_FindMinSnStartFromHeader(&pTCP_Win->pSegment_Rx);
	Segment * TempSnSegment = 0;
	uint32_t TempSn = MinSnSegment->SnStart, DataLenTemp = 0;

	*DataLen = 0;

	while (1)
	{
		/* �����SN�ſ�ʼ��������,�����û����帴������ */
		TempSnSegment = prvTCPWin_FindSnStartFromHeader(&pTCP_Win->pSegment_Rx, TempSn);
		if (TempSnSegment)
		{
			/* �������� */
			memcpy((uint8_t*)(Data + DataLenTemp), &TempSnSegment->Buff, TempSnSegment->Len);
			DataLenTemp += TempSnSegment->Len;
			TempSn += TempSnSegment->Len;
			if (DataLen)*DataLen = DataLenTemp;
			/* �ͷ����� */
			prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Rx, TempSnSegment);
			prvTCPWin_DelSegment(TempSnSegment);
		}
		/* ��һ���Ͽ���Sn���˳� */
		else break;
	}

}



