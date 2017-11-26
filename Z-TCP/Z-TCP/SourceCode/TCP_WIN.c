
#include "DataTypeDef.h"
#include "TCP_WIN.h"
#include "heap_5.h"
#include "TCP.h"
/* 创建一新的段，并把数据和SN号填入 */
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
/* 计算链表长度 */
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
/* 解除链表 */
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
	/* SegmentTemp->Next就是pSegment */
	if (SegmentTemp->Next)
	{
		SegmentTemp->Next = pSegment->Next;
		pSegment->Next = 0;
	}
}
/* 释放链表 */
static void prvTCPWin_DelSegment(Segment * pSegment)
{
	MM_Ops.Free((uint8_t*)pSegment);
}
/* 添加链表 */
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
/* 创建一窗体 */
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
/* 寻找SN号 */
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
/* 寻找SN号 */
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
/* 寻找最大SN号 */
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
/* 寻找最小SN号 */
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
/* 我感觉此函数没大有意义啊 */
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
/* 不小于他的最小的SN号 */
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
/* 接收一常规应答 */
void TCPWin_AckNormal(TCP_Win * pTCP_Win,uint32_t Sn){
	/* 获取等待应答链 */
	Segment * pSegment_Wait = prvTCPWin_FindSnEndFromHeader(&pTCP_Win->pSegment_Wait, Sn);
	if (pSegment_Wait){
		prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Wait, pSegment_Wait);
		prvTCPWin_DelSegment(pSegment_Wait);
	}
}
/* 添加数据到窗体，以链表的形式挂在pSegment_Tx上 */
uint32_t TCPWin_AddTxData(TCP_Win * pTCP_Win, uint8_t * Data, uint32_t Len){
	Segment * pSegment = 0;
	uint32_t SegmentLen = 0,i = 0,Send = 0;
	while (Len){
		/* 确定一个段含有的数据量 */
		if (Len >= pTCP_Win->MSS){SegmentLen = pTCP_Win->MSS;}
		else { SegmentLen = Len; }
		Len -= SegmentLen;
		/* 添加数据到发送段链 */
		pSegment = prvTCPWin_NewSegment((uint8_t *)(Data + i), SegmentLen, pTCP_Win->Sn + i);
		prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Tx, pSegment);
		i += SegmentLen; pTCP_Win->TxCapacity -= SegmentLen; Send += SegmentLen;
		/* 预计对方接收缓冲将满，返回已经发送的数据个数 */
		if (pTCP_Win->TxCapacity <= pTCP_Win->MSS)break;
	}
	return Send;
}
/* 从头部获取数据及其长度 */
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
/* 获取数据总长度 */
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
/* 获取下一步要发送的数据 */
void TCPWin_GetDataToTx(TCP_Win * pTCP_Win,uint8_t ** Data,uint32_t * Len,uint8_t Peek)
{
	/* SegmentWin为窗口大小 */
	uint32_t SegmentWaitCounter = 0, SegmentWin = pTCP_Win->TxCapacity / pTCP_Win->MSS;
	Segment * pSegment = 0;
	if(pTCP_Win->pSegment_Wait)SegmentWaitCounter = prvTCPWin_GetCountFromHeader(&pTCP_Win->pSegment_Wait);
	else SegmentWaitCounter = 0;
	
	/* 还可继续发送数据 */
	if (SegmentWin > SegmentWaitCounter)
	{
		/* 存在优先组 */
		if (pTCP_Win->pSegment_Pri)
		{
			pSegment = TCPWin_GetDataLenFromSegmentHeader(&pTCP_Win->pSegment_Pri,Data,Len);
			/* 从优先组移至等待组 */
			if (!Peek && pSegment)
			{
				prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Pri, pSegment);
				prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Wait, pSegment);
			}
		}
		else
		{
			/* 有数据要发送 */
			if (pTCP_Win->pSegment_Tx)
			{
				pSegment = TCPWin_GetDataLenFromSegmentHeader(&pTCP_Win->pSegment_Tx, Data, Len);
				/* 从TX组移至等待组 */
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
/* 把接受的数据保存在窗体，以链表的形式保存在pSegment_Rx */
void TCPWin_AddRxData(TCP_Win * pTCP_Win, uint8_t * RxData, uint32_t RxLen,uint32_t Sn)
{
	Segment * pSegment = 0;
	/* 创建新的段并将其保存 */
	pSegment = prvTCPWin_NewSegment(RxData, RxLen, Sn);
	prvTCPWin_AddSegmentToEnd(&pTCP_Win->pSegment_Rx, pSegment);
	pTCP_Win->RxCapacity -= RxLen;
}
/* 获取接收剩余容量 */
uint32_t TCPWin_GetRemainCapacity(TCP_Win * pTCP_Win)
{
	//return pTCP_Win->RxCapacity - TCPWin_GetTotalDataLenFromHeader(&pTCP_Win->pSegment_Rx);
	return pTCP_Win->RxCapacity;
}
/* 查找接收缺口 */
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
/* 判断接收是否完成 */
uint8_t TCPWin_RxFinished(TCP_Win * pTCP_Win)
{
	uint32_t SACKLen = 0;
	TCPWin_RxHasHole(pTCP_Win,0, &SACKLen);
	if (SACKLen)return 0;
	return 1;
}
/* 判断发送是否完成 */
uint8_t TCPWin_TxFinished(TCP_Win * pTCP_Win)
{
	if (pTCP_Win->pSegment_Tx || pTCP_Win->pSegment_Wait || pTCP_Win->pSegment_Pri)return 0;
	return 1;
}
/* 将接收到的数据向用户传递 */
void TCPWin_GiveUsrRxData(TCP_Win * pTCP_Win,uint8_t * Data,uint32_t * DataLen)
{
	/* 寻找最低Sn号 */
	Segment * MinSnSegment = prvTCPWin_FindMinSnStartFromHeader(&pTCP_Win->pSegment_Rx);
	Segment * TempSnSegment = 0;
	uint32_t TempSn = MinSnSegment->SnStart, DataLenTemp = 0;

	*DataLen = 0;

	while (1)
	{
		/* 从最低SN号开始遍历搜索,逐渐向用户缓冲复制数据 */
		TempSnSegment = prvTCPWin_FindSnStartFromHeader(&pTCP_Win->pSegment_Rx, TempSn);
		if (TempSnSegment)
		{
			/* 复制数据 */
			memcpy((uint8_t*)(Data + DataLenTemp), &TempSnSegment->Buff, TempSnSegment->Len);
			DataLenTemp += TempSnSegment->Len;
			TempSn += TempSnSegment->Len;
			if (DataLen)*DataLen = DataLenTemp;
			/* 释放链表 */
			prvTCPWin_DelSegmentFrom(&pTCP_Win->pSegment_Rx, TempSnSegment);
			prvTCPWin_DelSegment(TempSnSegment);
		}
		/* 第一个断开的Sn号退出 */
		else break;
	}

}



