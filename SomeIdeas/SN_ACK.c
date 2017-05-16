
/* 此处只能比较SN和ACK，而不能改变 */
/* pTCP_Header里面的数据为网络字序，需要转换为主机字序 */
/* 我们是否需要判断对方的SN号？还是只需要记录？ */
static RES prvTCP_SN_ACK_Rx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
    /* 我们已将本地SN通知于对方 */
	if (pTCP_Control->LocalSN_Informed)
	{
        /* pTCP_Control->LocalSN是我们期望的ACK号，他在发送时做了加法*/
        /* 我们暂时不考虑SACK，因为SACK比较复杂 */
		if (DIY_ntohl(pTCP_Header->AK) != pTCP_Control->LocalSN)return RES_TCPPacketDeny;
	}
    /* 已知晓对方SN */
	//if (pTCP_Control->RemoteSN_Knowed)
	//{
	//	if(DIY_ntohl(pTCP_Header->SN) == pTCP_Control->RemoteSN)return RES_TCPPacketDeny;
	//}
	//if (!pTCP_Control->RemoteSN_Knowed)
	//{
		pTCP_Control->RemoteSN_Knowed = 1;
		pTCP_Control->RemoteSN = DIY_ntohl(pTCP_Header->SN);
	//}
	return RES_TCPPacketPass;
}


/* 此处会改变SN和ACK的数值 */
static RES prvTCP_SN_ACK_Tx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header,uint32_t RxLen, uint32_t TxLen)
{
	pTCP_Header->SN = DIY_htonl(pTCP_Control->LocalSN);

	if (pTCP_Control->State < TCP_STATE_ESTABLISHED)
	{
        /* 在建立连接之前，增量为 1 */
		pTCP_Control->LocalSN += 1;
		if (pTCP_Control->RemoteSN_Knowed)
        {
            pTCP_Control->RemoteSN += 1;
            pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
        }
	}
    /* 连接已经建立 */
    else
    {
        /* 暂时先别管保活信号了 */
        pTCP_Control->LocalSN += TxLen;
        pTCP_Control->RemoteSN += RxLen;
        pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
    }
    /* 连接已建立，但是握手没完成，欠对方一个ACK */
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0)
	{
		pTCP_Control->LocalSN += 1;
	}
	pTCP_Control->LocalSN_Informed = 1;
}



