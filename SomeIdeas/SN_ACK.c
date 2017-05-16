
/* �˴�ֻ�ܱȽ�SN��ACK�������ܸı� */
/* pTCP_Header���������Ϊ����������Ҫת��Ϊ�������� */
/* �����Ƿ���Ҫ�ж϶Է���SN�ţ�����ֻ��Ҫ��¼�� */
static RES prvTCP_SN_ACK_Rx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header)
{
    /* �����ѽ�����SN֪ͨ�ڶԷ� */
	if (pTCP_Control->LocalSN_Informed)
	{
        /* pTCP_Control->LocalSN������������ACK�ţ����ڷ���ʱ���˼ӷ�*/
        /* ������ʱ������SACK����ΪSACK�Ƚϸ��� */
		if (DIY_ntohl(pTCP_Header->AK) != pTCP_Control->LocalSN)return RES_TCPPacketDeny;
	}
    /* ��֪���Է�SN */
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


/* �˴���ı�SN��ACK����ֵ */
static RES prvTCP_SN_ACK_Tx(TCP_Control * pTCP_Control, TCP_Header * pTCP_Header,uint32_t RxLen, uint32_t TxLen)
{
	pTCP_Header->SN = DIY_htonl(pTCP_Control->LocalSN);

	if (pTCP_Control->State < TCP_STATE_ESTABLISHED)
	{
        /* �ڽ�������֮ǰ������Ϊ 1 */
		pTCP_Control->LocalSN += 1;
		if (pTCP_Control->RemoteSN_Knowed)
        {
            pTCP_Control->RemoteSN += 1;
            pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
        }
	}
    /* �����Ѿ����� */
    else
    {
        /* ��ʱ�ȱ�ܱ����ź��� */
        pTCP_Control->LocalSN += TxLen;
        pTCP_Control->RemoteSN += RxLen;
        pTCP_Header->AK = DIY_htonl(pTCP_Control->RemoteSN);
    }
    /* �����ѽ�������������û��ɣ�Ƿ�Է�һ��ACK */
	if (pTCP_Control->State == TCP_STATE_ESTABLISHED && pTCP_Control->HSF == 0)
	{
		pTCP_Control->LocalSN += 1;
	}
	pTCP_Control->LocalSN_Informed = 1;
}



