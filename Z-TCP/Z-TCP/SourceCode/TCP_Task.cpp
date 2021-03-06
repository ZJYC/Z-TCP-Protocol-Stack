
#include "TCP_Task.h"
#include "NetworkBuff.h"
#include "Ethernet.h"
#include <stdio.h>
#include <windows.h>

TCB tcb = { 0x00 };

DWORD WINAPI LLDataProcessLoop(LPVOID lpParam)
{
	while (1) {
		if (tcb.Ethernet_Rx_Packet)
		{
			NeteworkBuff * pNeteworkBuff = Network_GetOne(NetworkBuffDirRx);
			Ethernet_ProcessPacket(pNeteworkBuff);
			Network_Del(pNeteworkBuff);
			tcb.Ethernet_Rx_Packet -= 1;
		}
		if (tcb.Ethernet_Tx_Packet)
		{
			NeteworkBuff * pNeteworkBuff = Network_GetOne(NetworkBuffDirTx);
			Ethernet_SendNetworkBuff(pNeteworkBuff);
			Network_Del(pNeteworkBuff);
			tcb.Ethernet_Tx_Packet -= 1;
		}
		Sleep(100);
	}
	return 0;
}

//Ethernet_RecvNetworkBuff

DWORD WINAPI SimulateDataInput(LPVOID lpParam) {
	const char FileName[] = "SimulateInput.txt";
	uint8_t FileData[10 * 1024] = { 0 }, FilePath[256] = {0};
	uint16_t FileDatalen = 0;
	while (1) {
		/* 从文件读入数据 */
		GetModuleFileName(NULL, (LPTSTR)FilePath,255);
		uint16_t StrLen = strlen((const char*)FilePath);
		while (1) {
			if (FilePath[StrLen] != '\\')StrLen--;
			else {
				FilePath[StrLen + 1] = 0;
				break;
			}
		}
		strcat((char *)FilePath, FileName);
		FILE * file = fopen((const char*)FilePath, "r+");
		if (file != NULL) {
			/* 读取文件数据 */
			fseek(file,0,SEEK_END);
			uint16_t FileSize = ftell(file); fseek(file, 0, SEEK_SET);
			uint16_t ReadSize = fread(FileData, 1, FileSize,file);
			FileDatalen = ReadSize;
			/* 清空文件 */
			fclose(file);
			FILE * file = fopen((const char*)FilePath, "w");
			if (file != NULL)fclose(file);
		}
		/* 转换数据为网络缓存 */
		if(file != NULL)fclose(file);
		if (FileDatalen) {
			/* 全部为大写字母 */
			uint16_t i = 0,CharNum = 0;
			for (i = 0; i < FileDatalen; i++) {
				if (FileData[i] <= 'z' && FileData[i] >= 'a')FileData[i] -= 32;
			}
			/* 去掉换行等 */
			for (i = 0; i < FileDatalen; i++) {
				if (FileData[i] == '\r' || FileData[i] == '\n')FileData[i] = ' ';
			}
			/* 计算显示字符个数 */
			for (i = 0; i < FileDatalen; i++) {
				if (FileData[i] != ' ')CharNum ++;
			}
			if (CharNum % 2 == 0) {//1234567890ABCDEF
				uint8_t Buff[10 * 1024] = { 0 },Temp = 0;
				uint16_t i = 0, j = 0,m = 0;
				for (i = 0; i < FileDatalen; i++) {
					if (FileData[i] >= '0' && FileData[i] <= '9') {
						Temp |= (FileData[i] - '0') << (4 - j * 4); j++;
					}
					if (FileData[i] >= 'A' && FileData[i] <= 'Z') {
						Temp |= (FileData[i] - 'A' + 10) << (4 - j * 4); j++;
					}
					if (j == 2) {
						Buff[m++] = Temp; j = 0; Temp = 0;
					}
				}
				/* 生成网络缓存 */
				Ethernet_RecvNetworkBuff(Buff,m);
			}
		}
		Sleep(500);
	}
}





















