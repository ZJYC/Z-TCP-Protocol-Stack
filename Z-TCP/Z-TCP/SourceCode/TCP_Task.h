
#ifndef __TCP_TASK_H__
#define __TCP_TASK_H__
#ifdef __cplusplus
extern "C" {
#endif

	#include <stdio.h>
	#include <windows.h>

	#include "DataTypeDef.h"

	typedef struct TCB_
	{
		uint32_t Ethernet_Rx_Packet;
		uint32_t Ethernet_Tx_Packet;
	}TCB;

	extern TCB tcb;

	DWORD WINAPI LLDataProcessLoop(LPVOID lpParam);
	DWORD WINAPI SimulateDataInput(LPVOID lpParam);

#ifdef __cplusplus
}
#endif
#endif


