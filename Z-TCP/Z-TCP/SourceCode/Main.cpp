
#include <stdio.h>
#include <windows.h>

#include "ARP.h"
#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "UDP.h"
#include "TCP_Task.h"
#include "TCP.h"
#include "DHCP.h"
#include "ICMP.h"

void Init(void){
	Network_Init();
	ARP_Init();
	Ethernet_Init();
	IP_Init();
	DHCP_Init();
}

void CreateTask() {
	//CreateThread(NULL,0,DHCP_MainTask,0,0,NULL);
	//printf("Create DHCP_MainTask\r\n"); 
	CreateThread(NULL, 0, LLDataProcessLoop, 0, 0, NULL);
	printf("Create LLDataProcessLoop\r\n"); 
	CreateThread(NULL, 0, SimulateDataInput, 0, 0, NULL);
	printf("Create SimulateDataInput\r\n");
}

int main(void)
{
	//IP_Str2Int((uint8_t *)"192.168.120.98", 0);
	//MAC_Str2Int((uint8_t*)"11:22:aa:bb:cc:34",0);
	//uint8_t Data[] = "1234567890";
	Init();
	CreateTask();
	//Socket * pSocket = prvSocket_New(&Address, IP_Protocol_UDP);
	//Socket_Send(pSocket,Data, 10);
	//TCP_Test_Rx();
	//----TCP_Test_Tx();
	//ARP_Test();
	//DHCP_Test();
	while (1) {
		Sleep(1000);
	}
	//ICMP_Test();
	while (1) {
		;
	}
}

















