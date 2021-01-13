#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdio.h> 
#include <stdlib.h>
#include <winsock2.h>  
#include <mswsock.h>  
#include <ws2tcpip.h>
#include <stdint.h>
#pragma comment(lib, "ws2_32.lib")  
#pragma comment(lib, "mswsock.lib") 

#define IO_BUF_SIZE (90000)

#define CMD_OS_INFO	1
#define CMD_CURRENT_TIME 2
#define CMD_TIME_SINCE_OS_STARTUP 3
#define CMD_USED_MEMORY	4
#define CMD_DRIVES_INFO	5
#define CMD_ACCESS_RIGHTS 6
#define CMD_OWNER 7
#define CMD_DISCONNECT 8

void InitIo();
void DeinitIo();
void EstablishConnection(char* ip, char* port);
void Disconnect(int serv_num);
void SendRequest(uint32_t cmd, char* arg, int serv_num);
void ProcessResponce(uint32_t cmd, int serv_num);