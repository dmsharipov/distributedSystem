#pragma once

#define WIN32_LEAN_AND_MEAN  

#include <winsock2.h> 
#include <mswsock.h>  
#include <stdio.h>  
#include <stdlib.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")  
#pragma comment(lib, "mswsock.lib") 

#define MAX_CLIENTS_QNT (100) 
#define IO_BUF_SIZE (90000)

#include "crypt_func.h"
#include "common.h"

struct clientContex
{
	SOCKET socket;
	CHAR bufRecv[IO_BUF_SIZE]; // Буфер приема
	CHAR bufSend[IO_BUF_SIZE]; // Буфер отправки

	unsigned int szRecv; // Принято данных
	unsigned int szSend; // Данных отправлено

	// Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlapRecv;
	OVERLAPPED overlapSend;
	OVERLAPPED overlapCancel;
	OVERLAPPED overlapRecvPublicKey;

	DWORD flagsRecv; // Флаги для WSARecv  

	HCRYPTKEY hSessionKey;
};

extern WSADATA wsa_data;
extern SOCKET listeningSock;
extern SOCKET acceptedSocket;

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
extern clientContex cliCtxs[MAX_CLIENTS_QNT];

void DeinitIo();
void IoServer();