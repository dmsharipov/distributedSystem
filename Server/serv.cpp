#include "serv_func.h"
#include "crypt_func.h"
#include "common.h"
#include "spy_func.h"
#include <windows.h> 
#include <stdio.h> 
#include <iostream>

#define CMD_OS_INFO	1
#define CMD_CURRENT_TIME 2
#define CMD_TIME_SINCE_OS_STARTUP 3
#define CMD_USED_MEMORY	4
#define CMD_DRIVES_INFO	5
#define CMD_ACCESS_RIGHTS 6
#define CMD_OWNER 7
#define CMD_DISCONNECT 8

WSADATA wsaData;
SOCKET listeningSock;
HANDLE IoCompletionPort;
SOCKET acceptedSocket;

clientContex cliCtxs[MAX_CLIENTS_QNT];

// Should left space (size of uint32_t) for size of crypted text.
bool ProcessRequest(CHAR* bufRecv, CHAR* bufSend, uint32_t* pSzPlainText, ULONG_PTR key)
{
	memset(bufSend, 0, IO_BUF_SIZE);

	CHAR* strArg = (CHAR*)((BYTE*)bufRecv + 2 * sizeof(uint32_t));
	uint32_t cmd = *((uint32_t*)bufRecv + 1);

	CHAR* bufResponce = (CHAR*)((BYTE*)bufSend + sizeof(uint32_t));

	switch (cmd)
	{
	case CMD_OS_INFO:
		printf("Requested command: CMD_OS_INFO\n");
		GetOsVersion(bufResponce, pSzPlainText);
		return 1;
		break;

	case CMD_CURRENT_TIME:
		printf("Requested command: CMD_CURRENT_TIME\n");
		GetCurrTime(bufResponce, pSzPlainText);
		return 1;
		break;

	case CMD_TIME_SINCE_OS_STARTUP:
		printf("Requested command: CMD_TIME_SINCE_OS_STARTUP\n");
		GetTimeElapsedSinceOsStartup(bufResponce, pSzPlainText);
		return 1;
		break;

	case CMD_USED_MEMORY:
		printf("Requested command: CMD_USED_MEMORY\n");
		GetMemoryStatus(bufResponce, pSzPlainText);
		return 1;
		break;

	case CMD_DRIVES_INFO:
		printf("Requested command: CMD_MAPPED_DRIVES_TYPES\n");
		GetDrivesInfo(bufResponce, pSzPlainText);
		return 1;
		break;

	case CMD_ACCESS_RIGHTS:
		printf("Requested command: CMD_ACCESS_RIGHTS_FILE_OBJECT\n");
		GetAccessRights(bufResponce, strArg, pSzPlainText);
		*pSzPlainText = strlen(bufResponce) + 1;
		return 1;
		break;

	case CMD_OWNER:
		printf("Requested command: CMD_OWNER_FILE_OBJECT\n");
		GetOwner(bufResponce, strArg, pSzPlainText);
		*pSzPlainText = strlen(bufResponce) + 1;
		return 1;
		break;

	case CMD_DISCONNECT:
		printf("Requested command: CMD_DISCONNECT\n");
		CancelIo((HANDLE)cliCtxs[key].socket);
		PostQueuedCompletionStatus(IoCompletionPort, 0, key, &cliCtxs[key].overlapCancel);
		return 0;
		break;

	default:
		printf("Error: unrecognized command: %d\n", cmd);
		DeinitEverything();
		exit(-1);
	}
}

// Функция стартует операцию чтения из сокета
void ScheduleRead(DWORD idx)
{
	WSABUF buf;
	buf.buf = cliCtxs[idx].bufRecv;
	buf.len = sizeof(cliCtxs[idx].bufRecv);
	memset(&cliCtxs[idx].overlapRecv, 0, sizeof(OVERLAPPED));
	cliCtxs[idx].flagsRecv = 0;
	WSARecv(cliCtxs[idx].socket, &buf, 1, NULL, &cliCtxs[idx].flagsRecv, &cliCtxs[idx].overlapRecv, NULL);
}

void ScheduleRecvPublicKey(DWORD idx)
{
	WSABUF buf;
	buf.buf = cliCtxs[idx].bufRecv;
	buf.len = sizeof(cliCtxs[idx].bufRecv);
	memset(&cliCtxs[idx].overlapRecvPublicKey, 0, sizeof(OVERLAPPED));
	cliCtxs[idx].flagsRecv = 0;
	WSARecv(cliCtxs[idx].socket, &buf, 1, NULL, &cliCtxs[idx].flagsRecv, &cliCtxs[idx].overlapRecvPublicKey, NULL);
}

// Функция добавляет новое принятое подключение клиента
void AddAcceptedConnection()
{
	// Поиск места в массиве g_ctxs для вставки нового подключения
	for (unsigned int i = 0; i < MAX_CLIENTS_QNT; i++)
	{
		if (cliCtxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(cliCtxs[0].bufRecv,
				cliCtxs[0].szRecv,
				sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16,
				(struct sockaddr**) & local_addr,
				&local_addr_sz,
				(struct sockaddr**) & remote_addr,
				&remote_addr_sz
			);

			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);

			printf("Connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);
			cliCtxs[i].socket = acceptedSocket;

			// Связь сокета с портом IOCP, в качестве key используется индекс массива     
			if (NULL == CreateIoCompletionPort((HANDLE)cliCtxs[i].socket, IoCompletionPort, i, 0))
			{
				printf("Error: CreateIoCompletionPort  (line: %d, error: %d\n)", __LINE__, GetLastError());
				return;
			}

			ScheduleRecvPublicKey(i);
			return;
		}
	}

	// Место не найдено => нет ресурсов для принятия соединения  
	closesocket(acceptedSocket);
	acceptedSocket = 0;
}

void ScheduleAccept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	acceptedSocket = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (acceptedSocket == INVALID_SOCKET)
	{
		printf("Error: WSASocket  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		exit(-1);
	}

	memset(&cliCtxs[0].overlapRecv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	bool isSuccess = AcceptEx(cliCtxs[0].socket,
		acceptedSocket,
		cliCtxs[0].bufRecv,
		0,
		sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16,
		NULL,
		&cliCtxs[0].overlapRecv
	);
	if (!isSuccess)
	{
		int WsaErr = WSAGetLastError();

		if (WsaErr != WSA_IO_PENDING)
		{
			printf("Error: AcceptEx  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
			DeinitEverything();
			exit(-1);
		}
	}
}

// Функция стартует операцию отправки подготовленных данных в сокет
void ScheduleWrite(DWORD idx)
{
	WSABUF buf;
	buf.buf = cliCtxs[idx].bufSend;
	buf.len = cliCtxs[idx].szSend;
	memset(&cliCtxs[idx].overlapSend, 0, sizeof(OVERLAPPED));
	WSASend(cliCtxs[idx].socket, &buf, 1, NULL, 0, &cliCtxs[idx].overlapSend, NULL);
}

void IoServer()
{
	printf("Server started.\n");

	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;

		// Ожидание событий в течение 1 секунды
		if (GetQueuedCompletionStatus(IoCompletionPort, &transferred, &key, &lp_overlap, 1000))
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				cliCtxs[0].szRecv += transferred;
				// Принятие подключения и начало принятия следующего
				AddAcceptedConnection();
				ScheduleAccept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента
				if (&cliCtxs[key].overlapRecv == lp_overlap) //Ключ key - индекс в массиве cliCtxs
				{
					// Данные приняты
					if (transferred == 0)
					{
						// Соединение разорвано        
						CancelIo((HANDLE)cliCtxs[key].socket);
						PostQueuedCompletionStatus(IoCompletionPort, 0, key, &cliCtxs[key].overlapCancel);
						continue;
					}

					cliCtxs[key].szRecv += transferred;

					uint32_t uiSzCipherText = *((uint32_t*)cliCtxs[key].bufRecv);
					DWORD dwSzCipherText = uiSzCipherText;

					if (CryptDecrypt(cliCtxs[key].hSessionKey, 0, 1, 0, ((BYTE*)(cliCtxs[key].bufRecv)) + sizeof(uint32_t), &dwSzCipherText) == 0)
					{
						printf("\nError: CryptDecrypt error on client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
						DeinitEverything();
						exit(-1);
					}

					uint32_t uiSzPlainText;
					bool needToAnswer = ProcessRequest(cliCtxs[key].bufRecv, cliCtxs[key].bufSend, &uiSzPlainText, key);

					if (needToAnswer)
					{
						DWORD dataLen = uiSzPlainText;
						if (CryptEncrypt(cliCtxs[key].hSessionKey, NULL, 1, 0, ((BYTE*)cliCtxs[key].bufSend) + sizeof(uint32_t), &dataLen, IO_BUF_SIZE - sizeof(uint32_t)) == 0)
						{
							printf("\nError: CryptEncrypt error on client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
							DeinitEverything();
							exit(-1);
						}

						*((uint32_t*)cliCtxs[key].bufSend) = dataLen;

						cliCtxs[key].szSend = dataLen + sizeof(uint32_t);

						cliCtxs[key].szRecv = 0;
						memset(cliCtxs[key].bufRecv, 0, sizeof(cliCtxs[key].bufRecv));
						ScheduleRead(key);

						ScheduleWrite(key);
					}
				}
				else if (&cliCtxs[key].overlapSend == lp_overlap)
				{
				}
				else if (&cliCtxs[key].overlapRecvPublicKey == lp_overlap)
				{
					uint32_t szBlobPublicKey = *((uint32_t*)cliCtxs[key].bufRecv);
					BYTE* pBlob = ((BYTE*)cliCtxs[key].bufRecv) + sizeof(uint32_t);

					HCRYPTKEY hPublicKey;
					if (CryptImportKey(hCryptProv, (BYTE*)(pBlob), szBlobPublicKey, 0, 0, &hPublicKey) == 0)
					{
						printf("\nError: CryptImportKey error on client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
						CancelIo((HANDLE)cliCtxs[key].socket);
						PostQueuedCompletionStatus(IoCompletionPort, 0, key, &cliCtxs[key].overlapCancel);
						continue;
					}

					if (CryptGenKey(hCryptProv, CALG_RC4, CRYPT_EXPORTABLE, &cliCtxs[key].hSessionKey) == 0)
					{
						printf("\nError: CryptGenKey error on client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
						DeinitEverything();
						exit(-1);
					}

					uint32_t szBlobSessionKey = IO_BUF_SIZE - sizeof(uint32_t);
					if (ExportSessionKey(((BYTE*)cliCtxs[key].bufSend) + sizeof(uint32_t), &szBlobSessionKey, hPublicKey, cliCtxs[key].hSessionKey) != 0)
					{
						printf("\nError: ExportSessionKey error on client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
						CancelIo((HANDLE)cliCtxs[key].socket);
						PostQueuedCompletionStatus(IoCompletionPort, 0, key, &cliCtxs[key].overlapCancel);
						continue;
					}
					*((uint32_t*)cliCtxs[key].bufSend) = szBlobSessionKey;

					cliCtxs[key].szSend = szBlobSessionKey + sizeof(uint32_t);

					cliCtxs[key].szRecv = 0;
					memset(cliCtxs[key].bufRecv, 0, sizeof(cliCtxs[key].bufRecv));
					ScheduleRead(key);

					ScheduleWrite(key);

					if (!(CryptDestroyKey(hPublicKey)))
					{
						printf("Warning: CryptDestroyKey failed on public key of client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
					}


				}
				else if (&cliCtxs[key].overlapCancel == lp_overlap)
				{
					if (cliCtxs[key].hSessionKey)
					{
						if (!(CryptDestroyKey(cliCtxs[key].hSessionKey)))
						{
							printf("Warning: CryptDestroyKey failed on session key of client %d (line: %d, error: %d)\n", key, __LINE__, GetLastError());
						}

						cliCtxs[key].hSessionKey = NULL;
					}

					closesocket(cliCtxs[key].socket);
					memset(&cliCtxs[key], 0, sizeof(cliCtxs[key]));
					printf("Connection %u closed\n", key);
				}
			}
		}
		else
		{
			DWORD err = GetLastError();
			if (err == ERROR_NETNAME_DELETED)
			{
				CancelIo((HANDLE)cliCtxs[key].socket);
				PostQueuedCompletionStatus(IoCompletionPort, 0, key, &cliCtxs[key].overlapCancel);
			}
			else if (err != WAIT_TIMEOUT)
			{
				printf("Error: GetQueuedCompletionStatus  (line: %d, error: %d)\n", __LINE__, GetLastError());
				DeinitIo();
				exit(-1);
			}
		}
	}
}

void DeinitIo()
{
	for (unsigned int i = 0; i < MAX_CLIENTS_QNT; i++)
	{
		if (cliCtxs[i].socket != 0)
		{
			CancelIo((HANDLE)cliCtxs[i].socket);
			closesocket(cliCtxs[i].socket);
		}
	}

	if (CloseHandle(IoCompletionPort) == 0)
	{
		printf("Warning: CloseHandle returned error (line: %d, error: %d)\n", __LINE__, GetLastError());
	}

	if (WSACleanup() != 0)
	{
		printf("Warning: WSACleanup returned error (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
	}
}

void DeinitEverything()
{
	DeinitCrypt();
	DeinitIo();
}

int main(void)
{
	setlocale(LC_ALL, "Russian");

	//Init IO
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("Error: WSAStartup  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		exit(-1);
	}

	//Создание сокета прослушивания
	listeningSock = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listeningSock == INVALID_SOCKET)
	{
		printf("\nError: WSASocket (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitIo();
		exit(-1);
	}

	//Создание порта завершения
	IoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == IoCompletionPort)
	{
		printf("Error: CreateIoCompletionPort  (line: %d, error: %d\n)", __LINE__, GetLastError());
		DeinitIo();
		exit(-1);
	}

	//Инициализация структуры для хранения входящих соединений
	memset(cliCtxs, 0, sizeof(cliCtxs));

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);

	if (bind(listeningSock, (struct sockaddr*) & addr, sizeof(addr)) == SOCKET_ERROR)
	{
		printf("Error: bind  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitIo();
		exit(-1);
	}

	if (listen(listeningSock, 1) == SOCKET_ERROR)
	{
		printf("Error: listen  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitIo();
		exit(-1);
	}

	printf("Listening port %hu\n", ntohs(addr.sin_port));

	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (CreateIoCompletionPort((HANDLE)listeningSock, IoCompletionPort, 0, 0) == NULL)
	{
		printf("Error: CreateIoCompletionPort  (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitIo();
		exit(-1);
	}

	cliCtxs[0].socket = listeningSock;

	// Старт операции принятия подключения.
	ScheduleAccept();

	InitCrypt();

	IoServer();

	return 0;
}