#define MAX_CMD_ARGUMENTS_QNT (10)
#include "client_func.h"
#include "crypt_func.h"
#include "common.h"
#include "serv_struct.h"
#include <string>
#include <windows.h>
#include <iostream>

WSADATA wsa_data;
CHAR ioBuf[IO_BUF_SIZE];
SERV servs[MAX_SERV_CNT];
int serv_cnt;

enum commandNames
{
	getOsVer,
	exit_,
	getCurrentTime,
	getTimeSinceOsStartup,
	help,
	connect_,
	getMemoryStatus,
	getDrivesInfo,
	getAccessRights,
	getOwner,
	unknown
};

void ProcessInfoOsVersion(void* buf)
{
	printf("{\n\t\"CMD_OS_INFO\" : \"%s\"\n}\n", (char*)buf);
}

void ProcessTimeElapsedSinceOsStartup(void* buf)
{
	printf("{\n\t\"CMD_TIME_SINCE_OS_STARTUP\" : \"%s\"\n}\n", (char*)buf);
}

void ProcessCurrentTime(void* buf)
{
	printf("{\n\t\"CMD_CURRENT_TIME\" : \"%s\"\n}\n", (char*)buf);
}

void ProcessMemoryStatus(void* buf)
{
	uint64_t* msVal = (uint64_t*)buf;

	printf("{\n\t\"TOTAL_PHYS\" : %u,\n", msVal[0]);
	printf("\t\"AVAIL_PHIS\" : %u,\n", msVal[1]);
	printf("\t\"TOTAL_PAGE_FILE\" : %u,\n", msVal[2]);
	printf("\t\"AVAIL_PAGE_FILE\" : %u,\n", msVal[3]);
	printf("\t\"TOTAL_VIRTUAL\" : %u,\n", msVal[4]);
	printf("\t\"AVAIL_VIRTUAL\" : %u\n}\n", msVal[5]);
}

void ProcessDrivesInfo(void* buf)
{
	printf("%s\n", (char*)buf);
}

void ProcessAccess(void* buf)
{
	printf("%s\n", (char*)buf);
}

void ProcessOwner(void* buf)
{
	printf("%s\n", (char*)buf);
}

void SendRequest(uint32_t cmd, char* arg, int serv_num)
{
	if (servs[serv_num].sock == INVALID_SOCKET)
	{
		printf("Error: no connection is established\n");
		return;
	}

	memset(ioBuf, 0, sizeof(ioBuf));

	memcpy((BYTE*)ioBuf + sizeof(uint32_t), &cmd, sizeof(cmd));
	uint32_t uiDataLen = sizeof(uint32_t);

	if (arg != NULL)
	{
		strcpy((char*)((BYTE*)ioBuf + 2 * sizeof(uint32_t)), arg);
		uiDataLen += strlen(arg) + 1;
	}

	DWORD dwDataLen = uiDataLen;
	if (CryptEncrypt(servs[serv_num].hSessionKey, NULL, 1, 0, ((BYTE*)ioBuf) + sizeof(uint32_t), &dwDataLen, IO_BUF_SIZE - sizeof(uint32_t)) == 0)
	{
		printf("Error: CryptEncrypt (line: %d, error: %d)\n", __LINE__, GetLastError());
		DeinitEverything();
		exit(-1);
	}

	*((uint32_t*)ioBuf) = dwDataLen;

	if (send(servs[serv_num].sock, ioBuf, dwDataLen + sizeof(uint32_t), 0) == SOCKET_ERROR)
	{
		printf("Error: send (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}
}

void ProcessResponce(uint32_t cmd, int serv_num)
{
	if ((servs[serv_num].sock == INVALID_SOCKET) || (!servs[serv_num].isConnected))
	{
		printf("Error: no connection is established\n");
		return;
	}

	memset(ioBuf, 0, sizeof(ioBuf));

	if (recv(servs[serv_num].sock, ioBuf, sizeof(ioBuf), 0) == SOCKET_ERROR)
	{
		printf("Error: recv (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}

	uint32_t uiSzCipherText = *((uint32_t*)ioBuf);
	DWORD dwSzCipherText = uiSzCipherText;

	if (CryptDecrypt(servs[serv_num].hSessionKey, 0, 1, 0, ((BYTE*)(ioBuf)) + sizeof(uint32_t), &dwSzCipherText) == 0)
	{
		printf("Error: CryptDecrypt (line: %d, error: %d)\n", __LINE__, GetLastError());
		DeinitEverything();
		exit(-1);
	}

	void* bufResponce = ((BYTE*)(ioBuf)) + sizeof(uint32_t);

	switch (cmd)
	{
	case CMD_OS_INFO:
		ProcessInfoOsVersion(bufResponce);
		break;

	case CMD_CURRENT_TIME:
		ProcessCurrentTime(bufResponce);
		break;

	case CMD_TIME_SINCE_OS_STARTUP:
		ProcessTimeElapsedSinceOsStartup(bufResponce);
		break;

	case CMD_USED_MEMORY:
		ProcessMemoryStatus(bufResponce);
		break;

	case CMD_DRIVES_INFO:
		ProcessDrivesInfo(bufResponce);
		break;

	case CMD_ACCESS_RIGHTS:
		ProcessAccess(bufResponce);
		break;

	case CMD_OWNER:
		ProcessOwner(bufResponce);
		break;
	}
}

void Disconnect(int serv_num)
{
	if (servs[serv_num].sock == INVALID_SOCKET)
	{
		return;
	}

	if (servs[serv_num].isConnected)
	{
		memset(ioBuf, 0, sizeof(ioBuf));

		uint32_t cmd = CMD_DISCONNECT;
		memcpy((BYTE*)ioBuf + sizeof(uint32_t), &cmd, sizeof(cmd));

		DWORD dataLen = sizeof(uint32_t);
		if (CryptEncrypt(servs[serv_num].hSessionKey, NULL, 1, 0, ((BYTE*)ioBuf) + sizeof(uint32_t), &dataLen, IO_BUF_SIZE - sizeof(uint32_t)) == 0)
		{
			printf("Error: CryptEncrypt (line: %d, error: %d)\n", __LINE__, GetLastError());
			DeinitEverything();
			exit(-1);
		}

		*((uint32_t*)ioBuf) = dataLen;

		if (send(servs[serv_num].sock, ioBuf, dataLen + sizeof(uint32_t), 0) == SOCKET_ERROR)
		{
			printf("Error: send (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
			DeinitEverything();
			exit(-1);
		}

		servs[serv_num].isConnected = 0;
		printf("{\n\t\"Connection\" : false\n}\n");
	}

	shutdown(servs[serv_num].sock, SD_BOTH);
	closesocket(servs[serv_num].sock);
	servs[serv_num].sock = INVALID_SOCKET;
}

void EstablishConnection(char* ip, char* port)
{
	if (servs[serv_cnt].sock != INVALID_SOCKET)
	{
		Disconnect(serv_cnt);
	}

	servs[serv_cnt].sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (servs[serv_cnt].sock == INVALID_SOCKET)
	{
		printf("Error: socket (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	if (inet_pton(AF_INET, ip, &addr.sin_addr.s_addr) != 1)
	{
		printf("Error: inet_pton (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}

	if (connect(servs[serv_cnt].sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		printf("Error: connect (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		exit(-1);
	}

	memset(ioBuf, 0, sizeof(ioBuf));
	uint32_t uiSzIoBuf = IO_BUF_SIZE - sizeof(uint32_t);
	ExportPublicKey((BYTE*)ioBuf + sizeof(uint32_t), &uiSzIoBuf, serv_cnt);
	*((uint32_t*)ioBuf) = uiSzIoBuf;

	if (send(servs[serv_cnt].sock, ioBuf, uiSzIoBuf + sizeof(uint32_t), 0) == SOCKET_ERROR)
	{
		printf("Error: send (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}

	if (recv(servs[serv_cnt].sock, ioBuf, sizeof(ioBuf), 0) == SOCKET_ERROR)
	{
		printf("Error: recv (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
		DeinitEverything();
		exit(-1);
	}

	if (CryptImportKey(servs[serv_cnt].hCryptProv, ((BYTE*)(ioBuf)) + sizeof(uint32_t), *((uint32_t*)ioBuf), servs[serv_cnt].hExchangeKeyPair, 0, &servs[serv_cnt].hSessionKey) == 0)
	{
		printf("Error: CryptImportKey (line: %d, error: %d)\n", __LINE__, GetLastError());
		DeinitEverything();
		exit(-1);
	}

	printf("{\n\t\"Connection\" : true\n}\n");

	servs[serv_cnt].isConnected = 1;
	serv_cnt++;
}

void DeinitIo()
{
	for (int i = 0; i < MAX_SERV_CNT; i++) {
		if (servs[i].sock != INVALID_SOCKET)
		{
			Disconnect(i);
		}
	}

	WSACleanup();
}

void DeinitEverything()
{
	for (int i = 0; i < serv_cnt; i++) {
		Disconnect(i);
	}
	for (int i = 0; i < serv_cnt; i++) {
		DeinitCrypt(i);
	}
	DeinitIo();
}

commandNames parseCommand(char* command, char** argv) {

	int args_qnt = MAX_CMD_ARGUMENTS_QNT;

	argv[0] = strtok(command, " \n");
	for (int i = 1; i < MAX_CMD_ARGUMENTS_QNT; i++) {

		argv[i] = strtok(NULL, " \n");

		if (argv[i] == NULL) {

			args_qnt = i;
			break;
		}
	}

	if (argv[0] == NULL)
		return (unknown);
	else if (strcmp(argv[0], "os") == NULL)
		return (getOsVer);
	else if (strcmp(argv[0], "ms") == NULL)
		return (getMemoryStatus);
	else if (strcmp(argv[0], "ct") == NULL)
		return (getCurrentTime);
	else if (strcmp(argv[0], "connect") == NULL)
		return (connect_);
	else if (strcmp(argv[0], "help") == NULL)
		return (help);
	else if (strcmp(argv[0], "st") == NULL)
		return (getTimeSinceOsStartup);
	else if (strcmp(argv[0], "exit") == NULL)
		return (exit_);
	else if (strcmp(argv[0], "di") == NULL)
		return (getDrivesInfo);
	else if (strcmp(argv[0], "ar") == NULL)
		return (getAccessRights);
	else if (strcmp(argv[0], "ow") == NULL)
		return (getOwner);
	else
		return (unknown);
}

void PrintCommandList() {
	printf("\nHelp list:\n");
	printf("\tCOMMON\n");
	printf("\t\thelp - show Help list\n");
	printf("\t\tconnect <ip> <port> - connect to the server\n");
	printf("\t\texit - disconnect and exit programm\n");
	printf("\tTIME\n");
	printf("\t\tct <serv_num> - request current time from the server\n");
	printf("\t\tst <serv_num> - request time since OS startup from the server\n");
	printf("\tOS_DRIVES\n");
	printf("\t\tos <serv_num> - request OS info from the server\n");
	printf("\t\tms <serv_num> - request memory status from the server\n");
	printf("\t\tdi <serv_num> - request drives info from the server\n");
	printf("\tFILES\n");
	printf("\t\tar <path> <serv_num> - request access rights from the server\n");
	printf("\t\tow <path> <serv_num> - request owner from the server\n");
	printf("\n");
}

int main()
{
	setlocale(LC_ALL, "Russian");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	int serv_num;
	serv_cnt = 0;

	InitCrypt();
	
	//init IO
	int i;
	for (i = 0; i < MAX_SERV_CNT; i++) {
		servs[i].isConnected = 0;

		servs[i].sock = INVALID_SOCKET;

		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
		{
			printf("Error: WSAStartup (line: %d, WSA error: %d)\n", __LINE__, WSAGetLastError());
			DeinitEverything();
			exit(-1);
		}
	}

	PrintCommandList();

	char command[1000];
	char* argv[MAX_CMD_ARGUMENTS_QNT];

	commandNames curCommand;

	while (1) {

		memset((void*)argv, 0, sizeof(char*) * MAX_CMD_ARGUMENTS_QNT);

		printf("\nEnter command: ");
		fgets(command, sizeof(command), stdin);
		curCommand = parseCommand(command, argv);

		//проверка на serv_cnt
		if (curCommand != connect_ && curCommand != help && curCommand != exit_ && curCommand != unknown) {
			if (curCommand == getAccessRights || curCommand == getOwner)
				serv_num = atoi(argv[2]);
			else
				serv_num = atoi(argv[1]);
			if (serv_cnt == 0) {
				printf("Need connection!\n");
				continue;
			}
		}

		switch (curCommand) {

		case connect_:
			EstablishConnection(argv[1], argv[2]);
			break;

		case getOsVer:
			SendRequest(CMD_OS_INFO, NULL, serv_num);
			ProcessResponce(CMD_OS_INFO, serv_num);
			break;

		case getCurrentTime:
			SendRequest(CMD_CURRENT_TIME, NULL, serv_num);
			ProcessResponce(CMD_CURRENT_TIME, serv_num);
			break;

		case getTimeSinceOsStartup:
			SendRequest(CMD_TIME_SINCE_OS_STARTUP, NULL, serv_num);
			ProcessResponce(CMD_TIME_SINCE_OS_STARTUP, serv_num);
			break;

		case getMemoryStatus:
			SendRequest(CMD_USED_MEMORY, NULL, serv_num);
			ProcessResponce(CMD_USED_MEMORY, serv_num);
			break;

		case getDrivesInfo:
			SendRequest(CMD_DRIVES_INFO, NULL, serv_num);
			ProcessResponce(CMD_DRIVES_INFO, serv_num);
			break;


		case getAccessRights:
			SendRequest(CMD_ACCESS_RIGHTS, argv[1], serv_num);
			ProcessResponce(CMD_ACCESS_RIGHTS, serv_num);
			break;

		case getOwner:
			SendRequest(CMD_OWNER, argv[1], serv_num);
			ProcessResponce(CMD_OWNER, serv_num);
			break;

		case help:
			PrintCommandList();
			break;

		case exit_:
			DeinitEverything();
			exit(0);
			break;

		case unknown:
			printf("\nUnknown command\n");
			break;

		default:
			printf("\n\n\nUnknown case constant\n\n\n");
			break;
		}
	}

	return 0;
}