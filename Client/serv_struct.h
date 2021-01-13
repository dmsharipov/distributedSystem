#pragma once
//#include "crypt_func.h"
#include "common.h"

typedef struct serv_st {
	bool isConnected;
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hExchangeKeyPair;
	HCRYPTKEY hSessionKey;
	SOCKET sock;
} SERV;

extern SERV servs[MAX_SERV_CNT];