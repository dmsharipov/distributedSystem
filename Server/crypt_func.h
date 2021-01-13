#pragma once

#include <windows.h>  
#include <Wincrypt.h>
#include <tchar.h>
#include <stdio.h>
#include "common.h"

#pragma comment(lib, "crypt32.lib")

extern HCRYPTPROV hCryptProv;

void InitCrypt();
void DeinitCrypt();
int ExportSessionKey(void* pBuf, uint32_t* pSzBlob, HCRYPTKEY hPublicKey, HCRYPTKEY hSessionKey);