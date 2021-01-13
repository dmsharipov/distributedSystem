#pragma once

#include <windows.h>  
#include <Wincrypt.h>
#include <tchar.h>
#include <stdio.h>
#include <stdint.h>
#include "common.h"

#pragma comment(lib, "crypt32.lib")

void InitCrypt();
void DeinitCrypt(int serv_num);
void ExportPublicKey(void* pBuf, uint32_t* pUiSzBlob, int serv_num);
