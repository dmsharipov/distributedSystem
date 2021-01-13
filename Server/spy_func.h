#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

#include <stdint.h> 
#include <stdio.h> 
#include <windows.h> 
#include <VersionHelpers.h>
#include <time.h>
#include <aclapi.h>
#include <Sddl.h>

struct timeSinceOsStartup
{
	DWORD msec;
	DWORD sec;
	DWORD min;
	DWORD hour;
};

void GetOsVersion(char* buf, uint32_t* pSzPlainText);
void GetTimeElapsedSinceOsStartup(char* buf, uint32_t* pSzPlainText);
void GetCurrTime(char* buf, uint32_t* pSzPlainText);
void GetMemoryStatus(char* buf, uint32_t* pSzPlainText);
void GetDrivesInfo(char* buf, uint32_t* pSzPlainText);
void GetAccessRights(char* cBuf, char* cPath, uint32_t* pSzPlainText);
void GetOwner(char* cBuf, char* cPath, uint32_t* pSzPlainText);