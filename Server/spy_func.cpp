#include "spy_func.h"
#include "common.h"

void GetOsVersion(char* buf, uint32_t* pSzPlainText)
{
	if (IsWindows10OrGreater())
	{
		sprintf(buf, "Windows 10");
	}
	else if (IsWindows8Point1OrGreater())
	{
		sprintf(buf, "Windows 8.1");
	}
	else if (IsWindows8OrGreater())
	{
		sprintf(buf, "Windows 8");
	}
	else if (IsWindows7SP1OrGreater())
	{
		sprintf(buf, "Windows 7 SP1");
	}
	else if (IsWindows7OrGreater())
	{
		sprintf(buf, "Windows 7");
	}
	else if (IsWindowsVistaSP2OrGreater())
	{
		sprintf(buf, "Windows Vista SP2");
	}
	else if (IsWindowsVistaSP1OrGreater())
	{
		sprintf(buf, "Windows Vista SP1");
	}
	else if (IsWindowsVistaOrGreater())
	{
		sprintf(buf, "Windows Vista");
	}
	else if (IsWindowsXPSP3OrGreater())
	{
		sprintf(buf, "Windows XP SP3");
	}
	else if (IsWindowsXPSP2OrGreater())
	{
		sprintf(buf, "Windows XP SP2");
	}
	else if (IsWindowsXPSP1OrGreater())
	{
		sprintf(buf, "Windows XP SP1");
	}
	else if (IsWindowsXPOrGreater())
	{
		sprintf(buf, "Windows XP");
	}
	else
	{
		printf("Error: can't get Windows version");
	}

	*pSzPlainText = strlen(buf) + 1;
}

void GetTimeElapsedSinceOsStartup(char* buf, uint32_t* pSzPlainText)
{
	timeSinceOsStartup t;

	t.msec = GetTickCount();
	t.hour = t.msec / (1000 * 60 * 60);
	t.min = t.msec / (1000 * 60) - t.hour * 60;
	t.sec = (t.msec / 1000) - (t.hour * 60 * 60) - t.min * 60;

	sprintf(buf, "%d:%02d:%02d.%03d", t.hour, t.min, t.sec, t.msec % 1000);

	*pSzPlainText = strlen(buf) + 1;
}

void GetCurrTime(char* buf, uint32_t* pSzPlainText)
{
	time_t timer;
	struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);

	strftime(buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	*pSzPlainText = strlen(buf) + 1;
}

void GetMemoryStatus(char* buf, uint32_t* pSzPlainText)
{
	MEMORYSTATUSEX ms;
	ms.dwLength = sizeof(MEMORYSTATUSEX);

	uint64_t* msVal = (uint64_t*)buf;

	if (!GlobalMemoryStatusEx(&ms))
	{
		printf("Error: recv(line : % d, error : % d)\n", __LINE__, GetLastError());
		memset(buf, 0xFF, sizeof(uint64_t) * 6);
	}
	else
	{
		msVal[0] = ms.ullTotalPhys;
		msVal[1] = ms.ullAvailPhys;
		msVal[2] = ms.ullTotalPageFile;
		msVal[3] = ms.ullAvailPageFile;
		msVal[4] = ms.ullTotalVirtual;
		msVal[5] = ms.ullAvailVirtual;
	}

	*pSzPlainText = sizeof(uint64_t) * 6;
}

void GetDrivesInfo(char* buf, uint32_t* pSzPlainText)
{
	DWORD drives = GetLogicalDrives();
	WCHAR driveName[26][4] = { 0 };
	WCHAR FileSystemName[100];
	DWORD SectorsPerCluster, BytesPerSector, NumberOfFreeClusters, TotalNumberOfClusters;
	unsigned count = 0;

	for (unsigned i = 0; i < 26; i++)
	{
		if ((drives & (1 << i)))
		{
			driveName[count][0] = WCHAR(65 + i);
			driveName[count][1] = ':';
			driveName[count][2] = '\\';
			count++;
		}
	}

	for (unsigned i = 0; i < count; i++)
	{
		sprintf(buf + strlen(buf), "{\n\t\"DRIVE_NAME\" : \"");
		for (int j = 0; j < 3; j++)
		{
			sprintf(buf + strlen(buf), "%lc", driveName[i][j]);
		}
		sprintf(buf + strlen(buf), "\",\n");

		switch (GetDriveTypeW((LPWSTR)driveName[i]))
		{

		case DRIVE_UNKNOWN:
			sprintf(buf + strlen(buf), "\t\"TYPE\" : \"unknown_drive\",\n");
			break;

		case DRIVE_FIXED:
			sprintf(buf + strlen(buf), "\t\"TYPE\" : \"hard_disk_drive\",\n");
			break;

		case DRIVE_REMOTE:
			sprintf(buf + strlen(buf), "\t\"TYPE\" : \"remote_drive\",\n");
			break;

		case DRIVE_CDROM:
			sprintf(buf + strlen(buf), "\t\"TYPE\" : \"CD-ROM_drive\",\n");
			break;

		case DRIVE_RAMDISK:
			sprintf(buf + strlen(buf), "\t\"TYPE\" : \"RAM_disk\",\n");
			break;
		}

		// Getting file sistem type
		GetVolumeInformationW((LPWSTR)driveName[i], NULL, NULL, NULL, NULL, NULL, FileSystemName, 100);

		if (!wcscmp(FileSystemName, L"NTFS"))
		{
			sprintf(buf + strlen(buf), "\t\"FILE_SYSTEM\" : \"NTFS\",\n");
		}
		if (!wcscmp(FileSystemName, L"FAT"))
		{
			sprintf(buf + strlen(buf), "\t\"FILE_SYSTEM\" : \"FAT\",\n");
		}
		if (!wcscmp(FileSystemName, L"CDFS"))
		{
			sprintf(buf + strlen(buf), "\t\"FILE_SYSTEM\" : \"CDFS\",\n");
		}

		GetDiskFreeSpaceW((LPWSTR)driveName[i], &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters, &TotalNumberOfClusters);

		sprintf(buf + strlen(buf), "\t\"FREE_SPACE\" : \"%f GBytes\"\n}\n", (double)NumberOfFreeClusters * (double)SectorsPerCluster * (double)BytesPerSector / 1024.0 / 1024.0 / 1024.0);

		*pSzPlainText = strlen(buf) + 1;
	}
}

void GetAccessRights(char* cBuf, char* cPath, uint32_t* pSzPlainText)
{
	size_t newsize = strlen(cPath) + 1;

	wchar_t* path = new wchar_t[newsize];

	size_t convertedChars = 0;

	mbstowcs_s(&convertedChars, path, strlen(cPath) + 1, cPath, _TRUNCATE);
	bool key = false;

	char* root__ = strtok(cPath, "\\");

	if (!strcmp(root__, "HKEY_CLASSES_ROOT"))
	{
		key = TRUE;
	}
	else if (!strcmp(root__, "HKEY_CURRENT_USER"))
	{
		key = TRUE;
	}
	else if (!strcmp(root__, "HKEY_LOCAL_MACHINE"))
	{
		key = TRUE;
	}
	else if (!strcmp(root__, "HKEY_USERS"))
	{
		key = TRUE;
	}
	else if (!strcmp(root__, "HKEY_CURRENT_CONFIG"))
	{
		key = TRUE;
	}
	else
	{
		key = FALSE;
	}

	PACL pDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	ACL_SIZE_INFORMATION aclSzInfo;				// class needed information from ACL
	SID_NAME_USE sid_nu;						//  contains values that specify the type of a security indentifier (SID)
	DWORD len = 200;							// lenght of username and domain
	wchar_t* subkey = NULL, *root = NULL;		// buf for key path

	WCHAR* buf = new WCHAR[IO_BUF_SIZE];
	memset(buf, 0, sizeof(WCHAR) * IO_BUF_SIZE);

	if (!key)
	{
		// processing file/folder
		if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"Get security information error\n");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] path;
			delete[] buf;
			return;
		}
	}
	else if (key)
	{
		// processing registry key

		HKEY hKey;
		wchar_t div[] = L"\\";
		root = wcstok(path, div, &subkey); // store type of key

		if (!wcscmp(root, L"HKEY_CLASSES_ROOT"))
			RegOpenKeyW(HKEY_CLASSES_ROOT, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_CURRENT_USER"))
			RegOpenKeyW(HKEY_CURRENT_USER, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_LOCAL_MACHINE"))
			RegOpenKeyW(HKEY_LOCAL_MACHINE, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_USERS"))
			RegOpenKeyW(HKEY_USERS, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_CURRENT_CONFIG"))
			RegOpenKeyW(HKEY_CURRENT_CONFIG, subkey, &hKey);
		else
		{
			swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"RegOpenKey Error\"\n}");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] path;
			delete[] buf;
			return;
		}

		if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"Get security information error\"\n}");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] path;
			delete[] buf;
			return;
		}
	}

	if (pDACL == NULL)
	{
		swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"ACL list is empty\"\n}");
		wcstombs(cBuf, buf, wcslen(buf));
		delete[] path;
		delete[] buf;
		return;
	}

	if (!GetAclInformation(pDACL, &aclSzInfo, sizeof(aclSzInfo), AclSizeInformation))
	{
		swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"Can't get ACL info\"\n}");
		wcstombs(cBuf, buf, wcslen(buf));
		delete[] path;
		delete[] buf;
		return;
	}

	// Цикл перебора всех ACL-записей
	for (DWORD i = 0; i < aclSzInfo.AceCount; i++)
	{
		LPWSTR user = new WCHAR[200], domain = new WCHAR[200];
		void* ace;
		// Получить текущую запись
		if (GetAce(pDACL, i, &ace))
		{
			PSID* pSID = (PSID*) & ((ACCESS_ALLOWED_ACE*)ace)->SidStart;
			if (LookupAccountSidW(NULL, pSID, user, (LPDWORD)&len, domain, &len, &sid_nu))
			{
				LPWSTR StringSid = NULL;
				ConvertSidToStringSidW(pSID, &StringSid);
				swprintf(buf + wcslen(buf), L"{\n\t\"SID\" : \"%ls\",\n", StringSid);
				swprintf(buf + wcslen(buf), L"\t\"ACCOUNT\" : \"%ls\",\n", user);

				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
					swprintf(buf + wcslen(buf), L"\t\"ALLOWED_ACE\" : [\n");
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
					swprintf(buf + wcslen(buf), L"\t\t\"Denied_ACE\",\n");
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
					swprintf(buf + wcslen(buf), L"\t\t\"System_Alarm_ACE\",\n");
				if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
					swprintf(buf + wcslen(buf), L"\t\t\"System_Audit_ACE\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & WRITE_OWNER) == WRITE_OWNER)
					swprintf(buf + wcslen(buf), L"\t\t\"Change_Owner\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & WRITE_DAC) == WRITE_DAC)
					swprintf(buf + wcslen(buf), L"\t\t\"Write_DAC\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & DELETE) == DELETE)
					swprintf(buf + wcslen(buf), L"\t\t\"Delete\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
					swprintf(buf + wcslen(buf), L"\t\t\"Read\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
					swprintf(buf + wcslen(buf), L"\t\t\"Write\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
					swprintf(buf + wcslen(buf), L"\t\t\"Execute\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & SYNCHRONIZE) == SYNCHRONIZE)
					swprintf(buf + wcslen(buf), L"\t\t\"Synchronize\",\n");
				if ((((ACCESS_ALLOWED_ACE*)ace)->Mask & READ_CONTROL) == READ_CONTROL)
					swprintf(buf + wcslen(buf), L"\t\t\"Read control\",\n");
				swprintf(buf + wcslen(buf), L"\t]\n}");
			}
		}
		delete[] user;
		delete[] domain;
	}

	wcstombs(cBuf, buf, wcslen(buf));

	delete[] path;
	delete[] buf;
}

void GetOwner(char* cBuf, char* cPath, uint32_t* pSzPlainText)
{
	size_t newsize = strlen(cPath) + 1;
	wchar_t* path = new wchar_t[newsize];

	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, path, strlen(cPath) + 1, cPath, _TRUNCATE);

	bool key = false;

	char* root__ = strtok(cPath, "\\");

	if (!strcmp(root__, "HKEY_CLASSES_ROOT"))
		key = TRUE;
	else if (!strcmp(root__, "HKEY_CURRENT_USER"))
		key = TRUE;
	else if (!strcmp(root__, "HKEY_LOCAL_MACHINE"))
		key = TRUE;
	else if (!strcmp(root__, "HKEY_USERS"))
		key = TRUE;
	else if (!strcmp(root__, "HKEY_CURRENT_CONFIG"))
		key = TRUE;
	else
	{
		key = FALSE;
	}

	PSID pOwnerSid = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	SID_NAME_USE sid_nu;
	wchar_t* subkey = NULL, *root = NULL;
	DWORD len = 200;
	LPWSTR user = new WCHAR[200], domain = new WCHAR[200];

	WCHAR* buf = new WCHAR[IO_BUF_SIZE];
	memset(buf, 0, sizeof(WCHAR) * IO_BUF_SIZE);

	if (!key) // processing file/folder
	{
		if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
			&pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"Get_security_information_error\"\n}");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] user;
			delete[] domain;
			delete[] path;
			delete[] buf;
			return;
		}
	}
	else if (key) // processing registry key
	{
		HKEY hKey;
		wchar_t div[] = L"\\";
		root = wcstok(path, div, &subkey); // store type of key

		if (!wcscmp(root, L"HKEY_CLASSES_ROOT"))
			RegOpenKeyW(HKEY_CLASSES_ROOT, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_CURRENT_USER"))
			RegOpenKeyW(HKEY_CURRENT_USER, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_LOCAL_MACHINE"))
			RegOpenKeyW(HKEY_LOCAL_MACHINE, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_USERS"))
			RegOpenKeyW(HKEY_USERS, subkey, &hKey);
		else if (!wcscmp(root, L"HKEY_CURRENT_CONFIG"))
			RegOpenKeyW(HKEY_CURRENT_CONFIG, subkey, &hKey);
		else
		{
			swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"RegOpenKey_Error\"\n}");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] user;
			delete[] domain;
			delete[] path;
			delete[] buf;
			return;
		}

		if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
			&pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"{\n\t\"ERROR\" : \"Get_security_information_error\"\n}");
			wcstombs(cBuf, buf, wcslen(buf));
			delete[] user;
			delete[] domain;
			delete[] path;
			delete[] buf;
			return;
		}

	}

	if (pSD == NULL)
	{
		swprintf(buf + wcslen(buf), L"\n\t\"ERROR\" : \"Security_descriptor_is_empty\"\n}");
		wcstombs(cBuf, buf, wcslen(buf));
		delete[] user;
		delete[] domain;
		delete[] path;
		delete[] buf;
		return;
	}
	LookupAccountSidW(NULL, pOwnerSid, user, (LPDWORD)&len, domain, &len, &sid_nu);

	LPWSTR StringSid = NULL;
	ConvertSidToStringSidW(pOwnerSid, &StringSid);
	swprintf(buf + wcslen(buf), L"{\n\t\"SID\" : \"%ls\",\n", StringSid);
	swprintf(buf + wcslen(buf), L"\t\"ACCOUNT\" : \"%ls\"\n}", user);

	delete[] user;
	delete[] domain;

	wcstombs(cBuf, buf, wcslen(buf));

	delete[] path;
	delete[] buf;
}