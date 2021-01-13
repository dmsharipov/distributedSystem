#include "serv_func.h"
#include "crypt_func.h"

HCRYPTPROV hCryptProv;

void MyHandleError(LPCTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	DeinitEverything();
	exit(1);
}

void InitCrypt()
{
	// The name of the container.
	LPCTSTR pszContainerName = TEXT("MyContainer");

	//---------------------------------------------------------------
	// Begin processing. Attempt to acquire a context by using the 
	// specified key container.
	if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, 0))
	{
		//_tprintf( TEXT("A crypto context with the %s key container has been acquired.\n"), pszContainerName);
	}
	else
	{
		//-----------------------------------------------------------
		// Some sort of error occurred in acquiring the context. 
		// This is most likely due to the specified container 
		// not existing. Create a new key container.
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				_tprintf(TEXT("A new key container has been created.\n"));
			}
			else
			{
				MyHandleError(TEXT("Could not create a new key container.\n"));
			}
		}
		else
		{
			MyHandleError(TEXT("CryptAcquireContext failed.\n"));
		}
	}
}

void DeinitCrypt()
{
	for (unsigned int i = 0; i < MAX_CLIENTS_QNT; i++)
	{
		if (cliCtxs[i].socket != 0)
		{
			if (cliCtxs[i].hSessionKey)
			{
				if (!(CryptDestroyKey(cliCtxs[i].hSessionKey)))
				{
					printf("Warning: CryptDestroyKey failed on session key of client %d (line: %d, error: %d)\n", i, __LINE__, GetLastError());
				}

				cliCtxs[i].hSessionKey = NULL;
			}
		}
	}

	// Release the CSP.
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			MyHandleError(TEXT("Error during CryptReleaseContext."));
		}
	}
}

//
// pSzBlob is a pointer to size of buffer pointed by pBuf
int ExportSessionKey(void* pBuf, uint32_t* pSzBlob, HCRYPTKEY hPublicKey, HCRYPTKEY hSessionKey)
{
	DWORD szBlobSessionKey;

	if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, NULL, &szBlobSessionKey) == 0)
	{
		MyHandleError(TEXT("Can't get expected blob size for exporting of session key"));
	}

	if (*pSzBlob < szBlobSessionKey)
	{
		printf("Expected blob size is greater then allocated blob size\n");
		return -1;
	}

	if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, (BYTE*)pBuf, &szBlobSessionKey) == 0)
	{
		MyHandleError(TEXT("Can't export session key"));
	}

	*pSzBlob = szBlobSessionKey;

	return 0;
}