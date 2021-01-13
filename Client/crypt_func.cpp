#include "crypt_func.h"
#include "serv_struct.h"

void MyHandleError(LPCTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	DeinitEverything();
	exit(1);
}

//
// pSzBlob is a pointer to size of buffer pointed by pBuf
void ExportPublicKey(void* pBuf, uint32_t* pUiSzBlob, int serv_num)
{
	DWORD dwSzBlob = *pUiSzBlob;

	if (CryptExportKey(servs[serv_num].hExchangeKeyPair, 0, PUBLICKEYBLOB, 0, (BYTE*)pBuf, &dwSzBlob) == FALSE)
	{
		printf("\nError: CryptExportKey error: %d\n(line %d, function %s)\n\n", GetLastError(), __LINE__, __func__);
		DeinitCrypt(serv_num);
		exit(-1);
	}

	*pUiSzBlob = dwSzBlob;
}

void InitCrypt()
{
	for (int i = 0; i < MAX_SERV_CNT; i++) {
		// The name of the container.
		LPCTSTR pszContainerName = TEXT("MyContainer");

		//---------------------------------------------------------------
		// Begin processing. Attempt to acquire a context by using the 
		// specified key container.
		if (CryptAcquireContext(&servs[i].hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, 0))
		{
			//_tprintf(TEXT("A crypto context with the %s key container has been acquired.\n"), pszContainerName);
		}
		else
		{
			//-----------------------------------------------------------
			// Some sort of error occurred in acquiring the context. 
			// This is most likely due to the specified container 
			// not existing. Create a new key container.
			if (GetLastError() == NTE_BAD_KEYSET)
			{
				if (CryptAcquireContext(&servs[i].hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				{
					//_tprintf(TEXT("A new key container has been created.\n"));
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

		//---------------------------------------------------------------
		// A context with a key container is available.
		// Attempt to get the handle to the exchange key. 

		// Check the exchange key. 
		if (CryptGetUserKey(servs[i].hCryptProv, AT_KEYEXCHANGE, &servs[i].hExchangeKeyPair))
		{
			//_tprintf(TEXT("An exchange key exists.\n"));
		}
		else
		{
			_tprintf(TEXT("No exchange key is available.\n"));

			// Check to determine whether an exchange key 
			// needs to be created.
			if (GetLastError() == NTE_NO_KEY)
			{
				// Create a key exchange key pair.
				_tprintf(TEXT("The exchange key does not exist.\n"));
				_tprintf(TEXT("Attempting to create an exchange key pair.\n"));

				if (CryptGenKey(servs[i].hCryptProv, AT_KEYEXCHANGE, 0, &servs[i].hExchangeKeyPair))
				{
					_tprintf(TEXT("Exchange key pair created.\n"));
				}
				else
				{
					MyHandleError(TEXT("Error occurred attempting to create an exchange key.\n"));

				}
			}
			else
			{
				MyHandleError(TEXT("An error other than NTE_NO_KEY occurred.\n"));
			}
		}
	}
}

void DeinitCrypt(int serv_num)
{
	if (servs[serv_num].hExchangeKeyPair)
	{
		if (!(CryptDestroyKey(servs[serv_num].hExchangeKeyPair)))
		{
			printf("Warning: CryptDestroyKey failed on hExchangeKeyPair (line: %d, error: %d)\n", __LINE__, GetLastError());
		}

		servs[serv_num].hExchangeKeyPair = NULL;
	}

	if (servs[serv_num].hSessionKey)
	{
		if (!(CryptDestroyKey(servs[serv_num].hSessionKey)))
		{
			printf("Warning: CryptDestroyKey failed on hSessionKey (line: %d, error: %d)\n", __LINE__, GetLastError());
		}

		servs[serv_num].hSessionKey = NULL;
	}

	// Release the CSP.
	if (servs[serv_num].hCryptProv)
	{
		if (!(CryptReleaseContext(servs[serv_num].hCryptProv, 0)))
		{
			MyHandleError(TEXT("Error during CryptReleaseContext."));
		}
	}
}