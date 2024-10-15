/* Header file for AES Decryption (all cryptographic functions are stack spoofed) */

#pragma once

#include <windows.h>
#include <iostream>

#include "functions.h"
#include "retaddrspoof.h"

#define KEYSIZE 32
#define IVSIZE 16

extern PVOID Gdgt;

/* AES Datatype Structure Definition */

typedef struct AES {

	PBYTE pPlainText; // Array Will Recieve Decrypted Data
	DWORD plainTextSize; // DWORD Variable Will Recieve The Size of Decrypted Data

	PBYTE pCipherText; // Array of Encrypted Data
	DWORD CipherSize; // The sizeof encrypted data

	PBYTE KEY; // 32 Byte AES Key to be used in decryption
	PBYTE IV; // 16 Byte AES IV to be used in decryption
}AES, * PAES;


/* ---------------------------------- */


/// <summary>
/// an Internal Function that Performs the AES Decryption using a Provided Pointer to an Initialized AES Structure
/// </summary>
/// <param name="pAES"></param>
/// <returns></returns>
BOOL InternalAESDecrypt(PAES pAES) {
	BOOL bSTATE = TRUE;

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;

	BCRYPT_KEY_HANDLE hKeyHandle = NULL;

	ULONG cbResult = NULL;

	DWORD dwBlockSize = NULL;

	DWORD cbKeyObject = NULL;

	PBYTE pbKeyObject = NULL;

	PBYTE pbPlainText = NULL;

	DWORD cbPlainText = NULL;

	NTSTATUS STATUS = NULL;


	// Initialize the hAlgorithm Handle as an AES Algorithm
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptOpenAlgorithmProvider, 4, Gdgt, &hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0));
	if (STATUS != 0) {
		std::cout << "[-] BCryptOpenAlgorithmProvider Function Failed To Initialize Algorithm Handle" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// Get The Size of the KeyObject Variable to use Later with BCryptGenerateSymmetricKey Function
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptGetProperty, 6, Gdgt, hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0));
	if (STATUS != 0) {
		std::cout << "[-] BCryptGetProperty Function Failed To Get The Size of the KeyObject " << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}




	// Get the size of the block used in the encryption. Since this is AES it should be 16 bytes.
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptGetProperty, 6, Gdgt, hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0));
	if (STATUS != 0) {
		std::cout << "[-] BCryptGetProperty Function Failed To Get The Size of the Encryption Block" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// Check The Encryption Block Size (Should Always be 16)
	if (dwBlockSize != 16) {
		std::cout << "[-] Encryption Block Size Is Not 16" << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// Allocate Memory on The Heap For The Key ( man do i miss C# )
	pbKeyObject = (PBYTE)malloc(cbKeyObject);
	RtlSecureZeroMemory(pbKeyObject, cbKeyObject);
	if (pbKeyObject == NULL) {
		std::cout << "[-] malloc failed to allocate memory for the key" << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}



	// Configure The Block Cipher Mode (AES MODE) to CBC This uses a 32 byte key and a 16 byte IV.
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptSetProperty, 5, Gdgt, hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
	if (STATUS != 0) {
		std::cout << "[-] BCryptSetProperty Failed to Set The Encryption Mode To CBC" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}



	// Generating an AES Key Object from The Provided pAES Structure and Saving the Key Object to pbKeyObject and its size to cbKeyObject and Its Handle to hKeyHandle
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptGenerateSymmetricKey, 7, Gdgt , hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAES->KEY, KEYSIZE, 0));
	if (STATUS != 0) {
		std::cout << "[-] BCryptGenerateSymmetricKey Failed to Generate a Key Object" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// running BCryptDecrypt For First Time With NULL Parameters to retrieve the Size of the OutPut Buffer And Save 
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptDecrypt, 10, Gdgt , hKeyHandle, (PUCHAR)pAES->pCipherText, (ULONG)pAES->CipherSize, NULL, pAES->IV, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING));
	if (STATUS != 0) {
		std::cout << "[-] BCryptDecrypt Failed to Retrieve OutPut Buffer Size" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// Allocate Memory On The Heap For OutPut Buffer
	pbPlainText = (PBYTE)malloc(cbPlainText);
	RtlSecureZeroMemory(pbPlainText, cbPlainText);
	if (pbPlainText == NULL) {
		std::cout << "[-] malloc failed to allocate memory for the output buffer" << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


	// running BCryptDecrypt again Given The Allocated Buffer so it Puts The Decrypted data To It
	STATUS = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)e_BCryptDecrypt, 10, Gdgt, hKeyHandle, (PUCHAR)pAES->pCipherText, (ULONG)pAES->CipherSize, NULL, pAES->IV, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING));
	if (STATUS != 0) {
		std::cout << "[-] BCryptDecrypt Failed to Decrypt" << std::endl;
		std::cout << "[-] Error Code: " << STATUS << std::endl;
		bSTATE = FALSE; goto _CLEANUP;
	}


_CLEANUP:
	if (hKeyHandle)
		RetSpoofCall((void*) e_BCryptDestroyKey, 1, Gdgt , hKeyHandle);

	if (hAlgorithm)
		RetSpoofCall((void*)e_BCryptCloseAlgorithmProvider, 2, Gdgt, hAlgorithm, 0);

	if (pbKeyObject)
		free(pbKeyObject);

	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText to The AES Structure so we can access them later
		pAES->pPlainText = pbPlainText;
		pAES->plainTextSize = cbPlainText;
	}

	if (pbPlainText == NULL) {
		std::cout << "plain text buffer is NULL" << std::endl;
	}


	return bSTATE;
}



/// <summary>
/// AES Decrytion Function
/// </summary>
/// <returns>boolean Indicates a Successfull or a Failed Decryption Process</returns>
BOOL AESDecrypt(IN PBYTE EncryptedData, IN DWORD EncryptedDataSize, IN PBYTE KEY, IN PBYTE IV, OUT PVOID* pPlaintTextData, OUT PDWORD pPlaintTextSize) {


	if (EncryptedData == NULL || EncryptedDataSize == NULL || KEY == NULL || IV == NULL) {
		return FALSE;
	}

	// Initialize The AES Structure For Decryption

	AES Aes;

	Aes.KEY = KEY;
	Aes.IV = IV;
	Aes.pCipherText = EncryptedData;
	Aes.CipherSize = EncryptedDataSize;


	// Decrypt

	if (!InternalAESDecrypt(&Aes)) {
		return FALSE;
	}


	// If Decryption Successfull, 
	// Set the OUT Parameters of The Function to The Arrays Defined By The Caller to Save The Decrypted Data

	*pPlaintTextData = Aes.pPlainText;
	*pPlaintTextSize = Aes.plainTextSize;

	return TRUE;
}



