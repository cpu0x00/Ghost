#pragma once
#include "structs.h"
#include "defs.h"




typedef NTSTATUS(NTAPI* fNtAllocateVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID            BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PSIZE_T           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect
	);



typedef NTSTATUS(NTAPI* fNtProtectVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID            BaseAddress,
	IN OUT PSIZE_T           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);



typedef NTSTATUS(NTAPI* fNtWriteVirtualMemory)(



	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN SIZE_T                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten
	);


typedef NTSTATUS(NTAPI* fNtReadVirtualMemory)(



	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN SIZE_T                NumberOfBytesToRead,
	OUT PSIZE_T              NumberOfBytesReaded OPTIONAL);





typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
	);


typedef NTSTATUS(NTAPI* fNtCreateEvent)(

	OUT PHANDLE             EventHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN PVOID                ObjectAttributes OPTIONAL,
	IN PVOID                EventType,
	IN BOOLEAN              InitialState
	);




typedef NTSTATUS(NTAPI* fRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING ImagePathName,
	PUNICODE_STRING DllPath,
	PUNICODE_STRING CurrentDirectory,
	PUNICODE_STRING CommandLine,
	PVOID Environment,
	PUNICODE_STRING WindowTitle,
	PUNICODE_STRING DesktopInfo,
	PUNICODE_STRING ShellInfo,
	PUNICODE_STRING RuntimeData,
	ULONG Flags
	);

typedef VOID(NTAPI* fRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);






typedef LPVOID(WINAPI* fnConvertThreadToFiber)(
	LPVOID lpParameter
	);


typedef LPVOID(WINAPI* fnCreateFiber)(
	SIZE_T                dwStackSize,
	LPFIBER_START_ROUTINE lpStartAddress,
	LPVOID                lpParameter
	);


typedef void(WINAPI* fnSwitchToFiber) (
	LPVOID lpFiber
	);




typedef HRSRC(WINAPI* fnFindResourceW)(
	HMODULE hModule,
	LPCWSTR lpName,
	LPCWSTR lpType
	);


typedef HGLOBAL(WINAPI* fnLoadResource)(
	HMODULE hModule,
	HRSRC   hResInfo
	);


typedef LPVOID(WINAPI* fnLockResource)(
	HGLOBAL hResData
	);


typedef DWORD(WINAPI* fnSizeofResource)(
	HMODULE hModule,
	HRSRC   hResInfo
	);



/* AES Functions */


typedef NTSTATUS(__stdcall* fnBCryptOpenAlgorithmProvider)(
	BCRYPT_ALG_HANDLE* phAlgorithm,
	LPCWSTR           pszAlgId,
	LPCWSTR           pszImplementation,
	ULONG             dwFlags
);


typedef NTSTATUS(__stdcall* fnBCryptGetProperty)(
	BCRYPT_HANDLE hObject,
	LPCWSTR       pszProperty,
	PUCHAR        pbOutput,
	ULONG         cbOutput,
	ULONG*		  pcbResult,
	ULONG         dwFlags
);



typedef NTSTATUS(__stdcall* fnBCryptSetProperty)(
	BCRYPT_HANDLE hObject,
	LPCWSTR       pszProperty,
	PUCHAR        pbInput,
	ULONG         cbInput,
	ULONG         dwFlags
	);


typedef NTSTATUS(__stdcall* fnBCryptGenerateSymmetricKey)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	BCRYPT_KEY_HANDLE* phKey,
	PUCHAR            pbKeyObject,
	ULONG             cbKeyObject,
	PUCHAR            pbSecret,
	ULONG             cbSecret,
	ULONG             dwFlags
	);


typedef NTSTATUS(__stdcall* fnBCryptDecrypt)(
	BCRYPT_KEY_HANDLE hKey,
	PUCHAR            pbInput,
	ULONG             cbInput,
	VOID*			  pPaddingInfo,
	PUCHAR            pbIV,
	ULONG             cbIV,
	PUCHAR            pbOutput,
	ULONG             cbOutput,
	ULONG*			  pcbResult,
	ULONG             dwFlags
	);



typedef NTSTATUS(__stdcall* fnBCryptDestroyKey)(
	BCRYPT_KEY_HANDLE hKey
	);


typedef NTSTATUS(__stdcall* fnBCryptCloseAlgorithmProvider)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	ULONG             dwFlags
	);



/* Definitions of Indirect Syscalls used in unhooking ntdll */


extern "C" NTSTATUS NTAPI SysNtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern "C" NTSTATUS NTAPI  SysNtReadVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN SIZE_T                NumberOfBytesToRead,
	OUT PSIZE_T              NumberOfBytesReaded OPTIONAL
);


extern "C" NTSTATUS NTAPI SysNtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            BaseAddress,
	IN OUT PSIZE_T           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
);


extern "C" NTSTATUS NTAPI SysNtTerminateProcess(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus
);
