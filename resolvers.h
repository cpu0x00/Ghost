#pragma once


#include "structs.h"
#include <stdio.h>
#include "hash.h"
#include <iostream>



/// <summary>
/// Returns a HMODULE "Handle" To The Requested DllName By Walking The PEB
/// , Providing NULL in the DLL Name Returns the Base Address To The Running EXE (uses 28 iterations of WIERDHASHA)
/// </summary>
/// <param name="DWORD Hash"></param>
/// <returns></returns>
HMODULE GetLoadedDllHandleH(DWORD dwHash) {
	PPEB peb = reinterpret_cast<PPEB>(__readgsqword(96));
	PPEB_LDR_DATA ldr = reinterpret_cast<PPEB_LDR_DATA>(peb->Ldr);
	PLDR_DATA_TABLE_ENTRY ldte = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldr->InLoadOrderModuleList.Flink);



	while (true) {



		CHAR ANSI[MAX_PATH];

		DWORD i = 0;
		while (ldte->FullDllName.Buffer[i]) {
			ANSI[i] = (CHAR)(ldte->FullDllName.Buffer[i]);
			i++;
		}
		ANSI[i] = '\0';

		DWORD Hash = WEIRDHASHA(ANSI, 28);



		if (dwHash == Hash) {


			return  reinterpret_cast<HMODULE>(ldte->DllBase);
		}
		ldte = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldte->InLoadOrderLinks.Flink);
	}
	return NULL;

}

/// <summary>
/// GetProcAddress Replacement, Retrieves Function Address By Parsing IMAGE_EXPORT_DIRECTORY of Given Dll (uses 27 iterations of WIERDHASHA)
/// </summary>
/// <param name="DllHandle"></param>
/// <param name="DWORD HASH"></param>
/// <returns></returns>
FARPROC GetFunctionAddressH(HMODULE DllHandle, DWORD dwHash) {
	// one thing i miss is C#'s general purpose pointer :(

	uintptr_t DllBase = reinterpret_cast<uintptr_t>(DllHandle); // this cast is to change the HMODULE type to a uint type to be able to perform ptr arithmetics on it
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DllBase;

	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Magic Signature Mismatched, Memory Alignment Issue (Check DataTypes)\n");
	}

	PIMAGE_NT_HEADERS ntheaders = reinterpret_cast<PIMAGE_NT_HEADERS>(DllBase + dos->e_lfanew);

	if (ntheaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("NT Signature Mismatched, Memory Alignment Issue (Check DataTypes)\n");
	}

	IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = ntheaders->OptionalHeader;
	DWORD ExportDirRva = OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(DllBase + ExportDirRva);
	PDWORD AddressOfNames = reinterpret_cast<PDWORD>(DllBase + pExportDirectory->AddressOfNames); // address of names is a list contains rvas, to function names
	PDWORD AddressOfFunctions = reinterpret_cast<PDWORD>(DllBase + pExportDirectory->AddressOfFunctions); // address of functions is a list contains rvas, to function addresses
	PWORD AddressOfOrdinals = reinterpret_cast<PWORD>(DllBase + pExportDirectory->AddressOfNameOrdinals); // address of ordinals is a list contains rvas, to function ordinals
	/* To Use RVAs in that list they must be added to the base */

	for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

		char* Name = reinterpret_cast<char*>(DllBase + AddressOfNames[i]);

		if (dwHash == WEIRDHASHA(Name, 27)) {
			//std::cout << Name << "\n";
			FARPROC Function = reinterpret_cast<FARPROC>(DllBase + AddressOfFunctions[AddressOfOrdinals[i]]);

			return Function;
		}
	}

	return NULL;
}


/// <summary>
/// Checks The Entire Epilog (mov r10, rcx ; mov eax, ???) if one byte didn't match then the function has been tampered and considered hooked
/// </summary>
/// <param name="functionbytes"></param>
/// <returns></returns>
BOOL IsHooked(PBYTE functionbytes) {
	if (functionbytes[0] != 0x4C && functionbytes[1] != 0x8b && functionbytes[2] != 0xd1 && functionbytes[3] != 0xb8) {
		return TRUE; // hooked
	}
	return FALSE;
}



/// <summary>
/// Finds The SSN of the requested function using API Hashing and provides the SSN and a Decoy SysCall Address For an Unhooked Function to use with Indirect Syscalls
/// </summary>
/// <param name="dwFunctionHash"></param>
/// <param name="SSN"></param>
/// <param name="SysCallAddr"></param>
/// <returns>nothing</returns>
PVOID GetSysCallByWalking(DWORD dwFunctionHash, OUT PDWORD SSN, OUT UINT_PTR* SysCallAddr) {


	int track = 1;
	int offset = 0x20;
	FARPROC pfunc = GetFunctionAddressH(GetLoadedDllHandleH(776560387), dwFunctionHash);
	uintptr_t fAddress = reinterpret_cast<uintptr_t>(pfunc);

	while (true) {

		PBYTE neighbor = (PBYTE)(fAddress + offset);

		if (!IsHooked(neighbor)) { // neighbor is not hooked get Target SSN from it

			if (neighbor[5] != 0x00) { // SSN is 3 bytes
				*SSN = ((neighbor[5] << 8) | neighbor[4]) - track;
				*SysCallAddr = ((uintptr_t)neighbor + 0x12);
				return NULL;
			}

			*SSN = (DWORD)neighbor[4] - track;
			*SysCallAddr = ((uintptr_t)neighbor + 0x12);

			return NULL;
		}
		else { // neighbor is hooked move on
			track++;
			offset = offset + 0x20;
			neighbor = (PBYTE)(fAddress + offset);
		}
	}
	return NULL;
}



HMODULE GetLoadedDllHandleByName(const wchar_t* DllName) {

	PPEB peb = reinterpret_cast<PPEB>(__readgsqword(96));
	PPEB_LDR_DATA ldr = reinterpret_cast<PPEB_LDR_DATA>(peb->Ldr);
	PLDR_DATA_TABLE_ENTRY ldte = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldr->InLoadOrderModuleList.Flink);

	if (DllName == NULL) {
		return reinterpret_cast<HMODULE>(peb->ImageBaseAddress);
	}

	while (true) {
		LPCWSTR Name = ldte->BaseDllName.Buffer;
		if (Name != nullptr && wcscmp(Name, DllName) == 0) {
			return  reinterpret_cast<HMODULE>(ldte->DllBase);
		}
		ldte = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldte->InLoadOrderLinks.Flink);
	}
	return NULL;

}

/// <summary>
/// GetProcAddress Replacement, Retrieves Function Address By Parsing IMAGE_EXPORT_DIRECTORY of Given Dll
/// </summary>
/// <param name="DllHandle"></param>
/// <param name="FunctionName"></param>
/// <returns></returns>
FARPROC GetFunctionAddressByName(HMODULE DllHandle, const char* FunctionName) {
	// one thing i miss is C#'s general purpose pointer :(

	uintptr_t DllBase = reinterpret_cast<uintptr_t>(DllHandle); // this cast is to change the HMODULE type to a uint type to be able to perform ptr arithmetics on it
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DllBase;

	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Magic Signature Mismatched, Memory Alignment Issue (Check DataTypes)\n");
	}

	PIMAGE_NT_HEADERS ntheaders = reinterpret_cast<PIMAGE_NT_HEADERS>(DllBase + dos->e_lfanew);

	if (ntheaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("NT Signature Mismatched, Memory Alignment Issue (Check DataTypes)\n");
	}

	IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = ntheaders->OptionalHeader;
	DWORD ExportDirRva = OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(DllBase + ExportDirRva);
	PDWORD AddressOfNames = reinterpret_cast<PDWORD>(DllBase + pExportDirectory->AddressOfNames); // address of names is a list contains rvas, to function names
	PDWORD AddressOfFunctions = reinterpret_cast<PDWORD>(DllBase + pExportDirectory->AddressOfFunctions); // address of functions is a list contains rvas, to function addresses
	PWORD AddressOfOrdinals = reinterpret_cast<PWORD>(DllBase + pExportDirectory->AddressOfNameOrdinals); // address of ordinals is a list contains rvas, to function ordinals
	/* To Use RVAs in that list they must be added to the base */

	for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

		char* Name = reinterpret_cast<char*>(DllBase + AddressOfNames[i]);
		if (strcmp(Name, FunctionName) == 0) {
			FARPROC Function = reinterpret_cast<FARPROC>(DllBase + AddressOfFunctions[AddressOfOrdinals[i]]);
			//std::cout << "[+] Resolved " << FunctionName << " Address -> " << Function << std::endl;
			return Function;
		}
	}

	return NULL;
}
