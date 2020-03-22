
#include <iostream>
#include <HookHelper.hpp>


typedef int (WINAPI* lpfnMessageBoxW)(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType);
static int WINAPI Hooked_MessageBoxW(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType);

static struct {
    SIZE_T nHookId;
    lpfnMessageBoxW fnMessageBoxW;
} sMessageBoxW_Hook = { 0, NULL };


static int WINAPI Hooked_MessageBoxW(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType)
{
    return sMessageBoxW_Hook.fnMessageBoxW(hWnd, lpText, L"hooked", uType);
}


DWORD WINAPI testThread()
{
    return MessageBoxW(::GetActiveWindow(), 
        std::wstring(L"normal" + std::to_wstring(::GetCurrentThreadId())).c_str(), 
        L"normal", MB_OK);
}



typedef PVOID(WINAPI* lpfnRtlAllocateHeap)(
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size
);

static PVOID WINAPI Hooked_RtlAllocateHeap (
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size
);

static struct {
    SIZE_T nHookId;
    lpfnRtlAllocateHeap fnRtlAllocateHeap;
} sRtlAllocateHeap_Hook = { 0, NULL };


static PVOID WINAPI Hooked_RtlAllocateHeap(
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size
)
{
    return sRtlAllocateHeap_Hook.fnRtlAllocateHeap(HeapHandle, Flags, Size);
}


DWORD WINAPI testThread2()
{
    for (size_t i = 256; i < 1024; i++)
        free(malloc(i));

     return EXIT_SUCCESS;
}




int main()
{
    CHookHelper hooker;

    size_t id = 0;

    uint64_t Trampoline = 0;

    /*
    id = hooker.Hook(L"user32.dll", "MessageBoxW", 0
        | CHookEntry::enum_HookFlags::DisallowReentrancy
        | CHookEntry::enum_HookFlags::UseAbsoluteIndirectJumps
        | CHookEntry::enum_HookFlags::DontEnableHooks
        | CHookEntry::enum_HookFlags::DontSkipJumps
        , uintptr_t(&Hooked_MessageBoxW), &Trampoline);

    if (0 == id) {
        printf_s("hook error\n");
        return EXIT_FAILURE;
    }

    printf_s("MessageBoxW: 0x%zX\n", id);

    CHookHelper::HookInfos infos = { id };
    
    hooker.QueueHookInfos(infos);

    sMessageBoxW_Hook.nHookId = infos.nHookId;

    if (infos.uHookFlags & CHookEntry::enum_HookFlags::DisallowReentrancy)
        sMessageBoxW_Hook.fnMessageBoxW = (lpfnMessageBoxW)(infos.fnTrampoline);
    else
        sMessageBoxW_Hook.fnMessageBoxW = (lpfnMessageBoxW)(infos.fnTrampoline);
    
    ::MessageBoxW(::GetActiveWindow(), L"normal", L"normal", MB_OK);

    hooker.EnableHook(id, true);
    
    // exceeding the maximum number (RETMINISTUBS_COUNT_XXX) of loads will not enter callback
    HANDLE hThreads[5] = { };
    for (int i = 0; i < _ARRAYSIZE(hThreads); i++) {
        DWORD dwThreadId = 0;
        hThreads[i] = ::CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(&testThread), 0, 0, &dwThreadId);
    }
    WaitForMultipleObjects(_ARRAYSIZE(hThreads), hThreads, TRUE, INFINITE);

    hooker.EnableHook(id, false);

    ::MessageBoxW(::GetActiveWindow(), L"normal", L"normal", MB_OK);
    */

    id = hooker.Hook(L"ntdll.dll", "RtlAllocateHeap", 0
        | CHookEntry::enum_HookFlags::DisallowReentrancy
        | CHookEntry::enum_HookFlags::UseAbsoluteIndirectJumps
        | CHookEntry::enum_HookFlags::DontEnableHooks
        | CHookEntry::enum_HookFlags::DontSkipJumps
        , uintptr_t(&Hooked_RtlAllocateHeap), &Trampoline);

    if (0 == id) {
        printf_s("hook error\n");
        return EXIT_FAILURE;
    }

    printf_s("RtlAllocateHeap: 0x%zX\n", id);

    CHookHelper::HookInfos infos = { id };

    hooker.QueueHookInfos(infos);

    sRtlAllocateHeap_Hook.nHookId = infos.nHookId;

    if (infos.uHookFlags & CHookEntry::enum_HookFlags::DisallowReentrancy)
        sRtlAllocateHeap_Hook.fnRtlAllocateHeap = (lpfnRtlAllocateHeap)(infos.fnTrampoline);
    else
        sRtlAllocateHeap_Hook.fnRtlAllocateHeap = (lpfnRtlAllocateHeap)(infos.fnTrampoline);

    hooker.EnableHook(id, true);

    // exceeding the maximum number (RETMINISTUBS_COUNT_XXX) of loads will not enter callback
    HANDLE hThreads[5] = { };
    for (int i = 0; i < _ARRAYSIZE(hThreads); i++) {
        DWORD dwThreadId = 0;
        hThreads[i] = ::CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(&testThread2), 0, 0, &dwThreadId);
    }
    WaitForMultipleObjects(_ARRAYSIZE(hThreads), hThreads, TRUE, INFINITE);

    hooker.EnableHook(id, false);

    ::system("pause");

    return EXIT_SUCCESS;
}