
#include <HookHelper.hpp>

boolean InitDisassemble()
{
	boolean bSuccess = false;

    if (ZYDIS_VERSION != ZydisGetVersion())
    {
        fputs("Invalid zydis version\n", ZYAN_STDERR);
        return false;
    }
	return bSuccess;
}

// ================================================================================================================================
typedef BOOL(WINAPI* LPFN_GLPI)(
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    PDWORD);

// Helper function to count set bits in the processor mask.
static DWORD CountSetBits(ULONG_PTR bitMask)
{
    DWORD LSHIFT = sizeof(ULONG_PTR) * 8 - 1;
    DWORD bitSetCount = 0;
    ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;

    for (DWORD i = 0; i <= LSHIFT; ++i) {
        bitSetCount += ((bitMask & bitTest) ? 1 : 0);
        bitTest /= 2;
    }

    return bitSetCount;
}

static uint32_t getlogicalProcessorCount()
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
    BOOL done = FALSE;
    DWORD returnLength = 0;
    DWORD byteOffset = 0;

    DWORD processorCoreCount = 0;
    DWORD logicalProcessorCount = 0;

    LPFN_GLPI glpi = NULL;
    glpi = (LPFN_GLPI)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),
        "GetLogicalProcessorInformation");

    if (NULL == glpi) {

        _tprintf(TEXT("\nGetLogicalProcessorInformation is not supported.\n"));

        return std::thread::hardware_concurrency();
    }


    while (!done) {
        if (FALSE == glpi(buffer, &returnLength)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                if (buffer)
                    free(buffer);

                buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(
                    returnLength);

                if (NULL == buffer) {
                    _tprintf(TEXT("\nError: Allocation failure\n"));
                    goto _cleanup;
                }
            }
            else {
                _tprintf(TEXT("\nError %d\n"), GetLastError());
                goto _cleanup;
            }
        }
        else
            done = TRUE;
    }

    ptr = buffer;

    if (NULL == ptr)
        goto _cleanup;

    while (byteOffset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= returnLength) {
        switch (ptr->Relationship)
        {
        case RelationProcessorCore:
            processorCoreCount++;

            // A hyperthreaded core supplies more than one logical processor.
            logicalProcessorCount += CountSetBits(ptr->ProcessorMask);
            break;
        }

        byteOffset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
        ptr++;
    }

    return logicalProcessorCount;

_cleanup:
    return 0;
}