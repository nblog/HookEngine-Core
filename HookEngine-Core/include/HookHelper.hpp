#pragma once

#include <Windows.h>
#include <inttypes.h>
//#include <intrin.h>

#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#include <ZycoreExportConfig.h>
#include <ZydisExportConfig.h>

#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

#include <BlackBone/Config.h>
#include <BlackBone/Process/Process.h>

#include "../../third-party/LinkedList/LinkedList.h"

namespace _asmjit { using namespace ::asmjit_; }

#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#define FlagOn(x, _flag) ((x) & (_flag))

#define RETMINISTUBS_COUNT_X86                           160
#define RETMINISTUBS_COUNT_X64                           120

#define DisassembleMAXLength                             64


class CHookEntry
{
public:

    // flags
    enum enum_HookFlags : uint32_t {
        DontRemoveOnUnhook = 1 << 1,
        DontSkipJumps = 1 << 2,
        UseAbsoluteIndirectJumps = 1 << 4,
        DisallowReentrancy = 1 << 5,
        DontEnableHooks = 1 << 6,
    };

    ~CHookEntry() {
        ZeroFieldsEx(false);
        ZeroFields();
    };

    CHookEntry() {   };

    CHookEntry(HANDLE hProcess) {
        auto status = _process.Attach(hProcess);
        ZYAN_ASSERT(STATUS_SUCCESS == status);
        ZYAN_ASSERT((_process.pid() && _process.valid()));
        ZeroFields();
    };


    size_t Hook(uint64_t runtimeAddress, uint32_t HookFlags, uint64_t lpCallBack) {

        _uHookFlags = HookFlags;

        _lpOrigAddress = runtimeAddress;

        _lpNewAddress = lpCallBack;

        ZeroFieldsEx(true);

        if (false == HookCommon())
            return 0;

#if defined(_M_IX86)
        _id = (size_t)this ^ 0x34B68363UL; //odd number to avoid result of zero
#elif defined(_M_X64)
        _id = (size_t)this ^ 0x34B68364A3CE19F3ui64; //odd number to avoid result of zero
#endif
        return _id;
    };

    boolean Unhook()
    {
        return UnhookCommon();
    };

    boolean EnableHook(boolean bEnable)
    {
        return EnableHookCommon(bEnable);
    };

    boolean QueueEnableHook()
    {
        return (getStatus() & 0x101) ? false : true;
    };


    const size_t getId() { return _id; };
    
    const long getStatus() { return _lHookStatus; };

    const uint32_t getHookFlags() { return _uHookFlags; };

    const uint64_t getTrampoline() { return _trampoline; };

private:

    blackbone::Process _process;
    boolean _is64Bit;

    size_t _id;
    uint32_t _uHookFlags;

    blackbone::ptr_t _lpOrigAddress;
    blackbone::ptr_t _lpNewAddress;

    blackbone::ptr_t _returnAddress;
    blackbone::ptr_t _codesAddress;

    struct relativeInfo {
        uint64_t offset;
        int32_t imm;
    };

    std::vector<relativeInfo> reloc;
    size_t _codes_length;
    void * _codes;

    size_t _ministub_length;
    blackbone::ptr_t _ministub;

    size_t _trampoline_length;
    blackbone::ptr_t _trampoline;

    size_t _handler_length;
    blackbone::ptr_t _handler;

    blackbone::ptr_t _ptr_handler;

    template<typename T>
    struct _CHKREENTRY {
        T UniqueThread;
        T lpReturnAddress;
    };

    typedef struct _CHKREENTRY<uint32_t> CHKREENTRY32, * PCHKREENTRY32;
    typedef struct _CHKREENTRY<uint64_t> CHKREENTRY64, * PCHKREENTRY64;


    long _lHookStatus;
    blackbone::ptr_t _lpHookStatus;
    blackbone::ptr_t _lpReentrys32;
    blackbone::ptr_t _lpReentrys64;

    size_t GetJumpToHookBytes()
    {
        if (0 != (_uHookFlags & enum_HookFlags::UseAbsoluteIndirectJumps))
            return 6;
        return 5;
    };


    blackbone::ptr_t AllocateMem(size_t size, uint32_t dwProtect, uint64_t refAddr)
    {
        auto pageSize = _process.core().native()->pageSize();

        MEMORY_BASIC_INFORMATION64 mbi64 = { };
        uint64_t nMin = 0, nMax = 0;

        size = Align(size, pageSize); //ALIGN(size, pageSize);

        auto last = _process.memory().EnumRegions().back();
        nMax = last.BaseAddress + last.RegionSize;

        if (NT_SUCCESS(_process.memory().Query(refAddr, &mbi64)))
            nMin = mbi64.BaseAddress;
        else
            nMin = (refAddr & (~MAXWORD));

        ZYAN_ASSERT(size <= mbi64.RegionSize);

        do {
            if (NT_SUCCESS(_process.memory().Query(nMin, &mbi64))
                && MEM_FREE == mbi64.State) {
                auto alloc = _process.memory().Allocate(
                    size, dwProtect, nMin, false);

                if (STATUS_SUCCESS == alloc.status)
                    return alloc->ptr();
            }
            nMin += pageSize;
        } while (nMin < nMax);

        return 0;
    }


    void ZeroFields() {
        _id = 0;
        _uHookFlags = 0;
        _lpOrigAddress = 0;
        _lpNewAddress = 0;
        _codes_length = 0;
        _ministub_length = 0;
        _trampoline_length = 0;
        _handler_length = 0;
        _ptr_handler = 0;
        _lHookStatus = 0;

        _lpHookStatus = 0;
        _lpReentrys32 = 0;
        _lpReentrys64 = 0;

        _is64Bit = false;
#if defined(_M_X64)
        _is64Bit = true;
#endif
    };

    void ZeroFieldsEx(boolean init = false)
    {
        if (init) {

            ZYAN_PRINTF("type:%d, sourceWow64:%hs, targetWow64:%hs\n",
                _process.barrier().type,
                _process.barrier().sourceWow64 ? "True" : "False",
                _process.barrier().targetWow64 ? "True" : "False");

            _is64Bit = !_process.barrier().targetWow64;

            _codes = calloc(DisassembleMAXLength, sizeof(uint8_t));

            if (_is64Bit)
            {
                auto alloc_ptr = AllocateMem(
                    sizeof(volatile long) + (RETMINISTUBS_COUNT_X64 * sizeof(CHKREENTRY64)),
                    PAGE_READWRITE, _lpOrigAddress);

                ZYAN_ASSERT(alloc_ptr);

                _lpHookStatus = alloc_ptr;
                _lpReentrys64 = alloc_ptr + sizeof(volatile long);
            }
            else
            {
                auto alloc_ptr = AllocateMem(
                    sizeof(volatile long) + (RETMINISTUBS_COUNT_X86 * sizeof(CHKREENTRY32)),
                    PAGE_READWRITE, _lpOrigAddress);

                ZYAN_ASSERT(alloc_ptr);

                _lpHookStatus = alloc_ptr;
                _lpReentrys32 = alloc_ptr + sizeof(volatile long);
            }
        }
        else
        {   // free
            if (_codes)
                free(_codes);

            {
                if (_lpHookStatus)
                    _process.memory().Free(_lpHookStatus);

                if (_lpReentrys32)
                    _process.memory().Free(_lpReentrys32);

                if (_lpReentrys64)
                    _process.memory().Free(_lpReentrys64);
            }

            {
                if (_ministub_length && _ministub)
                    _process.memory().Free(_ministub);

                if (_trampoline_length && _trampoline)
                    _process.memory().Free(_trampoline);

                if (_handler_length && _handler)
                    _process.memory().Free(_handler);
            }
        }
    }


    boolean CompilerMinistub32(
        blackbone::IAsmHelper& asmCode,
        _asmjit::Label& ministub,
        size_t count = RETMINISTUBS_COUNT_X86
    );
    boolean CompilerMinistub64(
        blackbone::IAsmHelper& asmCode,
        _asmjit::Label& ministub,
        size_t count = RETMINISTUBS_COUNT_X64
    );
    boolean CopyOldCodes(
        blackbone::IAsmHelper& asmCode
    );
    boolean CompilerTrampoline(
        blackbone::IAsmHelper& asmCode,
        _asmjit::Label& trampoline
    );

    boolean CompilerGenericHookFn(
    );

    boolean CompilerHandler(
    );

    boolean HookCommon();
    boolean UnhookCommon();
    boolean EnableHookCommon(boolean bEnable);
};



typedef enum {
    ccNA = -1, 
    ccStdCall = 0, ccCDecl = 1, ccFastCall = 2, ccThisCall = 3, 
} eCallingConvention;

// handler https://github.com/zyantific/zyan-hook-engine/blob/master/doc/Barrier.md
boolean CHookEntry::CompilerHandler()
{
    boolean bSuccess = false;

    // InitializeCriticalSection

    // EnterCriticalSection

    // pre call

    // post call

    // return value

    // LeaveCriticalSection

    bSuccess = true;

    return bSuccess;
}



/* ============================================================================================== */
/* disassemble callbacks                                                                                 */
/* ============================================================================================== */


ZYAN_INLINE ZyanI32 ZydisCalculateRelativeOffset(ZyanU8 instruction_length,
    ZyanU64 source_address, ZyanU64 destination_address)
{
    return (ZyanI32)(destination_address - source_address - instruction_length);
}


ZYAN_INLINE ZyanBool ZydisIsRelativeBranchInstruction(const ZydisDecodedInstruction* instruction)
{
    ZYAN_ASSERT(instruction);

    switch (instruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        return ZYAN_TRUE;
    default:
        return ZYAN_FALSE;
    }
}


typedef struct _USERASBJMP {
    boolean bJump;
    ZydisOperandType type;
    ZyanBool bRelative;
    ZyanU64 absoluteAddress;
} userJmpContext;

ZydisFormatterFunc default_print_address_absolute = nullptr;

static ZyanStatus ZydisFormatterPrintAddressAbsolute(const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
    ZyanU64 address = 0;
    
    ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand,
        context->runtime_address, &address));

    userJmpContext* userdata = (userJmpContext*)(context->user_data);
    if (nullptr != userdata)
    {
        if (ZYAN_TRUE == ZydisIsRelativeBranchInstruction(context->instruction)
            || ZYDIS_MNEMONIC_CALL == context->instruction->mnemonic)
            userdata->bJump = true;

        userdata->type = ZydisOperandType(context->operand->type);

        userdata->bRelative = (context->instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            ? ZYAN_TRUE
            : ZYAN_FALSE;

        userdata->absoluteAddress = address;
    }

    return default_print_address_absolute(formatter, buffer, context);
}



boolean CHookEntry::CopyOldCodes(blackbone::IAsmHelper& asmCode)
{
    if (0 == _lpOrigAddress)
        return false;

    printf_s("codes offset: %zu\n", asmCode->getOffset());

    boolean bSuccess = false;

    bool is64Bit = _is64Bit;

    bool isSkipJump = FlagOn(_uHookFlags, enum_HookFlags::DontSkipJumps);

    uint8_t codes[DisassembleMAXLength] = { };

    ZyanUSize length = 0;
    ZyanU64 address = _lpOrigAddress;
    ZyanU64 dstAddress = 0;

    ZydisDecoder decoder;

    ZydisDecodedInstruction instruction = { };

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    // Replace the `ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS` function that formats the absolute
    // addresses
    default_print_address_absolute = (ZydisFormatterFunc)&ZydisFormatterPrintAddressAbsolute;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS,
        (const void**)&default_print_address_absolute);

    ZydisDecoderInit(&decoder,
        is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
        is64Bit ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32);

_disassemble:
    ZYAN_MEMSET(codes, 0, DisassembleMAXLength);
    auto status = _process.memory().Read(address, DisassembleMAXLength, &codes);
    ZYAN_ASSERT(STATUS_SUCCESS == status);

_next:
    ZydisDecoderDecodeBuffer(&decoder, codes + length, DisassembleMAXLength, &instruction);

    userJmpContext user = { false, ZydisOperandType::ZYDIS_OPERAND_TYPE_UNUSED, false, 0 };

    {
        char buffer[1024] = { };

        // We have to pass a `runtime_address` different to `ZYDIS_RUNTIME_ADDRESS_NONE` to
        // enable printing of absolute addresses
        ZydisFormatterFormatInstructionEx(&formatter, &instruction, &buffer[0], sizeof(buffer),
            address, &user);

        ZYAN_PRINTF("%016" PRIX64 "  " " %hs\n", address, &buffer[0]);

        dstAddress = 0;
    }

    if (user.bJump && user.bRelative && ZYDIS_OPERAND_TYPE_MEMORY == user.type) {
        _process.memory().Read(user.absoluteAddress,
            is64Bit ? sizeof(uint64_t) : sizeof(uint32_t), &dstAddress);
        ZYAN_PRINTF("dest address: " "%016" PRIX64 "\n", dstAddress);
    }
    else
        dstAddress = user.absoluteAddress;

    // It's not safe to relocate a `CALL` instruction to the trampoline 
    if (ZYDIS_MNEMONIC_CALL == instruction.mnemonic)
        ZYAN_UNREACHABLE;

    if (user.bJump
        && false == isSkipJump) {

        ZYAN_PRINTF("--------------------------------\n");
        length = 0;
        address = dstAddress;
        goto _disassemble;
    }

_done: 

    {
        if (user.bRelative)
        {
            auto offset = asmCode->getOffset();
            
            relativeInfo info = { 0, 0 };

            if (ZydisIsRelativeBranchInstruction(&instruction))
            {   // jmp or jcc reloc

                ZyanU8 pos = 0;

                switch (instruction.mnemonic)
                {
                case ZYDIS_MNEMONIC_JMP: 
                    asmCode->db(0xE9); pos += 1; break;
                case ZYDIS_MNEMONIC_JO: 
                    asmCode->db(0x0F); asmCode->db(0x80); pos += 2; break;
                case ZYDIS_MNEMONIC_JNO: 
                    asmCode->db(0x0F); asmCode->db(0x81); pos += 2; break;
                case ZYDIS_MNEMONIC_JB: 
                    asmCode->db(0x0F); asmCode->db(0x82); pos += 2; break;
                case ZYDIS_MNEMONIC_JNB: 
                    asmCode->db(0x0F); asmCode->db(0x83); pos += 2; break;
                case ZYDIS_MNEMONIC_JZ: 
                    asmCode->db(0x0F); asmCode->db(0x84); pos += 2; break;
                case ZYDIS_MNEMONIC_JNZ: 
                    asmCode->db(0x0F); asmCode->db(0x85); pos += 2; break;
                case ZYDIS_MNEMONIC_JBE: 
                    asmCode->db(0x0F); asmCode->db(0x86); pos += 2; break;
                case ZYDIS_MNEMONIC_JNBE: 
                    asmCode->db(0x0F); asmCode->db(0x87); pos += 2; break;
                case ZYDIS_MNEMONIC_JS: 
                    asmCode->db(0x0F); asmCode->db(0x88); pos += 2; break;
                case ZYDIS_MNEMONIC_JNS: 
                    asmCode->db(0x0F); asmCode->db(0x89); pos += 2; break;
                case ZYDIS_MNEMONIC_JP: 
                    asmCode->db(0x0F); asmCode->db(0x8A); pos += 2; break;
                case ZYDIS_MNEMONIC_JNP: 
                    asmCode->db(0x0F); asmCode->db(0x8B); pos += 2; break;
                case ZYDIS_MNEMONIC_JL: 
                    asmCode->db(0x0F); asmCode->db(0x8C); pos += 2; break;
                case ZYDIS_MNEMONIC_JNL: 
                    asmCode->db(0x0F); asmCode->db(0x8D); pos += 2; break;
                case ZYDIS_MNEMONIC_JLE: 
                    asmCode->db(0x0F); asmCode->db(0x8E); pos += 2; break;
                case ZYDIS_MNEMONIC_JNLE: 
                    asmCode->db(0x0F); asmCode->db(0x8F); pos += 2; break;
                case ZYDIS_MNEMONIC_LOOP:
                case ZYDIS_MNEMONIC_LOOPE:
                case ZYDIS_MNEMONIC_LOOPNE:
                default:
                    ZYAN_UNREACHABLE;
                }

                asmCode->dd(0);
                info.offset = offset + pos;
                info.imm = ZydisCalculateRelativeOffset( 1 == pos ? 5 : 6, offset, dstAddress);
            }
            else
            {   // imm reloc
                ZYAN_ASSERT(0 < instruction.raw.disp.value);

                asmCode->embed(codes + length, instruction.length);

                info.offset = offset + instruction.raw.disp.offset;
                info.imm = ZydisCalculateRelativeOffset(instruction.length, offset, dstAddress);
            }

            reloc.push_back(info);
        }
        else
            asmCode->embed(codes + length, instruction.length);
    }

    length += instruction.length;
    address += instruction.length;

    if (length < GetJumpToHookBytes())
        goto _next;
    else
        bSuccess = true;

    // old codes
    _codesAddress = address - length;
    _returnAddress = address;

    _codes_length = length;
    ZYAN_MEMCPY(_codes, codes, _codes_length);

    return bSuccess;
}


boolean CHookEntry::CompilerMinistub32(blackbone::IAsmHelper& asmCode, _asmjit::Label& ministub, size_t count)
{
    auto& AsmCore = asmCode;

    AsmCore->bind(ministub);

    for (size_t iCount = 0; iCount < count; iCount++)
    {
        AsmCore->push(AsmCore->intptr_ptr_abs(blackbone::ptr_t(
            _lpReentrys32 
            + uint64_t(UInt32x32To64(iCount, sizeof(CHKREENTRY32))) 
            + offsetof(CHKREENTRY32, lpReturnAddress)))
        );
        AsmCore->lock();
        AsmCore->and_(AsmCore->intptr_ptr_abs(blackbone::ptr_t(
            _lpReentrys32 + uint64_t(UInt32x32To64(iCount, sizeof(CHKREENTRY32))) 
            + offsetof(CHKREENTRY32, UniqueThread)))
            , 0);
        AsmCore->ret();
        AsmCore->nop();
    }

    _ministub_length = AsmCore->getCodeSize() - AsmCore->getLabelOffset(ministub);
    _ministub = AsmCore->getLabelOffset(ministub);

    return 16 == (_ministub_length / count);
}

boolean CHookEntry::CompilerMinistub64(blackbone::IAsmHelper& asmCode, _asmjit::Label& ministub, size_t count)
{
    auto& AsmCore = asmCode;

    AsmCore->bind(ministub);

    for (size_t iCount = 0; iCount < count; iCount++)
    {
        AsmCore->push(AsmCore->zax);

        AsmCore->push(AsmCore->zax);
        AsmCore->push(AsmCore->zcx);

        AsmCore->mov(AsmCore->zcx, blackbone::ptr_t(
            _lpReentrys64 + uint64_t(UInt32x32To64(iCount, sizeof(CHKREENTRY64)))));
        AsmCore->mov(AsmCore->zax, AsmCore->intptr_ptr(AsmCore->zcx, 
            offsetof(CHKREENTRY64, lpReturnAddress)));

        AsmCore->mov(AsmCore->intptr_ptr(AsmCore->zsp, 2 * sizeof(PVOID64)), AsmCore->zax);

        AsmCore->lock();
        AsmCore->and_(AsmCore->intptr_ptr(AsmCore->zcx,
            offsetof(CHKREENTRY64, UniqueThread)), 0);

        AsmCore->pop(AsmCore->zcx);
        AsmCore->pop(AsmCore->zax);

        AsmCore->ret();
        AsmCore->nop();
        AsmCore->nop();
    }

    _ministub_length = AsmCore->getCodeSize() - AsmCore->getLabelOffset(ministub);
    _ministub = AsmCore->getLabelOffset(ministub);

    return 32 == (_ministub_length / count);
}

boolean CHookEntry::CompilerTrampoline(blackbone::IAsmHelper& asmCode, _asmjit::Label& trampoline)
{
    auto& AsmCore = asmCode;

    auto memSrcAddress = AsmCore->newLabel();

    AsmCore->bind(trampoline);

    // old code
    if (false == CopyOldCodes(asmCode) || 0 == _codes_length)
        return false;

    // jmp (oldcodes + oldcodes_size)
    AsmCore->jmp(AsmCore->intptr_ptr(memSrcAddress));

    AsmCore->bind(memSrcAddress);
    AsmCore->embed(&_returnAddress, sizeof(_returnAddress));

    {   // align 4
        for (size_t i = 0; i < AsmCore->getCodeSize() % 4; i++)
            AsmCore->nop();
    }

     // trampoline
    _trampoline_length = AsmCore->getCodeSize() - AsmCore->getLabelOffset(trampoline);
    _trampoline = AsmCore->getLabelOffset(trampoline);

    return 0 < _trampoline_length;
}

boolean CHookEntry::CompilerGenericHookFn()
{
    bool is64Bit = _is64Bit;

    auto HandlerCode = blackbone::AsmFactory::GetAssembler(is64Bit ? false : true);
    auto& AsmCore = *HandlerCode;
    AsmCore.EnableX64CallStack(is64Bit);

    auto call_original = AsmCore->newLabel();
    auto call_hooked = AsmCore->newLabel();
    auto call_callback = AsmCore->newLabel();

    auto handler = AsmCore->newLabel();
    auto trampoline = AsmCore->newLabel();
    auto ministub = AsmCore->newLabel();

    bool bNewTrampoline = true;

    if (FlagOn(_uHookFlags, enum_HookFlags::DisallowReentrancy))
        bNewTrampoline = false;
    else
        bNewTrampoline = true;


    AsmCore->bind(handler);

    // skip first eight NOP bytes for hot-patching double hooks
    for (size_t i = 0; i < 8; i++)
        AsmCore->nop();
    
    int argCount = 0;

    AsmCore->push(AsmCore->zdx);
    ++argCount;
    
    if (!bNewTrampoline)
    {
        AsmCore->push(AsmCore->zax);
        ++argCount;
    
        AsmCore->push(AsmCore->zbx);
        ++argCount;
    
        AsmCore->push(AsmCore->zcx);
        ++argCount;
    }
    
    AsmCore->mov(AsmCore->zdx, blackbone::ptr_t(_lpHookStatus));
    AsmCore->test(AsmCore->intptr_ptr(AsmCore->zdx), 0x00000101);
    AsmCore->jne(call_original);
    
    if (!bNewTrampoline)
    {
        auto L1 = AsmCore->newLabel();
        auto L2 = AsmCore->newLabel();
        auto chg_retaddress = AsmCore->newLabel();

        if (is64Bit)
        {   // X64 TEB_64->ClientId->UniqueThread
            AsmCore->mov(AsmCore->zax, 
                AsmCore->intptr_ptr_abs(0x30).setSegment(_asmjit::x86::gs));
    
            AsmCore->mov(AsmCore->zax, AsmCore->intptr_ptr(AsmCore->zax,
                offsetof(blackbone::_TEB64, ClientId) 
                + offsetof(blackbone::_CLIENT_ID_T<uint64_t>, UniqueThread)));
        }
        else
        {   // X86 TEB_32->ClientId->UniqueThread
            AsmCore->mov(AsmCore->zax, 
                AsmCore->intptr_ptr_abs(0x18).setSegment(_asmjit::x86::fs));
    
            AsmCore->mov(AsmCore->zax, AsmCore->intptr_ptr(AsmCore->zax,
                offsetof(blackbone::_TEB32, ClientId) 
                + offsetof(blackbone::_CLIENT_ID_T<uint32_t>, UniqueThread)));
        }
    
        AsmCore->mov(AsmCore->zdx, 
            is64Bit ? blackbone::ptr_t(_lpReentrys64) : blackbone::ptr_t(_lpReentrys32));
        AsmCore->mov(AsmCore->zcx, is64Bit ? RETMINISTUBS_COUNT_X64 : RETMINISTUBS_COUNT_X86);
        AsmCore->bind(L1);
    
        AsmCore->cmp(AsmCore->zax, AsmCore->intptr_ptr(AsmCore->zdx));
        AsmCore->je(call_original);
        AsmCore->add(AsmCore->zdx, is64Bit ? sizeof(CHKREENTRY64) : sizeof(CHKREENTRY32));
        //AsmCore->loop(L1);
        {   // loop
            //AsmCore->pushf();
            AsmCore->dec(AsmCore->zcx);
            AsmCore->jnz(L1);
            //AsmCore->popf();
        }
    
        AsmCore->mov(AsmCore->zbx, AsmCore->zax);
    
        AsmCore->mov(AsmCore->zdx,
            is64Bit ? blackbone::ptr_t(_lpReentrys64) : blackbone::ptr_t(_lpReentrys32));
        AsmCore->mov(AsmCore->zcx, is64Bit ? RETMINISTUBS_COUNT_X64 : RETMINISTUBS_COUNT_X86);
    

        AsmCore->bind(L2);
        AsmCore->xor_(AsmCore->zax, AsmCore->zax);
    
        AsmCore->lock();
        AsmCore->cmpxchg(AsmCore->intptr_ptr(AsmCore->zdx,
            is64Bit ? offsetof(CHKREENTRY64, UniqueThread) : offsetof(CHKREENTRY32, UniqueThread))
            , AsmCore->zbx);
        AsmCore->je(chg_retaddress);
        AsmCore->add(AsmCore->zdx, is64Bit ? sizeof(CHKREENTRY64) : sizeof(CHKREENTRY32));
        //AsmCore->loop(L2);
        {   // loop
            //AsmCore->pushf();
            AsmCore->dec(AsmCore->zcx);
            AsmCore->jnz(L2);
            //AsmCore->popf();
        }
    
        AsmCore->jmp(call_original);  // fix call_hooked
    
        AsmCore->bind(chg_retaddress);
    
        AsmCore->mov(AsmCore->zax, AsmCore->intptr_ptr(AsmCore->zsp, 
            argCount * (is64Bit ? sizeof(uint64_t) : sizeof(uint32_t))));
    
        AsmCore->mov(AsmCore->intptr_ptr(AsmCore->zdx, 
            is64Bit ? offsetof(CHKREENTRY64, lpReturnAddress) : offsetof(CHKREENTRY32, lpReturnAddress)),
            AsmCore->zax);
    
        AsmCore->mov(AsmCore->zax, is64Bit ? RETMINISTUBS_COUNT_X64 : RETMINISTUBS_COUNT_X86);
        AsmCore->sub(AsmCore->zax, AsmCore->zcx);
        AsmCore->shl(AsmCore->zax, is64Bit ? 5 : 4);
        AsmCore->lea(AsmCore->zcx, AsmCore->intptr_ptr(ministub));
        AsmCore->add(AsmCore->zax, AsmCore->zcx);
        AsmCore->mov(AsmCore->intptr_ptr(AsmCore->zsp, 
            argCount * (is64Bit ? sizeof(uint64_t) : sizeof(uint32_t))),
            AsmCore->zax);
    }
    
    AsmCore->bind(call_hooked);
    if (!bNewTrampoline)
    {
        AsmCore->pop(AsmCore->zcx);
        --argCount;
        AsmCore->pop(AsmCore->zbx);
        --argCount;
        AsmCore->pop(AsmCore->zax);
        --argCount;
    }
    
    AsmCore->pop(AsmCore->zdx);
    --argCount;
    
    // Callback Address
    AsmCore->jmp(AsmCore->intptr_ptr(call_callback));
    AsmCore->bind(call_callback);
    AsmCore->embed(&_lpNewAddress, sizeof(_lpNewAddress));
    
    AsmCore->bind(call_original);
    if (!bNewTrampoline)
    {
        AsmCore->pop(AsmCore->zcx);
        --argCount;
        AsmCore->pop(AsmCore->zbx);
        --argCount;
        AsmCore->pop(AsmCore->zax);
        --argCount;
    }
    
    AsmCore->pop(AsmCore->zdx);
    --argCount;
    
    {   // align 4
        for (size_t i = 0; i < AsmCore->getCodeSize() % 4; i++)
            AsmCore->nop();
    }

    {   // trampoline

        if (false == CompilerTrampoline(AsmCore, trampoline))
            return false;

        // handler  UseAbsoluteIndirectJumps
        _ptr_handler = AsmCore->getOffset();
        AsmCore->embedLabel(handler);

        ZYAN_ASSERT(_trampoline_length);
        if (0 == _trampoline_length)
            return false;

        if (!bNewTrampoline)
        {
            if (is64Bit) {
                if (false == CompilerMinistub64(AsmCore, ministub, RETMINISTUBS_COUNT_X64))
                    return false;
            }
            else {
                if (false == CompilerMinistub32(AsmCore, ministub, RETMINISTUBS_COUNT_X86))
                    return false;
            }
        }
    }

    {   // write target process
        auto alloc_ptr = AllocateMem(
            AsmCore->getCodeSize(), PAGE_EXECUTE_READWRITE, _lpOrigAddress);
        if (0 == alloc_ptr)
            return false;

        AsmCore->setBaseAddress(alloc_ptr);

        auto lpAddress = reinterpret_cast<void(*)()>(AsmCore->make());

        // reloc
        for (auto item : reloc)
            *(ZyanU32*)((uintptr_t)(lpAddress) + item.offset) = item.imm - ZyanU32(alloc_ptr);

        if (false == NT_SUCCESS(_process.memory().Write(alloc_ptr, AsmCore->getCodeSize(), lpAddress)))
            return false;

        // handler
        _handler_length = AsmCore->getCodeSize();
        _handler = alloc_ptr;

        // handler  UseAbsoluteIndirectJumps
        _ptr_handler += alloc_ptr;

        // trampoline
        _trampoline += alloc_ptr;

        if (!bNewTrampoline)
        {
            // ministub
            _ministub += alloc_ptr;
        }
    }

    ZYAN_ASSERT(_handler_length);

    return 0 < _handler_length;
}


boolean CHookEntry::HookCommon()
{
    if (false == EnableHookCommon(!FlagOn(_uHookFlags, enum_HookFlags::DontEnableHooks)))
        return false;

    if (false == CompilerGenericHookFn())
        return false;

    // jmp To hander
    {
        auto jmpToThunk = blackbone::AsmFactory::GetAssembler();
        auto& AsmCore = *jmpToThunk;
        AsmCore.EnableX64CallStack(_is64Bit);

        if (FlagOn(_uHookFlags, enum_HookFlags::UseAbsoluteIndirectJumps)) {
            AsmCore->db(0xFF); AsmCore->db(0x25);

            if(_is64Bit) // relative address
                AsmCore->dd(uint32_t(_ptr_handler - _codesAddress - GetJumpToHookBytes()));
            else // absolute address
                AsmCore->dd(uint32_t(_ptr_handler));
        }
        else {
            AsmCore->db(0xE9);
            AsmCore->dd(uint32_t(_handler - _codesAddress - GetJumpToHookBytes()));
        }

        auto jmpCodeSize = AsmCore->getCodeSize();
        auto jmpCode = reinterpret_cast<void(*)()>(AsmCore->make());

        DWORD oldProtect = PAGE_EXECUTE_READ;

        return NT_SUCCESS(_process.memory().Protect(_codesAddress, jmpCodeSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            && NT_SUCCESS(_process.memory().Write(_codesAddress, jmpCodeSize, jmpCode))
            && NT_SUCCESS(_process.memory().Protect(_codesAddress, jmpCodeSize, oldProtect));
    }
}

boolean CHookEntry::UnhookCommon()
{
    if (false == EnableHookCommon(false))
        return false;

    if (FlagOn(_uHookFlags, enum_HookFlags::DontRemoveOnUnhook))
        return true;

    return NT_SUCCESS(_process.memory().Write(_codesAddress, _codes_length, _codes));
}

boolean CHookEntry::EnableHookCommon(boolean bEnable)
{
    if (!NT_SUCCESS(_process.memory().Read(_lpHookStatus, sizeof(volatile LONG), &_lHookStatus)))
        return false;

    if (bEnable)
        _InterlockedAnd(&_lHookStatus, 0xFFFF00FF);
    else
        _InterlockedOr(&_lHookStatus, 0x00000100);

    return NT_SUCCESS(_process.memory().Write(_lpHookStatus, sizeof(volatile LONG), &_lHookStatus));
}




class CHookHelper : CHookEntry
{
public:

    typedef struct {
        size_t nHookId;
        uint32_t uHookFlags;
        boolean bEnable;
        uint64_t fnTrampoline;
    } HookInfos;

    ~CHookHelper() {
        UnAllhook();
    };

    CHookHelper(HANDLE hProcess = ::GetCurrentProcess()) {
        auto status = _process.Attach(hProcess);
        ZYAN_ASSERT(status == STATUS_SUCCESS);
    };

    CHookHelper(DWORD dwProcessId) {
        DWORD dwDesiredAccess =
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
            | PROCESS_VM_READ | PROCESS_VM_WRITE;

        if (FALSE == NT_SUCCESS(_process.Attach(dwProcessId, dwDesiredAccess)))
        {
            if ((dwDesiredAccess & (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)) == PROCESS_QUERY_INFORMATION)
            {
                dwDesiredAccess &= (~PROCESS_QUERY_INFORMATION);
                dwDesiredAccess |= PROCESS_QUERY_LIMITED_INFORMATION;
                auto status = _process.Attach(dwProcessId, dwDesiredAccess);
                ZYAN_ASSERT(status == STATUS_SUCCESS);
            }
        }
    };

    size_t Hook(LPCWSTR wModule, LPCSTR funcName, uint32_t HookFlags, uint64_t lpCallBack
        , uint64_t * lpTrampoline) {

        auto entry = new CHookEntry(_process.core().handle());

        HookedLinkedList.add(entry);

        auto fuc = _process.modules().GetExport(wModule, funcName);
        ZYAN_ASSERT(STATUS_SUCCESS == fuc.status);

        size_t id = entry->Hook(fuc->procAddress, HookFlags, lpCallBack);

        if (NULL != lpTrampoline)
            *lpTrampoline = entry->getTrampoline();

        return id;
    };

    size_t Hook(uint64_t runtimeAddress, uint32_t HookFlags, uint64_t lpCallBack
        , uint64_t* lpTrampoline) {

        auto entry = new CHookEntry(_process.core().handle());

        HookedLinkedList.add(entry);

        size_t id = entry->Hook(runtimeAddress, HookFlags, lpCallBack);

        if (NULL != lpTrampoline)
            *lpTrampoline = entry->getTrampoline();
        
        return id;
    };

    boolean QueueHookInfos(HookInfos& infos)
    {
        if (0 == infos.nHookId)
            return false;

        for (int idx = 0; idx < HookedLinkedList.size(); idx++)
        {
            auto entry = HookedLinkedList.get(idx);

            if (infos.nHookId == entry->getId()) {
                infos.uHookFlags = entry->getHookFlags();
                infos.bEnable = entry->QueueEnableHook();
                infos.fnTrampoline = entry->getTrampoline();
                return true;
            }
        }

        return false;
    }

    boolean QueueEnableHook(size_t id, boolean * pIsEnable)
    {
        if (NULL == pIsEnable)
            return false;

        for (int idx = 0; idx < HookedLinkedList.size(); idx++)
        {
            auto entry = HookedLinkedList.get(idx);

            if (id == entry->getId()) {
                *pIsEnable = entry->QueueEnableHook();
                return true;
            }
        }

        return false;
    }

    boolean EnableHook(size_t id, boolean bEnable)
    {
        for (int idx = 0; idx < HookedLinkedList.size(); idx++)
        {
            auto entry = HookedLinkedList.get(idx);

            if (id == entry->getId())
                return entry->EnableHook(bEnable);
        }

        return false;
    }

    boolean Unhook(size_t id)
    {
        boolean bSuccess = false;

        for (int idx = 0; idx < HookedLinkedList.size(); idx++)
        {
            auto entry = HookedLinkedList.get(idx);

            if (id == entry->getId())
            {
                bSuccess = entry->Unhook();

                HookedLinkedList.remove(idx);

                delete entry; entry = NULL;

                return bSuccess;
            }
        }

        return false;
    };

    boolean UnAllhook()
    {
        boolean bSuccess = false;

        while (auto entry = HookedLinkedList.shift())
        {
            bSuccess |= entry->Unhook();

            delete entry; entry = NULL;
        }

        return bSuccess;
    }

private:

    blackbone::Process _process;

    LinkedList<CHookEntry*> HookedLinkedList = LinkedList<CHookEntry*>();
};








