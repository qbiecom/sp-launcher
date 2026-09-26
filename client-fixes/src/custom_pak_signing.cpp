#include "custom_pak_signing.hpp"
#include "clientfixes_public_key.hpp"
#include <bcrypt.h>
#include <tlhelp32.h>
#include <array>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace clientfixes_signing {
namespace {
constexpr std::uintptr_t kValidateRva = 0x3eb4d20;
constexpr unsigned char kPrologue[] = {
    0x40,0x55,0x53,0x56,0x57,0x41,0x56,0x48,0x8d,0x6c,0x24,0xc9,
    0x48,0x81,0xec,0x90,0x00,0x00,0x00
};
constexpr char kDomain[] = "SPClientFixes-Pak-v1"; // Includes terminating zero.
struct Array { std::uintptr_t data; std::int32_t count, capacity; };
using Validate = bool (*)(void*, void*, const Array*);
Validate original = nullptr;
using Find = unsigned char (*)(void*, const Array*, void*);
Find originalFind = nullptr;
std::atomic<unsigned int> tableMessages{0};
Logger logMessage = nullptr;
std::wstring expectedPath;
volatile LONG* recentPakLookup = nullptr;
bool lookupLogged = false;
BCRYPT_ALG_HANDLE rsaAlgorithm = nullptr;
BCRYPT_KEY_HANDLE publicKey = nullptr;
std::atomic<HANDLE> lockedPak{INVALID_HANDLE_VALUE};

bool ReadBytes(std::uintptr_t address, void* output, std::size_t size) {
    SIZE_T read=0;
    return address && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),
                                        output,size,&read) && read==size;
}
void Log(const wchar_t* text) { if (logMessage) logMessage(text); }

struct Sha256 {
    BCRYPT_ALG_HANDLE algorithm=nullptr;
    BCRYPT_HASH_HANDLE hash=nullptr;
    std::vector<unsigned char> storage;
    ~Sha256() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm,0);
    }
    bool Start() {
        ULONG size=0,got=0;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)) ||
            !BCRYPT_SUCCESS(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&size),sizeof(size),&got,0)) || !size || size>4096) return false;
        storage.resize(size);
        return BCRYPT_SUCCESS(BCryptCreateHash(algorithm,&hash,storage.data(),size,nullptr,0,0));
    }
    bool Add(const void* data, ULONG size) {
        return BCRYPT_SUCCESS(BCryptHashData(hash,static_cast<PUCHAR>(const_cast<void*>(data)),size,0));
    }
    bool Finish(std::array<unsigned char,32>& digest) {
        return BCRYPT_SUCCESS(BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0));
    }
};

bool InitializeKey() {
    if (publicKey) return true;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&rsaAlgorithm,BCRYPT_RSA_ALGORITHM,nullptr,0))) return false;
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(rsaAlgorithm,nullptr,BCRYPT_RSAPUBLIC_BLOB,&publicKey,
        const_cast<PUCHAR>(kClientFixesPublicKey),sizeof(kClientFixesPublicKey),0))) return false;
    return true;
}

std::wstring CanonicalPath(const std::wstring& path) {
    std::vector<wchar_t> buffer(32768);
    DWORD count=GetFullPathNameW(path.c_str(),static_cast<DWORD>(buffer.size()),buffer.data(),nullptr);
    if (!count || count>=buffer.size()) return {};
    return {buffer.data(),count};
}

bool CustomName(const Array* name) {
    Array value{};
    if (!ReadBytes(reinterpret_cast<std::uintptr_t>(name),&value,sizeof(value)) ||
        value.count<2 || value.count>32768 || value.count>value.capacity) return false;
    std::vector<wchar_t> text(static_cast<std::size_t>(value.count));
    if (!ReadBytes(value.data,text.data(),text.size()*sizeof(wchar_t)) || text.back()!=0) return false;
    std::wstring path(text.data(),text.size()-1);
    if (path.find(L'\0')!=std::wstring::npos) return false;
    const auto full=CanonicalPath(path);
    return !full.empty() && _wcsicmp(full.c_str(),expectedPath.c_str())==0;
}

bool ValidateCustom(void* table) {
    // FPakSignatureFile: version +0, encrypted signature TArray +8,
    // cached master SHA1 +0x18, chunk CRC TArray +0x30. Exact preserved build only.
    std::int32_t version=-1;
    Array signature{},chunks{};
    const auto address=reinterpret_cast<std::uintptr_t>(table);
    if (!ReadBytes(address,&version,sizeof(version)) || version!=1 ||
        !ReadBytes(address+8,&signature,sizeof(signature)) || signature.count!=512 ||
        signature.capacity<signature.count || signature.capacity>4096 ||
        !ReadBytes(address+0x30,&chunks,sizeof(chunks)) || chunks.count<1 ||
        chunks.count>1048576 || chunks.capacity<chunks.count || chunks.capacity>1048576) return false;
    std::array<unsigned char,512> signedBytes{};
    std::vector<unsigned char> chunkBytes(static_cast<std::size_t>(chunks.count)*4);
    if (!ReadBytes(signature.data,signedBytes.data(),signedBytes.size()) ||
        !ReadBytes(chunks.data,chunkBytes.data(),chunkBytes.size())) return false;
    HANDLE file=CreateFileW(expectedPath.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,
                            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    bool okay=VerifyFile(file,signedBytes.data(),signedBytes.size(),chunkBytes.data(),chunkBytes.size());
    if (okay) {
        // Keep a read-only sharing handle until exit, preventing on-disk replacement
        // after successful verification. The engine still checks each chunk CRC.
        HANDLE empty=INVALID_HANDLE_VALUE;
        if (!lockedPak.compare_exchange_strong(empty,file)) CloseHandle(file);
    } else CloseHandle(file);
    return okay;
}

bool Hook(void* table, void* originalKey, const Array* name) {
    // All other filenames take the original validator with its original key.
    try {
        if (!CustomName(name)) return original(table,originalKey,name);
        const bool accepted=ValidateCustom(table);
        Log(accepted ? L"ClientFixes PAK: custom signature verified.\r\n"
                     : L"ClientFixes PAK: custom signature rejected.\r\n");
        return accepted;
    } catch (...) {
        Log(L"ClientFixes PAK: verification failed; refusing archive.\r\n");
        return false;
    }
}

std::wstring ReadString(std::uintptr_t address) {
    Array value{};
    if (!ReadBytes(address,&value,sizeof(value)) || value.count<1 ||
        value.count>32768 || value.capacity<value.count) return {};
    std::wstring text(static_cast<std::size_t>(value.count),L'\0');
    if (!ReadBytes(value.data,text.data(),text.size()*sizeof(wchar_t)) || text.back()!=0) return {};
    text.pop_back();
    return text;
}

unsigned char FindHook(void* pak, const Array* filename, void* entry) {
    const auto result=originalFind(pak,filename,entry);
    // Inspect only the filename suffix before allocating text. The diagnostic
    // returns the original result and never changes file selection or contents.
    try {
        Array name{};
        std::array<wchar_t,18> suffix{};
        if (tableMessages.load()>=64 ||
            !ReadBytes(reinterpret_cast<std::uintptr_t>(filename),&name,sizeof(name)) ||
            name.count<18 || name.count>32768 || name.capacity<name.count ||
            !ReadBytes(name.data+(name.count-18)*sizeof(wchar_t),suffix.data(),sizeof(suffix)) ||
            suffix.back()!=0 || !std::wcsstr(suffix.data(),L"CheatTable.")) return result;
        const auto address=reinterpret_cast<std::uintptr_t>(pak);
        const auto archive=ReadString(address+0x18);
        const bool custom=archive.find(L"BravoHotelGame-ClientFixes_P.pak")!=std::wstring::npos;
        if (!custom && result==0) return result;
        const auto mount=ReadString(address+0x108);
        LONG cache=-1;
        if (recentPakLookup) ReadBytes(reinterpret_cast<std::uintptr_t>(recentPakLookup),&cache,sizeof(cache));
        if (tableMessages.fetch_add(1)>=64) return result;
        std::array<wchar_t,2048> message{};
        _snwprintf_s(message.data(),message.size(),_TRUNCATE,
            L"ClientFixes PAK lookup: %ls; archive=%ls; result=%u; cache=%ld; mount=%ls\r\n",
            suffix.data(),archive.c_str(),static_cast<unsigned int>(result),cache,mount.c_str());
        Log(message.data());
    } catch (...) { /* Diagnostics must not change the engine result. */ }
    return result;
}

void AbsoluteJump(unsigned char* output, const void* target) {
    output[0]=0xff; output[1]=0x25;
    std::memset(output+2,0,4);
    const auto address=reinterpret_cast<std::uintptr_t>(target);
    std::memcpy(output+6,&address,8);
}

// Pause existing game threads briefly while replacing the complete prologue.
// Refuse the patch if a thread is currently executing inside that prologue.
struct PausedThreads {
    std::array<HANDLE,2048> handles{};
    std::size_t count=0;
    ~PausedThreads() {
        while (count) { HANDLE thread=handles[--count]; ResumeThread(thread); CloseHandle(thread); }
    }
    bool Pause(std::uintptr_t address, std::size_t size) {
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        if (snapshot==INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 entry{}; entry.dwSize=sizeof(entry);
        bool okay=Thread32First(snapshot,&entry)!=FALSE;
        while (okay) {
            if (entry.th32OwnerProcessID==GetCurrentProcessId() && entry.th32ThreadID!=GetCurrentThreadId()) {
                if (count==handles.size()) { okay=false; break; }
                HANDLE thread=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,
                                         FALSE,entry.th32ThreadID);
                if (!thread) { okay=false; break; }
                if (SuspendThread(thread)==static_cast<DWORD>(-1)) { CloseHandle(thread); okay=false; break; }
                handles[count++]=thread;
                CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
                if (!GetThreadContext(thread,&context) ||
                    (context.Rip>=address && context.Rip<address+size)) { okay=false; break; }
            }
            if (!Thread32Next(snapshot,&entry)) {
                okay=GetLastError()==ERROR_NO_MORE_FILES;
                break;
            }
        }
        CloseHandle(snapshot);
        return okay;
    }
};
bool InstallLookupDiagnostic(std::uintptr_t base) {
    // Three complete stack-save instructions; no RIP-relative operands.
    constexpr unsigned char prologue[] = {
        0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18
    };
    auto target=reinterpret_cast<unsigned char*>(base+0x3eb7eb0);
    std::array<unsigned char,sizeof(prologue)> actual{};
    if (!ReadBytes(reinterpret_cast<std::uintptr_t>(target),actual.data(),actual.size()) ||
        std::memcmp(actual.data(),prologue,sizeof(prologue))!=0) return false;
    auto trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,64,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!trampoline) return false;
    std::memcpy(trampoline,prologue,sizeof(prologue));
    AbsoluteJump(trampoline+sizeof(prologue),target+sizeof(prologue));
    DWORD protection=0;
    if (!VirtualProtect(trampoline,64,PAGE_EXECUTE_READ,&protection) ||
        !FlushInstructionCache(GetCurrentProcess(),trampoline,64)) {
        VirtualFree(trampoline,0,MEM_RELEASE); return false;
    }
    originalFind=reinterpret_cast<Find>(trampoline);
    std::array<unsigned char,sizeof(prologue)> patch{};
    patch.fill(0x90);
    AbsoluteJump(patch.data(),reinterpret_cast<void*>(&FindHook));
    bool installed=false;
    {
        PausedThreads paused;
        if (paused.Pause(reinterpret_cast<std::uintptr_t>(target),sizeof(prologue)) &&
            ReadBytes(reinterpret_cast<std::uintptr_t>(target),actual.data(),actual.size()) &&
            std::memcmp(actual.data(),prologue,sizeof(prologue))==0 &&
            VirtualProtect(target,sizeof(prologue),PAGE_EXECUTE_READWRITE,&protection)) {
            std::memcpy(target,patch.data(),patch.size());
            FlushInstructionCache(GetCurrentProcess(),target,patch.size());
            DWORD ignored=0;
            VirtualProtect(target,sizeof(prologue),protection,&ignored);
            installed=true;
        }
    }
    if (!installed) { originalFind=nullptr; VirtualFree(trampoline,0,MEM_RELEASE); }
    return installed;
}
} // namespace

bool VerifyFile(HANDLE file, const unsigned char* signature, std::size_t signatureSize,
                const unsigned char* chunks, std::size_t chunksSize) {
    if (!signature || signatureSize!=512 || !chunks || !chunksSize || chunksSize%4 ||
        chunksSize>4194304 || !InitializeKey()) return false;
    LARGE_INTEGER length{},zero{};
    if (!GetFileSizeEx(file,&length) || length.QuadPart<=0 ||
        static_cast<std::uint64_t>((length.QuadPart+65535)/65536)!=chunksSize/4 ||
        !SetFilePointerEx(file,zero,nullptr,FILE_BEGIN)) return false;
    Sha256 pakHash;
    if (!pakHash.Start()) return false;
    std::array<unsigned char,65536> buffer{};
    std::uint64_t total=0;
    for (;;) {
        DWORD read=0;
        if (!ReadFile(file,buffer.data(),static_cast<DWORD>(buffer.size()),&read,nullptr)) return false;
        if (!read) break;
        total+=read;
        if (!pakHash.Add(buffer.data(),read)) return false;
    }
    if (total!=static_cast<std::uint64_t>(length.QuadPart)) return false;
    std::array<unsigned char,32> pakDigest{},messageDigest{};
    Sha256 message;
    if (!pakHash.Finish(pakDigest) || !message.Start() ||
        !message.Add(kDomain,sizeof(kDomain)) || !message.Add(pakDigest.data(),static_cast<ULONG>(pakDigest.size())) ||
        !message.Add(chunks,static_cast<ULONG>(chunksSize)) || !message.Finish(messageDigest)) return false;
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    return BCRYPT_SUCCESS(BCryptVerifySignature(publicKey,&padding,messageDigest.data(),
        static_cast<ULONG>(messageDigest.size()),const_cast<PUCHAR>(signature),
        static_cast<ULONG>(signatureSize),BCRYPT_PAD_PKCS1));
}

bool Install(std::uintptr_t base, Logger logger) {
    logMessage=logger;
    std::array<wchar_t,32768> executable{};
    DWORD length=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
    if (!length || length>=executable.size()) return false;
    std::wstring path(executable.data(),length);
    const auto slash=path.find_last_of(L"\\/");
    if (slash==std::wstring::npos) return false;
    expectedPath=CanonicalPath(path.substr(0,slash)+L"\\..\\..\\Content\\Paks\\BravoHotelGame-ClientFixes_P.pak");
    if (expectedPath.empty() || !InitializeKey()) return false;
    auto target=reinterpret_cast<unsigned char*>(base+kValidateRva);
    std::array<unsigned char,sizeof(kPrologue)> actual{};
    if (!ReadBytes(reinterpret_cast<std::uintptr_t>(target),actual.data(),actual.size()) ||
        std::memcmp(actual.data(),kPrologue,sizeof(kPrologue))!=0) return false;
    auto trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,64,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!trampoline) return false;
    std::memcpy(trampoline,kPrologue,sizeof(kPrologue));
    AbsoluteJump(trampoline+sizeof(kPrologue),target+sizeof(kPrologue));
    DWORD protection=0;
    if (!VirtualProtect(trampoline,64,PAGE_EXECUTE_READ,&protection) ||
        !FlushInstructionCache(GetCurrentProcess(),trampoline,64)) {
        VirtualFree(trampoline,0,MEM_RELEASE); return false;
    }
    original=reinterpret_cast<Validate>(trampoline);
    std::array<unsigned char,sizeof(kPrologue)> patch{};
    patch.fill(0x90);
    AbsoluteJump(patch.data(),reinterpret_cast<void*>(&Hook));
    bool installed=false;
    {
        PausedThreads paused;
        if (paused.Pause(reinterpret_cast<std::uintptr_t>(target),sizeof(kPrologue)) &&
            ReadBytes(reinterpret_cast<std::uintptr_t>(target),actual.data(),actual.size()) &&
            std::memcmp(actual.data(),kPrologue,sizeof(kPrologue))==0 &&
            VirtualProtect(target,sizeof(kPrologue),PAGE_EXECUTE_READWRITE,&protection)) {
            std::memcpy(target,patch.data(),patch.size());
            FlushInstructionCache(GetCurrentProcess(),target,patch.size());
            DWORD ignored=0;
            VirtualProtect(target,sizeof(kPrologue),protection,&ignored);
            installed=true;
        }
    }
    if (!installed) { original=nullptr; VirtualFree(trampoline,0,MEM_RELEASE); return false; }
    Log(L"ClientFixes PAK: scoped signing hook installed; original PAK validation preserved.\r\n");
    // The registration passes this int by reference and the file lookup reads
    // it directly. Validate both RIP-relative instructions before using it.
    constexpr unsigned char lookupCheck[] = {0x83,0x3d,0x58,0x83,0x8a,0x03,0x00};
    constexpr unsigned char registration[] = {0x4c,0x8d,0x05,0xc3,0xed,0x8c,0x06};
    std::array<unsigned char,7> check{},reference{};
    MEMORY_BASIC_INFORMATION region{};
    auto value = reinterpret_cast<volatile LONG*>(base+0x77508f0);
    const DWORD attributes=GetFileAttributesW(expectedPath.c_str());
    if (attributes!=INVALID_FILE_ATTRIBUTES && !(attributes&FILE_ATTRIBUTE_DIRECTORY) &&
        ReadBytes(base+0x3eb8591,check.data(),check.size()) &&
        ReadBytes(base+0xe91b26,reference.data(),reference.size()) &&
        std::memcmp(check.data(),lookupCheck,sizeof(lookupCheck))==0 &&
        std::memcmp(reference.data(),registration,sizeof(registration))==0 &&
        VirtualQuery(reinterpret_cast<const void*>(base+0x77508f0),&region,sizeof(region)) &&
        region.State==MEM_COMMIT && !(region.Protect&(PAGE_GUARD|PAGE_NOACCESS)) &&
        (region.Protect&(PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
        recentPakLookup=value;
        MaintainPriorityLookup();
    } else {
        Log(L"ClientFixes PAK: priority lookup control unavailable or custom PAK absent.\r\n");
    }
    wchar_t diagnosticSetting[2]{};
    if (GetEnvironmentVariableW(L"SP_CLIENT_FIXES_CONSOLE",diagnosticSetting,2)==1 && diagnosticSetting[0]==L'1') {
        Log(InstallLookupDiagnostic(base)
            ? L"ClientFixes PAK: CheatTable lookup diagnostic installed (result 0=missing, 1=found, 2=deleted).\r\n"
            : L"ClientFixes PAK: CheatTable lookup diagnostic could not be installed.\r\n");
    }
    return true;
}
void MaintainPriorityLookup() {
    if (!recentPakLookup) return;
    const LONG previous=InterlockedExchange(recentPakLookup,0);
    if (!lookupLogged || previous!=0) {
        Log(previous!=0
            ? L"ClientFixes PAK: lookup cache changed from nonzero to 0; priority lookup active.\r\n"
            : L"ClientFixes PAK: lookup cache confirmed 0; priority lookup active.\r\n");
        lookupLogged=true;
    }
}
} // namespace clientfixes_signing
