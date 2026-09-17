#include "Dumper.hpp"
#include <sstream>
#include <skCrypter/skCrypter.hpp>
#include "core/engine/Engine.hpp"
#include "core/anti_debug/AntiDebug.hpp"
#include <lazy_importer/lazy_importer.hpp>

bool Dumper::Init() {
    return GetInstance().InitImpl();
}

bool Dumper::InitImpl() {
    auto client = Engine::GetClient();

    // Hardcoded offsets from cs2-dumper 2026-08-27 14:43 UTC.
    offsets::viewMatrix            = 0x23CB830;
    offsets::entityList            = 0x2571230;
    offsets::localPlayerController = 0x23A0F30;
    offsets::globalVars            = 0x20AF5F0;
    offsets::plantedC4             = 0x2390A18;
    offsets::localPlayerPawn       = 0x23C6268;
    offsets::csgoInput             = 0x23DBC80;
    offsets::viewAngles            = 0x23DC308;
    offsets::buildNumber           = 0x60F594;

    printf(skCrypt("[SysMonitor] offsets loaded\n"));

    return true;
}

DWORD64 Dumper::Scan(const std::string sig, ProcessModule module) {
    // Try disk-based scan first (immune to FaceIT RPM hooks)
    DWORD64 result = ScanFromDisk(sig, module);
    if (result) return result;

    // Fallback: live process memory scan
    auto process = Engine::GetProcess();
    if (!process) return 0;

    std::vector<DWORD64> list = ScanMemory(sig, module.base, module.base + 0x4000000);
    if (list.empty()) return 0;

    DWORD offsets = 0;
    if (!process->read_raw(list.at(0) + 3, &offsets, sizeof(DWORD))) return 0;
    return list.at(0) + offsets + 7;
}

// Get the on-disk path for a memory-mapped module.
// Uses NtQueryVirtualMemory(MemoryMappedFilenameInformation) � no RPM needed.
bool Dumper::GetModuleDiskPath(ProcessModule module, wchar_t* outPath, size_t outLen) {
    auto process = Engine::GetProcess();
    if (!process || !process->handle_) return false;

    typedef NTSTATUS(WINAPI* NtQVM_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    auto NtQVM = (NtQVM_t)li::detail::resolve(0xBE4E761Fu);
    if (!NtQVM) return false;

    struct { USHORT Len, Max; ULONG Pad; PWSTR Buf; wchar_t Data[MAX_PATH * 2]; } ni = {};
    SIZE_T ret = 0;
    if (NtQVM(process->handle_, (PVOID)module.base, 2, &ni, sizeof(ni), &ret) != 0 || !ni.Len)
        return false;

    // ni.Data contains device path: \Device\HarddiskVolumeX\path\to\file.dll
    // Convert to drive letter path
    wchar_t drives[512] = {};
    GetLogicalDriveStringsW(512, drives);
    for (wchar_t* drv = drives; *drv; drv += wcslen(drv) + 1) {
        wchar_t devName[3] = { drv[0], drv[1], 0 };
        wchar_t device[MAX_PATH] = {};
        QueryDosDeviceW(devName, device, MAX_PATH);
        size_t devLen = wcslen(device);
        if (_wcsnicmp(ni.Data, device, devLen) == 0) {
            swprintf_s(outPath, outLen, L"%s%s", devName, ni.Data + devLen);
            return true;
        }
    }
    return false;
}

// Scan for a signature in the module's on-disk PE image.
// Code sections (.text) are identical on disk and in memory (wildcards cover relocations).
// Returns the resolved virtual address (module.base + RVA + extracted_offset + 7).
DWORD64 Dumper::ScanFromDisk(const std::string& sig, ProcessModule module) {
    wchar_t diskPath[MAX_PATH * 2] = {};
    if (!GetModuleDiskPath(module, diskPath, MAX_PATH * 2)) return 0;

    HANDLE hFile = CreateFileW(diskPath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER fs = {};
    GetFileSizeEx(hFile, &fs);
    if (fs.QuadPart < 0x1000 || fs.QuadPart > 512LL * 1024 * 1024) {
        CloseHandle(hFile); return 0;
    }

    std::vector<uint8_t> file((size_t)fs.QuadPart);
    DWORD bytesRead = 0;
    ReadFile(hFile, file.data(), (DWORD)fs.QuadPart, &bytesRead, nullptr);
    CloseHandle(hFile);
    if (bytesRead < 0x1000) return 0;

    // Parse PE sections
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto* secs = IMAGE_FIRST_SECTION(nt);
    WORD  nSec = nt->FileHeader.NumberOfSections;

    auto sigBytes = StrSigToArray(sig);
    if (sigBytes.empty()) return 0;

    for (WORD s = 0; s < nSec; s++) {
        auto& sec = secs[s];
        if (!sec.PointerToRawData || !sec.SizeOfRawData) continue;
        // Only scan executable sections
        if (!(sec.Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        uint8_t* data = file.data() + sec.PointerToRawData;
        DWORD    dSz  = sec.SizeOfRawData;

        for (DWORD i = 0; i + sigBytes.size() + 7 <= dSz; i++) {
            bool match = true;
            for (size_t j = 0; j < sigBytes.size() && match; j++)
                if (sigBytes[j] != 256 && sigBytes[j] != data[i + j]) match = false;

            if (match) {
                // Convert file-section offset back to virtual address
                DWORD inSection = i;
                DWORD64 patternVA = module.base + sec.VirtualAddress + inSection;

                // Extract the RIP-relative offset embedded at pattern+3
                // (same bytes on disk as in memory for non-relocated data)
                int32_t relOff = *reinterpret_cast<int32_t*>(data + i + 3);
                DWORD64 resolved = patternVA + relOff + 7;
                LOGF(VERBOSE, "ScanFromDisk: found sig in [{}] at VA 0x{:X} -> 0x{:X}",
                     std::string((char*)sec.Name, 8).c_str(), patternVA, resolved);
                return resolved;
            }
        }
    }
    return 0;
}

std::vector<WORD> Dumper::StrSigToArray(const std::string& sig) {
    std::istringstream iss(sig);
    std::vector<WORD> bytes;
    std::string byte_str;

    while (iss >> byte_str) {
        if (byte_str == "??" || byte_str == "?")
            bytes.push_back(256);
        else
            bytes.push_back(static_cast<WORD>(std::stoul(byte_str, nullptr, 16)));
    }
    return bytes;
}

void Dumper::GetNextArray(std::vector<short>& next, const std::vector<WORD>& signature)
{
    auto size = signature.size();
    for (int i = 0; i < size; i++)
        next[signature[i]] = i;
}

void Dumper::ScanBlock(byte* buffer, const std::vector<short>& next, const std::vector<WORD>& signature, DWORD64 start, DWORD size, std::vector<DWORD64>& result)
{
    auto process = Engine::GetProcess();

    if (!process->read_raw(start, buffer, size))
        return;

    int length = signature.size();

    for (int i = 0, j, k; i < size;)
    {
        j = i; k = 0;

        for (; k < length && j < size && (signature[k] == buffer[j] || signature[k] == 256); k++, j++);

        if (k == length)
            result.push_back(start + i);

        if ((i + length) >= size)
            return;

        int Num = next[buffer[i + length]];
        if (Num == -1)
            i += (length - next[256]);
        else
            i += (length - Num);
    }
}

std::vector<DWORD64> Dumper::ScanMemory(const std::string& sig, DWORD64 start, DWORD64 end, int number)
{
    std::vector<DWORD64> result;
    std::vector<short> next(260, -1);

    auto process = Engine::GetProcess();

    if (!process)
        return result;

    byte* buffer = new byte[MAX_BLOCK_SIZE];

    auto signature = StrSigToArray(sig);
    if (!signature.size())
        return result;

    GetNextArray(next, signature);

    MEMORY_BASIC_INFORMATION mbi;
    using FVQE = SIZE_T(WINAPI*)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    auto pVirtualQueryEx = reinterpret_cast<FVQE>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("VirtualQueryEx")));
    while (pVirtualQueryEx(process->handle_, reinterpret_cast<LPCVOID>(start), &mbi, sizeof(mbi)) != 0)
    {
        int searches = 0;
        auto size = mbi.RegionSize;

        while (size >= MAX_BLOCK_SIZE)
        {
            if (result.size() >= number) {
                delete[] buffer;
	            return result;
            }

            ScanBlock(buffer, next, signature, start + (MAX_BLOCK_SIZE * searches), MAX_BLOCK_SIZE, result);

            size -= MAX_BLOCK_SIZE;
            searches++;
        }

        ScanBlock(buffer, next, signature, start + (MAX_BLOCK_SIZE * searches), size, result);

        start += mbi.RegionSize;

        if (result.size() >= number || end != 0 && start > end)
            break;
    }

	delete[] buffer;
	return result;
}