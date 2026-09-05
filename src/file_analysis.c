#include "../include/wintriage.h"
#include <bcrypt.h>
#include <softpub.h>
#include <wintrust.h>
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

static int sha256_file(const wchar_t *path, BYTE digest[32]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE buffer[65536];
    DWORD read = 0;
    int ok = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) goto cleanup;
    if (BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) != 0) goto cleanup;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) goto cleanup;
    while (ReadFile(file, buffer, sizeof(buffer), &read, NULL) && read) {
        if (BCryptHashData(hash, buffer, read, 0) != 0) goto cleanup;
    }
    if (GetLastError() != ERROR_SUCCESS && read != 0) goto cleanup;
    if (BCryptFinishHash(hash, digest, 32, 0) != 0) goto cleanup;
    ok = 1;
cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    SecureZeroMemory(buffer, sizeof(buffer));
    return ok;
}

static LONG signature_status(const wchar_t *path) {
    WINTRUST_FILE_INFO file_info = {0};
    WINTRUST_DATA data = {0};
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file_info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG status = WinVerifyTrust(NULL, &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &data);
    return status;
}

static void write_pe_summary(FILE *file, const wchar_t *path) {
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE mapping = NULL;
    BYTE *view = NULL;
    LARGE_INTEGER file_size = {0};
    const wchar_t *kind = L"not_pe";
    WORD machine = 0, sections = 0;
    DWORD entry = 0;
    if (handle == INVALID_HANDLE_VALUE) goto output;
    if (!GetFileSizeEx(handle, &file_size) ||
        file_size.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER)) goto output;
    mapping = CreateFileMappingW(handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) goto output;
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) goto output;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) goto output;
    if ((ULONGLONG)dos->e_lfanew >
        (ULONGLONG)file_size.QuadPart - sizeof(DWORD) - sizeof(IMAGE_FILE_HEADER)) goto output;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto output;
    if ((ULONGLONG)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader > (ULONGLONG)file_size.QuadPart) goto output;
    machine = nt->FileHeader.Machine;
    sections = nt->FileHeader.NumberOfSections;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)nt;
        entry = nt64->OptionalHeader.AddressOfEntryPoint;
        kind = L"PE32+";
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               nt->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)nt;
        entry = nt32->OptionalHeader.AddressOfEntryPoint;
        kind = L"PE32";
    }
output:
    fputws(L",\"pe_kind\":", file);
    wt_json_string(file, kind);
    fwprintf(file, L",\"machine\":%u,\"sections\":%u,\"entry_point_rva\":%lu",
             machine, sections, entry);
    if (view) UnmapViewOfFile(view);
    if (mapping) CloseHandle(mapping);
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
}

int wt_write_file_analysis(WT_REPORT *report, const wchar_t *path) {
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    BYTE digest[32] = {0};
    int hashed = sha256_file(path, digest);
    int exists = GetFileAttributesExW(path, GetFileExInfoStandard, &attributes);
    fputws(L"  \"file_analysis\":{\"path\":", report->file);
    wt_json_string(report->file, path);
    fputws(L",\"sha256\":", report->file);
    if (hashed) {
        wchar_t hex[65];
        for (int i = 0; i < 32; ++i) swprintf_s(hex + i * 2, 3, L"%02x", digest[i]);
        wt_json_string(report->file, hex);
    } else {
        fputws(L"null", report->file);
    }
    if (exists) {
        ULARGE_INTEGER size;
        size.HighPart = attributes.nFileSizeHigh;
        size.LowPart = attributes.nFileSizeLow;
        fwprintf(report->file, L",\"size\":%llu", size.QuadPart);
    } else {
        fputws(L",\"size\":null", report->file);
    }
    fwprintf(report->file, L",\"authenticode_status\":%ld", signature_status(path));
    write_pe_summary(report->file, path);
    fputwc(L'}', report->file);
    SecureZeroMemory(digest, sizeof(digest));
    return exists && hashed;
}
