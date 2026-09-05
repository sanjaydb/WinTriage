#include "../include/wintriage.h"
#include <winsvc.h>
#include <stdlib.h>
#pragma comment(lib, "Advapi32.lib")

static int write_run_key(FILE *file, HKEY root, const wchar_t *root_name,
                         const wchar_t *path, int *first) {
    HKEY key = NULL;
    DWORD index = 0;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS) return 0;
    for (;;) {
        wchar_t name[512];
        BYTE data[32768];
        DWORD name_size = ARRAYSIZE(name);
        DWORD data_size = sizeof(data);
        DWORD type = 0;
        LONG status = RegEnumValueW(key, index++, name, &name_size, NULL, &type, data, &data_size);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        data[sizeof(data) - sizeof(wchar_t)] = 0;
        if (!*first) fputwc(L',', file);
        fputws(L"\n    {\"location\":", file);
        wt_json_string(file, root_name);
        fputws(L",\"name\":", file);
        wt_json_string(file, name);
        fputws(L",\"command\":", file);
        wt_json_string(file, (wchar_t *)data);
        fputwc(L'}', file);
        *first = 0;
    }
    RegCloseKey(key);
    return 1;
}

static void write_auto_services(FILE *file, int *first) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    DWORD needed = 0, count = 0, resume = 0;
    BYTE *buffer = NULL;
    if (!manager) return;
    EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &needed, &count, &resume, NULL);
    if (GetLastError() != ERROR_MORE_DATA || !needed) {
        CloseServiceHandle(manager);
        return;
    }
    buffer = malloc(needed);
    if (!buffer) {
        CloseServiceHandle(manager);
        return;
    }
    resume = 0;
    if (EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer, needed, &needed, &count, &resume, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSW *services = (ENUM_SERVICE_STATUS_PROCESSW *)buffer;
        for (DWORD i = 0; i < count; ++i) {
            SC_HANDLE service = OpenServiceW(manager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            DWORD bytes = 0;
            if (!service) continue;
            QueryServiceConfigW(service, NULL, 0, &bytes);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                QUERY_SERVICE_CONFIGW *config = malloc(bytes);
                if (config && QueryServiceConfigW(service, config, bytes, &bytes) &&
                    config->dwStartType == SERVICE_AUTO_START) {
                    if (!*first) fputwc(L',', file);
                    fputws(L"\n    {\"location\":\"auto_start_service\",\"name\":", file);
                    wt_json_string(file, services[i].lpServiceName);
                    fputws(L",\"command\":", file);
                    wt_json_string(file, config->lpBinaryPathName);
                    fputwc(L'}', file);
                    *first = 0;
                }
                free(config);
            }
            CloseServiceHandle(service);
        }
    }
    free(buffer);
    CloseServiceHandle(manager);
}

int wt_write_persistence(WT_REPORT *report) {
    static const wchar_t run_path[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    static const wchar_t run_once_path[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    int first = 1;
    fputws(L"  \"persistence\":[", report->file);
    write_run_key(report->file, HKEY_CURRENT_USER, L"HKCU\\...\\Run", run_path, &first);
    write_run_key(report->file, HKEY_CURRENT_USER, L"HKCU\\...\\RunOnce", run_once_path, &first);
    write_run_key(report->file, HKEY_LOCAL_MACHINE, L"HKLM\\...\\Run", run_path, &first);
    write_run_key(report->file, HKEY_LOCAL_MACHINE, L"HKLM\\...\\RunOnce", run_once_path, &first);
    write_auto_services(report->file, &first);
    if (!first) fputwc(L'\n', report->file);
    fputws(L"  ]", report->file);
    return 1;
}
