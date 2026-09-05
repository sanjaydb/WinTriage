#include "../include/wintriage.h"
#include <tlhelp32.h>

int wt_write_processes(WT_REPORT *report) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {0};
    int first = 1;
    fputws(L"  \"processes\":[", report->file);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fputws(L"{\"error\":", report->file);
        wt_json_error(report->file, GetLastError());
        fputws(L"}]", report->file);
        return 0;
    }
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            wchar_t path[32768] = L"";
            DWORD path_size = ARRAYSIZE(path);
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (process) {
                QueryFullProcessImageNameW(process, 0, path, &path_size);
                CloseHandle(process);
            }
            if (!first) fputwc(L',', report->file);
            fputws(L"\n    {\"pid\":", report->file);
            fwprintf(report->file, L"%lu,\"parent_pid\":%lu,\"name\":",
                     entry.th32ProcessID, entry.th32ParentProcessID);
            wt_json_string(report->file, entry.szExeFile);
            fputws(L",\"path\":", report->file);
            wt_json_string(report->file, path);
            fputwc(L'}', report->file);
            first = 0;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (!first) fputwc(L'\n', report->file);
    fputws(L"  ]", report->file);
    return 1;
}
