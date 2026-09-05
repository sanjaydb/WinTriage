#include "../include/wintriage.h"
#include <lmcons.h>

int wt_write_system(WT_REPORT *report) {
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = L"";
    wchar_t user[UNLEN + 1] = L"";
    DWORD computer_size = ARRAYSIZE(computer);
    DWORD user_size = ARRAYSIZE(user);
    SYSTEM_INFO system;
    ULONGLONG uptime = GetTickCount64();
    GetComputerNameW(computer, &computer_size);
    GetUserNameW(user, &user_size);
    GetNativeSystemInfo(&system);

    fputws(L"  \"system\":{\n    \"computer\":", report->file);
    wt_json_string(report->file, computer);
    fputws(L",\n    \"user\":", report->file);
    wt_json_string(report->file, user);
    fwprintf(report->file,
        L",\n    \"processor_architecture\":%u,"
        L"\n    \"logical_processors\":%lu,"
        L"\n    \"page_size\":%lu,"
        L"\n    \"uptime_seconds\":%llu\n  }",
        system.wProcessorArchitecture, system.dwNumberOfProcessors,
        system.dwPageSize, uptime / 1000);
    return 1;
}
