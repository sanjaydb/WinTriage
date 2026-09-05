#include "../include/wintriage.h"
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

static const wchar_t *tcp_state(DWORD state) {
    static const wchar_t *states[] = {
        L"UNKNOWN", L"CLOSED", L"LISTEN", L"SYN_SENT", L"SYN_RECEIVED",
        L"ESTABLISHED", L"FIN_WAIT_1", L"FIN_WAIT_2", L"CLOSE_WAIT",
        L"CLOSING", L"LAST_ACK", L"DELETE_TCB"
    };
    return state < ARRAYSIZE(states) ? states[state] : L"UNKNOWN";
}

int wt_write_network(WT_REPORT *report) {
    DWORD size = 0;
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD result = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0);
    fputws(L"  \"tcp_connections\":[", report->file);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        fputws(L"]", report->file);
        return 0;
    }
    table = malloc(size);
    if (!table) {
        fputws(L"]", report->file);
        return 0;
    }
    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
    if (result == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            IN_ADDR local = {0}, remote = {0};
            wchar_t local_ip[INET_ADDRSTRLEN] = L"", remote_ip[INET_ADDRSTRLEN] = L"";
            local.S_un.S_addr = row->dwLocalAddr;
            remote.S_un.S_addr = row->dwRemoteAddr;
            InetNtopW(AF_INET, &local, local_ip, ARRAYSIZE(local_ip));
            InetNtopW(AF_INET, &remote, remote_ip, ARRAYSIZE(remote_ip));
            if (i) fputwc(L',', report->file);
            fputws(L"\n    {\"pid\":", report->file);
            fwprintf(report->file, L"%lu,\"state\":", row->dwOwningPid);
            wt_json_string(report->file, tcp_state(row->dwState));
            fputws(L",\"local_address\":", report->file);
            wt_json_string(report->file, local_ip);
            fwprintf(report->file, L",\"local_port\":%u,\"remote_address\":",
                     ntohs((u_short)row->dwLocalPort));
            wt_json_string(report->file, remote_ip);
            fwprintf(report->file, L",\"remote_port\":%u}", ntohs((u_short)row->dwRemotePort));
        }
        if (table->dwNumEntries) fputwc(L'\n', report->file);
    }
    free(table);
    fputws(L"  ]", report->file);
    return result == NO_ERROR;
}
