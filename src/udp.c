#include "../include/wintriage.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

static DWORD udp_table(ULONG family, void **table) {
    DWORD size = 0;
    DWORD result = GetExtendedUdpTable(NULL, &size, TRUE, family,
                                       UDP_TABLE_OWNER_PID, 0);
    *table = NULL;
    /* Endpoints can appear between the size query and the snapshot. */
    for (unsigned attempt = 0;
         result == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        void *buffer = malloc(size);
        if (!buffer) return ERROR_NOT_ENOUGH_MEMORY;
        result = GetExtendedUdpTable(buffer, &size, TRUE, family,
                                     UDP_TABLE_OWNER_PID, 0);
        if (result == NO_ERROR) {
            *table = buffer;
            return NO_ERROR;
        }
        free(buffer);
    }
    return result;
}

static void udp_row(FILE *file, const wchar_t *family, const wchar_t *address,
                    DWORD port, DWORD pid, DWORD scope, int *first) {
    if (!*first) fputwc(L',', file);
    *first = 0;
    fputws(L"\n    {\"address_family\":", file);
    wt_json_string(file, family);
    fwprintf(file, L",\"pid\":%lu,\"local_address\":", pid);
    wt_json_string(file, address);
    fwprintf(file, L",\"local_port\":%u,\"local_scope_id\":%lu}",
             (unsigned)ntohs((u_short)port), scope);
}

int wt_write_udp(WT_REPORT *report) {
    void *buffer = NULL;
    int first = 1;
    DWORD ipv4_result, ipv6_result;
    fputws(L"  \"udp_endpoints\":[", report->file);
    ipv4_result = udp_table(AF_INET, &buffer);
    if (ipv4_result == NO_ERROR && buffer) {
        PMIB_UDPTABLE_OWNER_PID table = buffer;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_UDPROW_OWNER_PID *row = &table->table[i];
            IN_ADDR address;
            wchar_t text[INET_ADDRSTRLEN] = L"";
            address.S_un.S_addr = row->dwLocalAddr;
            if (!InetNtopW(AF_INET, &address, text, ARRAYSIZE(text))) {
                ipv4_result = GetLastError();
                if (!ipv4_result) ipv4_result = ERROR_INVALID_DATA;
                continue;
            }
            udp_row(report->file, L"IPv4", text, row->dwLocalPort,
                    row->dwOwningPid, 0, &first);
        }
    }
    free(buffer);
    ipv6_result = udp_table(AF_INET6, &buffer);
    if (ipv6_result == NO_ERROR && buffer) {
        PMIB_UDP6TABLE_OWNER_PID table = buffer;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_UDP6ROW_OWNER_PID *row = &table->table[i];
            wchar_t text[INET6_ADDRSTRLEN] = L"";
            if (!InetNtopW(AF_INET6, row->ucLocalAddr, text, ARRAYSIZE(text))) {
                ipv6_result = GetLastError();
                if (!ipv6_result) ipv6_result = ERROR_INVALID_DATA;
                continue;
            }
            udp_row(report->file, L"IPv6", text, row->dwLocalPort,
                    row->dwOwningPid, ntohl(row->dwLocalScopeId), &first);
        }
    }
    free(buffer);
    fputws(L"\n  ],\n  \"udp_collection_errors\":{\"IPv4\":", report->file);
    if (ipv4_result == NO_ERROR) fputws(L"null", report->file);
    else wt_json_error(report->file, ipv4_result);
    fputws(L",\"IPv6\":", report->file);
    if (ipv6_result == NO_ERROR) fputws(L"null", report->file);
    else wt_json_error(report->file, ipv6_result);
    fputwc(L'}', report->file);
    return ipv4_result == NO_ERROR && ipv6_result == NO_ERROR;
}
