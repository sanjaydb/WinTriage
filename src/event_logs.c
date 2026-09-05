#include "../include/wintriage.h"
#include <winevt.h>
#include <stdlib.h>
#pragma comment(lib, "Wevtapi.lib")

static int write_channel(FILE *file, const wchar_t *channel, const wchar_t *query, int *first) {
    EVT_HANDLE results = EvtQuery(NULL, channel, query,
        EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!results) return 0;
    for (DWORD total = 0; total < 25;) {
        EVT_HANDLE events[8] = {0};
        DWORD returned = 0;
        if (!EvtNext(results, ARRAYSIZE(events), events, 0, 0, &returned)) break;
        for (DWORD i = 0; i < returned && total < 25; ++i, ++total) {
            DWORD needed = 0, properties = 0;
            EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &needed, &properties);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                wchar_t *xml = malloc(needed);
                if (xml && EvtRender(NULL, events[i], EvtRenderEventXml,
                                     needed, xml, &needed, &properties)) {
                    if (!*first) fputwc(L',', file);
                    fputws(L"\n    {\"channel\":", file);
                    wt_json_string(file, channel);
                    fputws(L",\"event_xml\":", file);
                    wt_json_string(file, xml);
                    fputwc(L'}', file);
                    *first = 0;
                }
                free(xml);
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(results);
    return 1;
}

int wt_write_events(WT_REPORT *report) {
    int first = 1;
    fputws(L"  \"recent_security_events\":[", report->file);
    write_channel(report->file, L"System",
        L"*[System[(Level=1 or Level=2 or Level=3)]]", &first);
    write_channel(report->file, L"Microsoft-Windows-Windows Defender/Operational",
        L"*[System[(Level=1 or Level=2 or Level=3)]]", &first);
    if (!first) fputwc(L'\n', report->file);
    fputws(L"  ]", report->file);
    return 1;
}
