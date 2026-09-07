#include "../include/wintriage.h"
#include <fcntl.h>
#include <io.h>

void wt_json_string(FILE *file, const wchar_t *value) {
    fputwc(L'"', file);
    if (value) {
        for (const wchar_t *p = value; *p; ++p) {
            switch (*p) {
                case L'"': fputws(L"\\\"", file); break;
                case L'\\': fputws(L"\\\\", file); break;
                case L'\b': fputws(L"\\b", file); break;
                case L'\f': fputws(L"\\f", file); break;
                case L'\n': fputws(L"\\n", file); break;
                case L'\r': fputws(L"\\r", file); break;
                case L'\t': fputws(L"\\t", file); break;
                default:
                    if (*p < 0x20) fwprintf(file, L"\\u%04x", (unsigned)*p);
                    else fputwc(*p, file);
            }
        }
    }
    fputwc(L'"', file);
}

void wt_json_error(FILE *file, DWORD error) {
    wchar_t message[512] = L"";
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, 0, message, ARRAYSIZE(message), NULL);
    size_t length = wcslen(message);
    while (length && (message[length - 1] == L'\r' || message[length - 1] == L'\n')) {
        message[--length] = L'\0';
    }
    fwprintf(file, L"{\"code\":%lu,\"message\":", error);
    wt_json_string(file, message);
    fputwc(L'}', file);
}

int wt_write_report(const wchar_t *output, const wchar_t *analysis_path) {
    FILE *file = NULL;
    WT_REPORT report;
    if (_wfopen_s(&file, output, L"w, ccs=UTF-8") != 0 || !file) return 0;
    report.file = file;
    report.pretty = 1;

    fputws(L"{\n  \"schema_version\":\"1.0\",\n", file);
    fputws(L"  \"tool\":\"WinTriage\",\n", file);
    wt_write_system(&report);
    fputws(L",\n", file);
    wt_write_processes(&report);
    fputws(L",\n", file);
    wt_write_network(&report);
    fputws(L",\n", file);
    wt_write_udp(&report);
    fputws(L",\n", file);
    wt_write_persistence(&report);
    fputws(L",\n", file);
    wt_write_events(&report);
    if (analysis_path) {
        fputws(L",\n", file);
        wt_write_file_analysis(&report, analysis_path);
    }
    fputws(L"\n}\n", file);

    if (ferror(file)) {
        fclose(file);
        return 0;
    }
    return fclose(file) == 0;
}
