#include "../include/wintriage.h"
#include <wchar.h>

static void usage(const wchar_t *program) {
    fwprintf(stderr,
        L"WinTriage - read-only Windows host triage\n\n"
        L"Usage: %ls --output REPORT.json [--file FILE]\n"
        L"       %ls --help\n\n"
        L"Options:\n"
        L"  --output PATH  Required JSON report destination.\n"
        L"  --file PATH    Optionally analyze one local PE or data file.\n",
        program, program);
}

int wmain(int argc, wchar_t **argv) {
    const wchar_t *output = NULL;
    const wchar_t *analysis_path = NULL;

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (wcscmp(argv[i], L"--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (wcscmp(argv[i], L"--file") == 0 && i + 1 < argc) {
            analysis_path = argv[++i];
        } else {
            fwprintf(stderr, L"Unknown or incomplete option: %ls\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!output) {
        usage(argv[0]);
        return 2;
    }

    if (!wt_write_report(output, analysis_path)) {
        fwprintf(stderr, L"Failed to create report: %ls\n", output);
        return 1;
    }

    wprintf(L"Read-only triage report written to %ls\n", output);
    return 0;
}
