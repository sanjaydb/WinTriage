#ifndef WINTRIAGE_H
#define WINTRIAGE_H

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>

typedef struct {
    FILE *file;
    int pretty;
} WT_REPORT;

void wt_json_string(FILE *file, const wchar_t *value);
void wt_json_error(FILE *file, DWORD error);
int wt_write_system(WT_REPORT *report);
int wt_write_processes(WT_REPORT *report);
int wt_write_network(WT_REPORT *report);
int wt_write_persistence(WT_REPORT *report);
int wt_write_events(WT_REPORT *report);
int wt_write_file_analysis(WT_REPORT *report, const wchar_t *path);
int wt_write_report(const wchar_t *output, const wchar_t *analysis_path);

#endif
