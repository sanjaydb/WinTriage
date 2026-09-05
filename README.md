# WinTriage

[![Windows build](https://github.com/sanjaydb/WinTriage/actions/workflows/windows-build.yml/badge.svg)](https://github.com/sanjaydb/WinTriage/actions/workflows/windows-build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

WinTriage is a read-only Windows incident-response and host-triage collector written in C using documented Win32 APIs. It creates a UTF-8 JSON report that helps analysts correlate processes, executable paths, TCP connections, persistence locations, recent important events, and optional file metadata.

The project is intended for SOC analysts, incident responders, malware analysts, system administrators, students, and defensive-security researchers.

## Current capabilities

- Hostname, user, architecture, processor count, page size, and uptime
- Running processes with PID, parent PID, name, and accessible executable path
- IPv4 TCP endpoints with state, addresses, ports, and owning PID
- Current-user and local-machine `Run` and `RunOnce` registry values
- Automatically started Windows services and their configured executable paths
- Recent warning and error events from System and Microsoft Defender logs
- Optional SHA-256, Authenticode result, size, and basic PE metadata for one file
- Explicit output path: WinTriage never silently uploads or transmits results

## Build

Open an **x64 Native Tools Command Prompt for Visual Studio 2022**, then run:

```bat
build.cmd
```

The executable is created as `build\wintriage.exe`.

## Use

```bat
build\wintriage.exe --output triage-report.json
build\wintriage.exe --output triage-report.json --file C:\Windows\System32\notepad.exe
```

Administrator access is optional. Running from an elevated terminal may reveal additional process paths, services, and event-log entries. The program continues when access to an individual data source is restricted.

## Interpret results carefully

WinTriage reports observations—it does not declare a process or file malicious. Legitimate administration and security tools can resemble suspicious activity. Correlate results with organizational context, approved software, additional telemetry, and qualified human review.

## Safety and privacy

- Collection is local and read-only.
- No process injection, credential collection, memory dumping, persistence creation, remote scanning, or security-control modification.
- Reports can contain usernames, paths, process details, IP addresses, and event data. Review and redact them before sharing.
- Use only on systems you own or are explicitly authorized to investigate.

See [collected data](docs/collected-data.md), [architecture](docs/architecture.md), [privacy guidance](docs/privacy.md), and the [roadmap](ROADMAP.md).

## Contributing

Corrections, tests, documentation, and defensive features are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) first.

## License

MIT License. See [LICENSE](LICENSE).

## Repository notice

This account contains personal research, educational projects, experiments, and historical code developed over several years.

Names, domains, identifiers, and sample data appearing in older repositories may be test or demonstration values and should not, by their presence alone, be interpreted as representing an employer, customer, organization, product, or endorsement.

I periodically review older repositories for maintainability, security, documentation, and appropriate handling of confidential or proprietary information.
