# Architecture

WinTriage is deliberately small and dependency-free. `main.c` validates command-line arguments and requires an explicit report path. `report.c` owns JSON serialization and calls independent collectors.

| Module | Primary APIs | Output |
| --- | --- | --- |
| `system_info.c` | `GetComputerNameW`, `GetUserNameW`, `GetNativeSystemInfo` | Host context |
| `processes.c` | Tool Help and limited process-query APIs | Process inventory |
| `network.c` | IP Helper API | PID-associated TCP endpoints |
| `persistence.c` | Registry and Service Control Manager | Common autoruns and automatic services |
| `event_logs.c` | Windows Event Log API | Recent warning/error event XML |
| `file_analysis.c` | CNG, WinTrust, PE structures | Hash, signature result, and PE summary |

Collectors do not modify the system. A failure in one collector is represented by empty or partial output rather than causing changes or retries with alternate credentials.
