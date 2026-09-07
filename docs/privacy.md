# Privacy guidance

A triage report can contain personal or operational information. Treat it as sensitive evidence.

UDP inventory also reveals local IPv6 addresses, interface scope IDs, ports, and process associations. Review these fields before sharing; no UDP packet contents or remote destinations are collected.

1. Store reports in an access-controlled case directory.
2. Review usernames, paths, IP addresses, command lines, and event XML before sharing.
3. Redact values that are unnecessary for the investigation.
4. Do not commit real reports to a public repository.
5. Follow applicable organizational retention and deletion requirements.

The `examples/sample-report.json` file contains invented demonstration values only.
