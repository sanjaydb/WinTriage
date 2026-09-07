# Collected data

Reports may contain:

- Computer and user names
- Process identifiers, parent relationships, names, and executable paths
- Local and remote IPv4 addresses and TCP ports
- Local IPv4/IPv6 UDP addresses, ports, owning PIDs, and IPv6 scope IDs
- Commands configured in common autorun registry locations
- Automatically started service names and executable paths
- Raw XML for up to 25 recent warning/error events per queried channel
- A user-selected file path, SHA-256 digest, size, signature status, and PE header summary

WinTriage does not collect passwords, browser data, process memory, file contents, private keys, or packet contents. It does not send reports over a network.

## UDP inventory

The additive `udp_endpoints` and `udp_collection_errors` fields retain schema version `1.0`; existing TCP fields are unchanged. Readers should tolerate additional object fields.

Each UDP endpoint contains `address_family` (`IPv4` or `IPv6`), `pid`, `local_address`, `local_port` (host byte order), and `local_scope_id` (host byte order; zero for IPv4). The scope identifies an IPv6 interface when applicable. A PID of zero means the owner is unavailable. Wildcard addresses `0.0.0.0` and `::` represent binding to any local interface.

`udp_collection_errors` has `IPv4` and `IPv6` members, each either `null` on success or an object with a Windows error `code` and `message`. Collection continues for the other family on failure. A non-null error can accompany partial results. Buffer growth is retried at most four times to handle endpoint churn.

UDP tables do not expose remote peers or TCP-style connection states. A bound endpoint may only be used for sending; it is not proof of an active listener or malicious activity. Process and network snapshots are collected separately, so short-lived processes and PID reuse can affect correlation.
