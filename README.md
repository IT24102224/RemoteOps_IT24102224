# RemoteOps — IE3090 Network Programming

Registration number: IT24102224

## Overview

RemoteOps is an Agent/Controller application being developed in C
using the standard BSD sockets API. TCP will carry control commands
and file transfers. UDP will carry periodic monitoring statistics.

## Personalisation

| Item | Value |
|---|---|
| Agent listening port | 9410 |
| Agent source | agent_224.c |
| Controller source | controller_224.c |
| Makefile | Makefile_224 |
| Session ID tag | SID:4222 |
| Authentication token | OPS-2224 |
| Log file | remoteops_IT24102224.log |
| File-storage directory | ./agentfiles/IT24102224/ |
| Submission archive | IE3090_IT24102224.zip |

## Development Environment

- Ubuntu 24.04.3 LTS running in VirtualBox
- GCC 13.3.0
- GNU Make 4.3
- Git 2.43.0

## Current Status
The initial TCP Agent and Controller have been implemented.

Verified functionality:
- The Agent listens on personalised TCP port 9410.
- The C Controller connects to the Agent over local TCP.
- Buffered line framing handles split command input and multiple
  newline-delimited commands sent together.
- Commands submitted before authentication are rejected.
- Incorrect authentication tokens are rejected.
- AUTH OPS-2224 returns OK AUTHENTICATED SID:4222.
- Authenticated QUIT returns OK BYE SID:4222 and closes the connection.

Authentication and QUIT were tested using a Bash TCP client.
The C Controller currently tests connectivity only.

The Agent currently handles one connection at a time.
Concurrent connections, SYSINFO, LISTPROC, EXEC, file transfers,
UDP monitoring, and timestamped file logging remain to be implemented.
Further error-handling and integration tests are also pending.
## Build and Run

Run these commands from the project root.

Build both programs:

```bash
make -f Makefile_224
```

Start the Agent:

```bash
./agent
```

In another terminal, connect using the Controller:

```bash
./controller 127.0.0.1
```

The Controller accepts the Agent's IPv4 address as its argument
and uses the fixed personalised port 9410.

Check the listening port:

```bash
ss -tlnp 'sport = :9410'
```

Stop the initial Agent using Ctrl+C.

Remove both generated executables:

```bash
make -f Makefile_224 clean
```
##Verified functionality:
-- Authenticated PUT and GET transfer binary files up to 10 MiB.
- Files are stored under ./agentfiles/IT24102224/.
- A 16,384-byte file passed comparison of the original, stored,
  and downloaded copies using cmp and SHA-256.
- GET for a missing file returns ERR 005 FILE_NOT_FOUND SID:4222.
