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

##Verified functionality:
- Timestamped connection, command, response, and file-transfer logging
  in remoteops_IT24102224.log, including PID and SID:4222.
- Authentication tokens are redacted in logs.
- flock() serialises concurrent log writes.
- Client EOF is logged and the Agent continues serving new connections.
