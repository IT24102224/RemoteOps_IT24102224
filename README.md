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
- MONITOR START sends SID-tagged UDP system statistics every
  two seconds to the client's IP and requested UDP port.
- MONITOR STOP stops the stream while TCP commands remain usable.
- QUIT stops active monitoring and closes the TCP connection.
- Monitoring was tested using a Bash TCP client and Netcat UDP receiver.
