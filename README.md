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

The initial TCP Agent has been implemented and tested:
- Compilation completed without displayed warnings or errors.
- Listening on personalised TCP port 9410 was verified using ss.
- Two sequential local connections were accepted and closed.

At this stage, the Agent closes each accepted connection immediately.
Authentication, command handling, concurrency, file transfers,
UDP monitoring, logging, and the Controller remain to be implemented.


## Build and Run

Run these commands from the project root.

Build the Agent:

```bash
make -f Makefile_224
```

Start the Agent:

```bash
./agent
```

Check the listening port from another terminal:

```bash
ss -tlnp 'sport = :9410'
```

Stop this initial Agent using Ctrl+C.

Remove the generated executable:

```bash
make -f Makefile_224 clean
```
