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

## Current Status

The initial TCP Agent and Controller have been implemented.

Verified results:
- The Agent compiled without displayed warnings or errors.
- Listening on personalised port 9410 was confirmed using ss.
- The Agent accepted two sequential local test connections.
- The C Controller connected successfully to 127.0.0.1:9410.
- The buffered reader reconstructed a command sent in two writes
  and parsed additional newline-terminated commands separately.
- Orderly peer disconnection was detected.

The Agent currently prints complete command lines locally.
It does not authenticate clients, execute commands, or send TCP
protocol responses. The initial Controller connects and closes.

Authentication, concurrency, command handlers, file transfers,
UDP monitoring, logging, and complete send handling remain pending.
The Controller also requires command and response handling.

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
