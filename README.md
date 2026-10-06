### Controller usage

Build:
make -f Makefile_224

Run the Agent in one terminal:
./agent

Run the Controller in another:
./controller 127.0.0.1

Optional custom UDP receiver port:
./controller 127.0.0.1 9501

Authenticate using AUTH OPS-2224.
Supported commands: SYSINFO, LISTPROC, EXEC DATE/UPTIME/DISKFREE/
HOSTNAME/WHOAMI, PUT <filename>, GET <filename>,
MONITOR START <receiver-port>, MONITOR STOP, and QUIT.

PUT calculates the file size automatically. Files must be in the
Controller's current directory. Downloads are saved under ./downloads/.
The default UDP receiver port is 9500. Each simultaneous Controller
on the same machine needs a different UDP port.

Verified Controller TCP commands, file transfer with byte comparison,
UDP reception, TCP operation during monitoring, STOP, and QUIT.
