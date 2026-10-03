Design Diary

 3 October 2026 — Environment Preparation and Personalisation

Selected Ubuntu 24.04.3 LTS running in VirtualBox as the development environment. Terminal checks confirmed GCC 13.3.0 and the ss utility. GNU Make and Git were initially unavailable; following installation, GNU Make 4.3 and Git 2.43.0 were verified.

Calculated the required personalisation values from registration number IT24102224 and recorded them in the Implementation Report. The development environment was also documented. Implementation of the Agent and Controller has not yet started.

 Project Directory Setup

Created /home/ashka/RemoteOps_IT24102224 as the project root and agentfiles/IT24102224 as the personalised file-storage directory required by Section 2.4. Created docs/screenshots and tests to organise documentation, evidence, and test files. Verified the directory structure using pwd and find. No source code has been created yet.
Implemented the initial TCP Agent in agent_224.c and created Makefile_224. Compilation completed without displayed warnings or errors. Verified that the Agent was listening on personalised port 9410 using ss. Two sequential local TCP connections were accepted and closed successfully.

Used this minimal stage to verify socket setup and the accept loop before adding session handling. Captured code and execution screenshots for the Implementation Report. Authentication, command processing, concurrency, file transfers, and UDP monitoring remain pending.
Initial TCP Controller

Implemented controller_224.c to accept an IPv4 address and connect to the Agent on personalised port 9410. Updated Makefile_224 to build both programs. Verified local connectivity using ./controller 127.0.0.1; the Controller reported a successful connection, and the Agent displayed the corresponding accepted connection.

Kept this stage limited to connection establishment and closure so that basic connectivity could be verified before adding protocol commands. Added execution and annotated code evidence to the Implementation Report.
TCP Line Framing

Added a buffered line reader that retains unread bytes between calls. Chose a 4096-byte receive buffer and a maximum command-text length of 1023 bytes. Verified reconstruction of an AUTH line sent in two writes and separate parsing of SYSINFO and LISTPROC sent alongside its final fragment. Confirmed orderly peer-disconnection detection and captured report evidence. Command execution and authentication remain pending.
