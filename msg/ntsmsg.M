!NTS

STARTUP	I	NTS %1$s starting up
The NTS system has been started, but is not yet running.
.

RUNNING	I	NTS %1$s [%2$s] running
NTS has finished starting up and is now ready for processing.
.

SHUTDWN	I	NTS shutdown beginning: %1$s
NTS is beginning the shutdown process and will terminate when complete.
.

RMPID	W	unable to remove PID file %1$s: %2$s
NTS was unable to remove the file containing its current process id
(PID).  This file should be removed manually, or NTS may fail to start
up correctly.
.

ALDYRUNNING	F	NTS already running, pid %1$d
NTS detected that its process id file already exists, and contains a
process id for a running process.  This most likely means that another
copy of NTS has already been started; however, it could also mean that
the pid file was not correct removed on the last shutdown, and another
process is using the same process id by chance.

Remedy: check if the process id specified in the error message is
actually a copy of NTS.  If not, remove the pid file by hand and
restart NTS.  Ensure the pid file is removed correctly on shutdown to
prevent recurrance of this problem.
.
