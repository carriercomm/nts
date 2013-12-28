!DB 4

NOLOC	F	database path not configure
The database path was not specified in the configuration file.  Edit
nts.conf and ensure the database is correctly configured:

database {
        path:           "/var/db/nts";
};
.

MKDIR	F	cannot create directory "%1$s": %2$s
NTS could not create a directory to hold its database.  Ensure that
the correct permissions are set on the database path to allow the NTS
user to write to it.
.

ENVFAIL	F	cannot create database environment: %1$s
NTS could not initialise the Berkeley DB environment.  Check for
previous error logged by the Berkeley DB subsystem and correct the
problem.
.

MXTXNFAIL	F	cannot set maximum transaction count: %1$d
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

LOGCFGFAIL	F	cannot configure log auto-removal: %1$s
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

DLKFAIL	F	cannot configure deadlock detection: %1$s
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

CACHEFAIL	F	cannot configure cache size: %1$s
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)

In addition, check that the system has sufficient physical and virtual
memory to support the requested database cache size.
.

ENVOPNFAIL	F	cannot open database environment: %1$s
NTS failed to open the Berkeley DB database environment.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

CLSFAIL	F	cannot close database environment: %1$s
NTS failed to close the Berkeley DB database environment.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

DBHDLFAIL	F	cannot create database handle: %1$s
NTS failed to create a new Berkeley DB database handle. Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

DBFLGFAIL	F	cannot set database flags: %1$s
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

DBSRTFAIL	F	cannot set database flags: %1$s
NTS failed to configure an internal Berkeley DB option.  Check for
previous errors logged by the Berkeley DB subsystem and correct the
problem.  (This message may also be caused by a programming error.)
.

DBOPNFAIL	F	cannot open database "%1$s": %2$s
NTS failed to open a Berkeley DB database. Check for previous errors 
logged by the Berkeley DB subsystem and correct the problem.
.

NTXNFAIL	F	cannot create database transaction: %1$s
NTS failed to create a new Berkeley DB transaction. Check for previous 
errors logged by the Berkeley DB subsystem and correct the problem.
.

CTXNFAIL	F	cannot commit database transaction: %1$s
NTS failed to commit a Berkeley DB transaction. Check for previous 
errors logged by the Berkeley DB subsystem and correct the problem.
.

ATXNFAIL	F	cannot abort database transaction: %1$s
NTS failed to abort a Berkeley DB transaction. Check for previous 
errors logged by the Berkeley DB subsystem and correct the problem.
.

BKEND	W	message from database: %1$s
The backend database logged a message.  This may represent a problem
with the database; consult the specific message for more information.
.

BKENDP	W	message from database: %1$s: %2$s
The backend database logged a message.  This may represent a problem
with the database; consult the specific message for more information.
.
