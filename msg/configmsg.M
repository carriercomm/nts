!CONFIG 3

OPNFAIL	F	cannot open configuration file "%1$s": %2$s
NTS failed to open its configuration file.  Check that the file exists
and the NTS user has permission to access it.
.

UNKBLK	F	"%s", line %d: unrecognised block "%s"
NTS encountered an unknown configuration block in the configuration
file.  Examine the specified line and correct the problem.
.

UNKOPT	F	"%s", line %d: unrecognised option "%s::%s"
NTS encountered an unknown configuration option in the configuration
file.  Examine the specified line and correct the problem.
.

PARSERR	F	"%s", line %d: %s
NTS encountered a problem parsing the configuration file. Examine the
specified line and correct the problem.
.


