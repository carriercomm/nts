!AUTH 1

OPNFAIL	E	"%s": failed to open file: %s
NTS failed to open the configured authentication database.  Ensure the
path is configured correctly and the NTS user has access to read the
file.
.

PARSERR	E	"%s", line %d: parse error: %s
NTS failed to parse the authentication database.  Examine the specified
line and ensure the syntax is correct.
.

UNKHASH	F	"%s", line %d: unknown hash algorithm "%s"
A hash algorithm was configured which is not supported by NTS.  Examine
the specified line and ensure the hash algorithm is correct.
.

