!SPOOL 8

BADMETHOD	F	"%s", line %d: invalid spool method "%s"
An invalid spool access was specific in the configuration file. The
spool access method should be either "file" to use file-based access,
or "mmap" to map the spool file into memory, in which case spool size
is limited by the system's available virtual memory.
.

BADCOMPR	F	"%s", line %d: compression level must be between 1 and 9
An invalid spool compression level was specified in the configuration.
The spool compression level must be between 1 (least compression) and
9 (most compression).  To disable compression entirely, specify
"compress: no".
.

CFGERRS	F	%d configuration errors
Errors were detected in the spool configuration which prevent NTS from
starting.  Refer to the above messages to identify the errors, then
restart NTS.
.

NOPATH	F	spool path not specified
The location of the spool path was not specified.  This should be
configured in nts.conf:

spool {
	path: "/var/spool/nts";
};

It should point to an otherwise empty directory, or a non-existent
directory, in which case NTS will attempt to create it.
.

MKDFAIL	F	%s: cannot create directory: %s
NTS failed to create its spool directory.  Ensure the permissions on
the parent directory are correct, and allow NTS to create its spool
directory.
.

DOPNFAIL	F	%s: cannot open: %s
NTS failed to open its spool directory.  Ensure the permissions on the
directory are correct, and allow NTS to both read and write the
directory.
.

JUNK	W	%s: junk file in spool directory: %s
NTS found an unexpected file inside its spool directory.  This is not a
fatal error, but the spool directory should be considered private to
NTS, and other files not created there.
.

BADMAGIC	E	"%s": article at %X,%lu: bad magic
While attempting to load an article from the specified spool, NTS found 
an incorrect header at the location an article was expected to be. This 
may indicate on-disk corruption, but it can also be caused by an 
incorrect written article if "sync: no" is specified in the spool 
configuration, in which case this message can be ignored.
.

TOOLONG	E	"%s": article at %.8lX/%lu goes past end of spool file
While attempting to load an article from the specified spool, NTS found 
invalid data in the article header. This may indicate on-disk 
corruption, but it can also be caused by an incorrect written article if 
"sync: no" is specified in the spool configuration, in which case this 
message can be ignored.
.

BADCRC	E	%s: bad CRC
While attempting to load an article from the specified spool, NTS found 
data in the article body which did not match the checksum previously 
stored in the header.  This should not occur during normal operation,
and indicates either on-disk corruption or a programming error.
.

UNCMPFAIL	E	%s: uncompress failed: %s
While attempting to load a compressed article from the specified spool, 
NTS was unable to decompress the article text.  This should not occur 
during normal operation, and indicates either on-disk corruption or a 
programming error.
.

VFYBADSZ	I	"%s": invalid stored size, verifying entire file
While verifying a spool file after an unclean shutdown, NTS found the 
length of the spool file stored in the spool header was longer than the 
file's actually length on disk.  This should not be the case even after 
an unclean shutdown, and may indicate on-disk corruption or a 
programming error.
.

VFYRDFAIL	F	"%1$s": read error: %2$s
While verifying a spool file after an unclean shutdown, NTS was unable
to read data from the spool file due to an operating system error.
Correct the problem and restart NTS or, if the spool is unrecoverable,
delete its contents.
.

VFYWRFAIL	F	"%1$s": write error: %2$s
While verifying a spool file after an unclean shutdown, NTS was unable
to write data to the spool file due to an operating system error.
Correct the problem and restart NTS or, if the spool is unrecoverable,
delete its contents.
.

VFYBEGIN	I	"%1$s": unclean shutdown, verifying from %lu...
NTS detected that it failed to shut down correct during the previous
run, and is verifying the spool file to fix any data inconsistencies.
.

EOS	I	%1$s: found EOS at %2$s
NTS found an end-of-spool marker at the specified position in the spool
file, indicating that the spool's article data is consistent.
.

VFYIVART	I	 %1$s: invalid article found at %2$lu
NTS detected an invalid or incomplete article at the specified
position in the spool file.  The article will be discarded.
.

NOEOS	I	%1$s: no EOS at end of file
NTS did not detect an end-of-spool marker at the end of the spool file.
The EOS marker will be added.
.

VFYOKAY	I	verify complete
NTS finished verifying the spool file and detected no unrecoverable
errors.
.
