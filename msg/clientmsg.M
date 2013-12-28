!CLIENT 2

ACPTERR	E	accepting client: %1$s: %2$s
An error occurred while attempting to accept a new client connection.
This is usually a transient error which will resolve itself.
.

DENIED	I	unknown[%1$s]:%2$s: connection rejected: access denied
A client attempted to connect, but was denied because its IP addess
did not match any configured servers, and a reader-handler is not
configured.

If this client should be accepted, add its IP address or network to the
appropriate server's accept-from configuration.

If unauthorised clients should be passed to a reader handling program,
such as nnrpd, then configure an appropriate reader-handler in
nts.conf.
.

TOOMANY	W	%1$s[%2$s]:%3$s: connection rejected: too many connections
A client connection was rejected because the server it is associated
with has already made too many connections.  Either increase the
max-connections value for this server, or configure the remote system
to attempt fewer connections.
.

TLSCTXFAIL	F	listener "%1$s": cannot create TLS context: %2$s
NTS was unable to create its internal context for this TLS listener.
This may indicate a lack of system resources.
.

TLSCERTFAIL	F	listener "%1$s": cannot load TLS certificate: %2$s
NTS was unable to load the configured TLS certificate for this TLS
listener.  Check that the correct path has been specified and that NTS
has permission to load the certificate file.
.

TLSKEYFAIL	F	listener "%1$s": cannot load TLS certificate: %2$s
NTS was unable to load the configured TLS key for this TLS listener.  Check 
that the correct path has been specified and that NTS has permission to load 
the certificate file.
.

TLSCYFAIL	F	listener %1$s: no valid cyphers
No valid TLS cyphers were found in the cypher list configured for the
specified listener.  Ensure that the installed version of OpenSSL
supports the requested cyphers.
.

NOTLS	F	listener %s: TLS support not available
A listener was configured to use TLS, but this version of NTS was not
built with TLS support.  Rebuild NTS from source, or if you obtained a
binary distribution, ask the builder to build with TLS support.
.

TLSBADOPT	F	"%1$s", line %2$d: unknown TLS option "%3$s",
An invalid TLS mode was specified for this listener connection.  The
TLS mode should be 'always', to enable TLS on this connection by
default, or 'starttls' to enable the STARTTLS command for clients that
wish to enable TLS.
.

INVADDR	F	listen: "%1$s": invalid address
An invalid listen address was specified in a listener.  The listen
address should be in one of the following forms:

 A port:                       listen "119";
 A hostname and port:          listen "news.example.com:119";
 An IPv4 address and port:     listen "127.0.0.1:119";
 An IPv6 address and port:     listen "[::1]:119";
.

INVHOST	F	listen: %1$s: invalid host: %2$s
NTS was unable to resolve the listen address specified for this
listener.  Either the hostname is incorrect or, if the address was
specified in IP address format, the IP address is invalid.
.

LSNFAIL	F	listen: "%1$s": %2$s: %3$s
NTS was unable to listen on the specified address / hostname. Consult
the error message for more detailed information.
.

LSNCFGERRS	F	listen: %d configuration errors
The listener subsystem was unable to start because of previous
configuration errors.  Consult previous message for the error(s) and
fix them.
.

CONNECT	I	client connected
A new client has connected to the server.
.

CONNTLS	I	client connected (%s %s)
A new client has connected to the server using the indicated TLS
cipher.
.

STARTTLS	I	TLS started: %s %s
A client negotiated TLS on an existing unencrypted connection.
.

DISCEOF	I	disconnected (EOF)
A client closed the TCP connection to the server without sending a QUIT
command.  This is normal behaviour for some feeders.
.

DISCERR	I	disconnected (read error: %2$s)
NTS encountered an error when trying to read data from a client.  This
might indicate either a network problem, or a problem with the remote
client.
.

DISCQUIT	I	disconnected (QUIT)
A client disconnected normally, by sending a QUIT command.
.

TLSERR	I	TLS error: %s
An TLS error occurred when trying to read from or write to the client.
.

