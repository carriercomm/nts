/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	"client.h"
#include	"server.h"
#include	"auth.h"
#include	"log.h"

void
c_authinfo(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char	*type;

	if (client->cl_authenticated) {
		client_printf(client, "502 Already authenticated.\r\n");
		return;
	}
	
	if (!auth_enabled || (client->cl_server &&
			      !client->cl_server->se_username_in)) {
		client_printf(client, "502 Authentication unavailable.\r\n");
		return;
	}

	if (!insecure_auth && !(client->cl_flags & CL_SSL)) {
		client_printf(client, "483 TLS required.\r\n");
		return;
	}

	if ((type = next_word(&line)) == NULL) {
		client_printf(client, "501 Syntax error.\r\n");
		return;
	}

	if (strcasecmp(type, "USER") == 0) {
	char	*un;
		if ((un = next_word(&line)) == NULL) {
			client_printf(client, "501 Syntax error.\r\n");
			return;
		}

		free(client->cl_username);
		client->cl_username = xstrdup(un);
		client_printf(client, "381 Enter password.\r\n");
	} else if (strcasecmp(type, "PASS") == 0) {
	char	*password;

		if (!client->cl_username) {
			client_printf(client, "482 Need a username first.\r\n");
			return;
		}

		if ((password = next_word(&line)) == NULL) {
			client_printf(client, "501 Syntax error.\r\n");
			free(client->cl_username);
			client->cl_username = NULL;
			return;
		}

		if (auth_check(client->cl_username, password)) {
			if (!client->cl_server) {
			char		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
			char		 host[NI_MAXHOST], serv[NI_MAXSERV];
			server_t	*se;

				SLIST_FOREACH(se, &servers, se_list) {
					if (se->se_username_in &&
					    strcmp(client->cl_username,
						   se->se_username_in) == 0) {
						client->cl_server = se;
						break;
					}
				}

				if (!client->cl_server) {
					client_log(LOG_INFO, client,
						"authentication as \"%s\" failed",
						client->cl_username);
					client_printf(client, "481 Authentication failed.\r\n");
					free(client->cl_username);
					client->cl_username = NULL;
					return;
				}

				getnameinfo((struct sockaddr *) &client->cl_addr,
					client->cl_addrlen,
					host, sizeof(host), serv, sizeof(serv),
					NI_NUMERICHOST | NI_NUMERICSERV);

				if (se->se_nconns == se->se_maxconns_in) {
					nts_log(LOG_NOTICE, "%s[%s]:%s: "
						"connection rejected: "
						"too many connections",
						se->se_name, host, serv);
					client_printf(client, 
						"481 Too many connections "
						"(%s).\r\n", contact_address);
					free(client->cl_username);
					client->cl_username = NULL;
					return;
				}
				SIMPLEQ_INSERT_TAIL(&se->se_clients, client, cl_list);
				++se->se_nconns;

				snprintf(strname, sizeof(strname), "%s[%s]:%s",
						se->se_name, host, serv);
				client->cl_strname = xstrdup(strname);
			}

			client_log(LOG_INFO, client, "authenticated as \"%s\"",
					client->cl_username);
			client_printf(client, "281 Authentication accepted.\r\n");
			client->cl_authenticated = 1;
		} else {
			client_log(LOG_INFO, client, "authentication as \"%s\" failed",
					client->cl_username);
			client_printf(client, "481 Authentication failed.\r\n");
		}
	} else {
		client_printf(client, "501 Syntax error.\r\n");
	}
}
