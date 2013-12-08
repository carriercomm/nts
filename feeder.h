/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_FEEDER_H
#define	NTS_FEEDER_H

#include	"server.h"
#include	"spool.h"
#include	"database.h"

struct hash_table;
struct article;

typedef enum {
	FM_IHAVE,
	FM_STREAM
} fconn_mode_t;

typedef enum {
	FS_DNS = 0,
	FS_CONNECT,
	FS_WAIT_GREETING,
	FS_SENT_CAPABILITIES,
	FS_READ_CAPABILITIES,
	FS_SENT_MODE_STREAM,
	FS_RUNNING
} fconn_state_t;

struct	server;
struct	feeder;

#define	FC_DEAD		0x1
#define	FC_FULL		0x2

typedef struct fconn {
	int			 fc_fd;
	struct feeder		*fc_feeder;
	char			*fc_strname;
	fconn_state_t		 fc_state;
	fconn_mode_t		 fc_mode;
	time_t			 fc_last_used;
	int			 fc_ncq;
	sendq_t			 fc_cq;
	address_t		*fc_cur_addr;
	address_list_t		*fc_addrs;
	int			 fc_flags;
	TAILQ_ENTRY(fconn)	 fc_list;
} fconn_t;

typedef TAILQ_HEAD(fconn_list, fconn) fconn_list_t;

#define FE_ADP		0x1
#define FE_POLLING	0x2
#define FE_NOTIFY	0x4

typedef struct feeder {
	struct server		*fe_server;
	fconn_list_t		 fe_conns;
	time_t			 fe_last_fail;
	time_t			 fe_last_defer_load;
	int			 fe_adp_count,
				 fe_adp_accepted;
	struct hash_table	*fe_pending;
	int			 fe_flags;
} feeder_t;

int	feeder_init(void);
int	feeder_run(void);
void	feeder_shutdown(void);
void	feeder_notify(struct feeder *);

#endif	/* !NTS_FEEDER_H */
