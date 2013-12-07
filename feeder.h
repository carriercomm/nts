/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/feeder.h,v 1.19 2012/01/10 17:14:13 river Exp $ */

#ifndef	NTS_FEEDER_H
#define	NTS_FEEDER_H

#include	"article.h"
#include	"server.h"
#include	"spool.h"
#include	"database.h"
#include	"hash.h"

typedef struct article_entry {
	struct article			*ae_article;
	SIMPLEQ_ENTRY(article_entry)	 ae_list;
} article_entry_t;

typedef SIMPLEQ_HEAD(article_list, article_entry) article_list_t;

typedef enum {
	FM_IHAVE,
	FM_STREAM
} feeder_mode_t;

typedef enum {
	FS_DNS = 0,
	FS_CONNECT,
	FS_WAIT_GREETING,
	FS_SENT_CAPABILITIES,
	FS_READ_CAPABILITIES,
	FS_SENT_MODE_STREAM,
	FS_RUNNING
} feeder_state_t;

typedef enum {
	FT_REALTIME,
	FT_BACKLOG
} feeder_type_t;

#define	FE_DEAD	0x1
#define	FE_ADP	0x2

struct server;
typedef struct feeder {
	struct server		*fe_server;
	article_list_t		 fe_send_queue;
	int			 fe_waiting_size,
				 fe_send_queue_size;
	hash_table_t		*fe_waiting_hash;
	int			 fe_fd;
	feeder_mode_t		 fe_mode;
	feeder_state_t		 fe_state;
	feeder_type_t		 fe_type;
	address_t		*fe_cur_addr;
	char			*fe_strname;
	int			 fe_adp_count,
				 fe_adp_accepted;
	address_list_t		*fe_addrs;
	time_t			 fe_last_used;
	uint8_t			 fe_flags;
	int			 fe_offer,
				 fe_accept,
				 fe_refuse,
				 fe_defer,
				 fe_reject;
	spool_pos_t		 fe_spool_pos;
} feeder_t;

int	feeder_init(void);
int	feeder_run(void);

void	feeder_notify_article(article_t *);

#endif	/* !NTS_FEEDER_H */
