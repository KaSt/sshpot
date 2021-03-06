#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>
#include <libssh/libssh.h>
#include "stats.h"

#define MAXBUF 100

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF];
    char con_time[MAXBUF];
    const char *user;
    const char *pass;
};

void handle_auth(ssh_session session, const char *logfile, bool syslog, int delay,
	const char *jsonlog, const char *sensor, stats_t *stats );
void drop_priv(const char *user, const char *group); 
void sshpot_chroot (const char *chrootdir);
void init_session_uuid();

#endif
