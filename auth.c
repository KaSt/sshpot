#include "auth.h"
#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>

#include <unistd.h>

#include <json-c/json.h>
#include "uuid4.h"

/* Stores the current UTC time. Returns 0 on error. */
static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%FT%TZ", gmtime(&t));
}


/* Stores the client's IP address in the connection sruct. */
static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);

    return 0;
}

/* Write interesting information about a connection attempt to  LOGFILE. 
 * Returns -1 on error. */
 
static int log_attempt(struct connection *c, const char *logfile, const char *jsonlog, 
	bool syslog_bool, const char *sensor) {
    FILE *f;
    int r;

    if ((f = fopen(logfile, "a+")) == NULL) {
        fprintf(stderr, "Unable to open %s\n", LOGFILE);
        return -1;
    }

    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        return -1;
    }

    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }

    c->user = ssh_message_auth_user(c->message);
    c->pass = ssh_message_auth_password(c->message);

    if ( syslog_bool ) {
	openlog("sshpot",SYSLOG_PRIORITY, SYSLOG_FACILITY);
	syslog(LOG_PID, "Login attempt from %s,  username %s, password %s", c->client_ip, c->user, c->pass); 	
	closelog(); 
	}

    if (DEBUG) { printf("%s %s %s %s\n", c->con_time, c->client_ip, c->user, c->pass); }
    r = fprintf(f, "%s %s %s %s\n", c->con_time, c->client_ip, c->user, c->pass);
    fclose(f);
    
    /* Write Cowrie compatible JSON log file*/
    json_object * jobj = json_object_new_object();
    /* Event Id */
    json_object *eventid = json_object_new_string("cowrie.login.failed");
    json_object_object_add(jobj,"eventid", eventid);
    /* User ID */
    json_object *userid = json_object_new_string(c->user);
    json_object_object_add(jobj,"username", userid);
    /* Timestamp */
    json_object *timestap = json_object_new_string(c->con_time);
    json_object_object_add(jobj,"timestamp", timestap);
    /* Message */
    size_t needed = snprintf(NULL, 0, "login attempt [%s/%s]", c->user, c->pass)+1;
    char* message = malloc(needed);
    snprintf(message, needed, "login attempt [%s/%s]", c->user, c->pass);
    json_object *jmessage = json_object_new_string(message);
    json_object_object_add(jobj,"message", jmessage);
    /* System */
    json_object *jsystem = json_object_new_string("SSHService 'ssh-userauth'");
    json_object_object_add(jobj,"system", jsystem);
    /* Error */
    json_object *jint = json_object_new_int((int32_t)0);
    json_object_object_add(jobj,"isError", jint);
    /* Source IP */
    json_object *jip = json_object_new_string(c->client_ip);
    json_object_object_add(jobj,"src_ip", jip);
    /* Session - Fresh UUID */
    char uuid[UUID4_LEN];
	uuid4_generate(uuid);
    json_object *jsession = json_object_new_string(uuid);
    json_object_object_add(jobj,"session", jsession);
    /* Password */
    json_object *jpassword = json_object_new_string(c->pass);
    json_object_object_add(jobj,"password", jpassword);
    /* Sensor */
    json_object *jsensor = json_object_new_string(sensor);
    json_object_object_add(jobj,"sensor", jsensor);
    FILE *fo = fopen(jsonlog, "a");
    if (fo != NULL) {
	    	fprintf(fo, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE));
	    	fprintf(fo,"\n");
    	fclose(fo);
	} else {
		fprintf(stderr, "Couldn't write to JSON log file\n");
		return -1;	
	}
    return r;
}

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session, const char *logfile, bool syslog_bool, int delay, 
	const char *jsonlog, const char *sensor) {
    struct connection con;
    con.session = session;

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(con.session));
        return -1;
    }
    if (DEBUG) { 
    	printf("Successful key exchange.\n"); 
    }

    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    while (1) {
        if ((con.message = ssh_message_get(con.session)) == NULL) {
            break;
        }

        /* Log the authentication request and disconnect. */
        if (ssh_message_subtype(con.message) == SSH_AUTH_METHOD_PASSWORD) {
        	log_attempt(&con, logfile, jsonlog, syslog_bool, sensor);
			sleep(delay);
			
			 
        }
        else {
            if (DEBUG) { fprintf(stderr, "Not a password authentication attempt.\n"); }
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(con.message);
        ssh_message_free(con.message);
    }

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}


void drop_priv (const char *user, const char *group) { 


   struct passwd *pw = NULL;

   pw = getpwnam(user);

   if (!pw) { 
	fprintf(stderr, "Cannot locate user: '%s'. Abort!\n", user); 
	exit(-1); 
	}
   
   if ( getuid() == 0 ) { 

	printf("Dropping priv to %s:%s.\n", user, group); 

	if (initgroups(pw->pw_name, pw->pw_gid) != 0 || setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) { 
		fprintf(stderr, "Could not drop privs! Abort!\n"); 
		exit(-1); 
		}

	} else { 
	
	printf("Not dropping priv.  Already a unprivledged user.\n"); 
	}

}

void sshpot_chroot (const char *chrootdir) { 

    printf("Chroot to %s.\n", chrootdir); 

    if (chroot(chrootdir) != 0 || chdir ("/") != 0)  { 
	fprintf(stderr, "Cannot chroot to %s", chrootdir); 
	exit(-1); 
	}

}

