#include "config.h"
#include "auth.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdbool.h>

#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <json-c/json.h>

#define MINPORT 0
#define MAXPORT 65535


/* Global so they can be cleaned up at SIGINT. */
static ssh_session session;
static ssh_bind sshbind;

/* RSA keyfile generation */
const int kBits = 1024;
const int kExp = 3;

/* Print usage information to `stream', exit with `exit_code'. */
static void usage(FILE *stream, int exit_code) {
    fprintf(stream, "Usage: sshpot [-h]\n");
    fprintf(stream,
        "   -h  --help             Display this usage information.\n"
	    "   -l  --listen {addr}    Listen address; defaults to %s.\n"
        "   -p  --port <port>      Port to listen on; defaults to %d.\n"
        "   -r  --rsa <file>       RSA Key file; defaults to %s.\n" 
        "   -L  --logfile <file>   Output log file; defaults to %s\n"
	    "   -s  --syslog           Log output to syslog.\n"
	    "   -u  --user <username>  Username to drop privs to; defaults to '%s'.\n"
	    "   -g  --group <group>    Group to drop privs to; defaults to '%s'.\n"
	    "   -d  --daemon           Become a daemon.\n"
	    "   -t  --delay <#>        Seconds to delay between auth attempts; default %ds.\n"
	    "   -c  --chroot <dir>     Run in a chroot environment.\n"
	    "   -b  --banner <banner>  SSH Banner; defaults to '%s'.\n"
	    "   -j  --json <jsonfile> JSON Cowrie compatible log; defaults to '%s'.\n"
	    "   -e  --sensor <sensor_name> Sensor name (JSON log); defaults to '%s'.\n", 
	    	LISTENADDRESS, DEFAULTPORT, RSA_PRIV_KEYFILE, LOGFILE, USER, GROUP, DELAY, 
	    		BANNER, JSON_SSH_LOG, SENSOR ); 


    exit(exit_code);
}


/* Return the c-string `p' as an int if it is a valid port 
 * in the range of MINPORT - MAXPORT, or -1 if invalid. */
static int valid_port(char *p) {
    int port;
    char *endptr;

    port = strtol(p, &endptr, 10);
    if (port >= MINPORT && port <= MAXPORT && !*endptr && errno == 0) 
        return port;

    return -1;
}


/* Signal handler for cleaning up after children. We want to do cleanup
 * at SIGCHILD instead of waiting in main so we can accept multiple
 * simultaneous connections. */
static int cleanup(void) {
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
        if (DEBUG) { printf("process %d reaped\n", pid); }
    }

    /* Re-install myself for the next child. */
    signal(SIGCHLD, (void (*)())cleanup);

    return 0;
}


/* SIGINT handler. Cleanup the ssh* objects and exit. */
static void wrapup(void) {
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    exit(0);
}

/* Function responsigle for RSA keyfile generation */
bool generate_keyfile(const char* rsa_keyfile)
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;
    int             bits = 2048;
    unsigned long   e = RSA_F4;
 
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
 
    // 2. save public key
    bp_public = BIO_new_file(RSA_PUB_KEYFILE, "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }
 
    // 3. save private key
    bp_private = BIO_new_file(rsa_keyfile, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
 
    // 4. free
free_all:
 
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
 
    return (ret == 1);
}

int main(int argc, char *argv[]) {

    int port = DEFAULTPORT;
    int delay = DELAY; 

    const char *rsa_keyfile = RSA_PUB_KEYFILE;
    const char *logfile = LOGFILE;
    const char *user = USER; 
    const char *group = GROUP; 
    const char *listen = LISTENADDRESS; 
    const char *banner = BANNER; 
    const char *jsonlog = JSON_SSH_LOG;
    const char *sensor = SENSOR;
    const char *chroot = NULL; 
    
    /* Init the session id */
    init_session_uuid();

	/* Parse configuration file if present */
	/* Command line parameters override configuration file */
	char * buffer = 0;
	long length;
	FILE * f = fopen (CONFIG_FILE, "rb");
	if (f) {
  		fseek (f, 0, SEEK_END);
  		length = ftell (f);
  		fseek (f, 0, SEEK_SET);
  		buffer = malloc (length);
  		if (buffer) {
    		fread (buffer, 1, length, f);
  		}
  		fclose (f);
	}

	if (buffer) {
  		/* Parse JSON Config file */
  		json_object * jobj = json_tokener_parse(buffer);
  		/* Listenaddress */
  		json_object* jlistenaddress = json_object_object_get(jobj, CONFIG_LISTENADDRESS);
  		if (jlistenaddress) {
  			listen = json_object_get_string(jlistenaddress);
  		}
  		/* Port */
  		json_object* jport = json_object_object_get(jobj, CONFIG_PORT);
  		if (jport) {
  			port = json_object_get_int(jport);
  		}
  		/* RSA Keyfile */
  		json_object* jrsa_keyfile = json_object_object_get(jobj, CONFIG_RSA_PRIV_KEYFILE);
  		if (jrsa_keyfile) {
  			rsa_keyfile = json_object_get_string(jrsa_keyfile);
  		}
  		/* Logfile */
  		json_object* jlogfile = json_object_object_get(jobj, CONFIG_LOGFILE);
  		if (jlogfile) {
  			logfile = json_object_get_string(jlogfile);
  		}
  		/* JSON Logfile */
  		json_object* jjsonlogfile = json_object_object_get(jobj, CONFIG_JSONLOG);
  		if (jjsonlogfile) {
  			jsonlog = json_object_get_string(jjsonlogfile);
  		}
  		/* Sensor */
  		json_object* jsensor = json_object_object_get(jobj, CONFIG_SENSOR);
  		if (jsensor) {
  			sensor = json_object_get_string(jsensor);
  		}			  		
	}

    bool syslog_bool = 0; 
    bool chroot_bool = 0; 
    bool daemon_bool = 0; 

    /* Handle command line options. */
    int next_opt = 0;
    const char *short_opts = "b:c:g:u:l:L:r:p:hsd:j:e";
    const struct option long_opts[] = {
        { "help",    no_argument, NULL, 'h' },
		{ "daemon",  no_argument, NULL, 'd' }, 
    	{ "port",    required_argument, NULL, 'p' },
    	{ "rsa",     required_argument, NULL, 'r' }, 
    	{ "logfile", required_argument, NULL, 'L' }, 
    	{ "syslog",  required_argument, NULL, 's' }, 
		{ "user",    required_argument, NULL, 'u' }, 
		{ "group",   required_argument, NULL, 'g' }, 
		{ "delay",   required_argument, NULL, 't' }, 
		{ "chroot",  required_argument, NULL, 'c' }, 
		{ "listen",  required_argument, NULL, 'l' }, 
    	{ "banner",  required_argument, NULL, 'b' },
    	{ "json",  	 required_argument, NULL, 'j' },
    	{ "sensor",  required_argument, NULL, 'e' }, 
        { NULL,      0, NULL, 0   }
    };

    while (next_opt != -1) {
        next_opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        switch (next_opt) {
            case 'h':
                usage(stdout, 0);
                break;

            case 'p':
                if ((port = valid_port(optarg)) < 0) {
                    fprintf(stderr, "Port must range from %d - %d\n\n", MINPORT, MAXPORT);
                    usage(stderr, 1);
                }
                break;

	    case 'r':
	        rsa_keyfile = optarg; 
		break;

	    case 'L':
		logfile = optarg; 
		break;

	    case 'l':
	        listen = optarg; 
		break;
   
            case 's':
		syslog_bool = 1; 
		break;

	    case 'u':
		user = optarg; 
		break;

	    case 'g':
		group = optarg; 
		break; 

	    case 'b': 
		banner = optarg; 
		break;

	    case 'd': 
		daemon_bool = 1; 
		break;

	    case 't': 
		delay = atoi(optarg); 
		break;

            case '?':
                usage(stderr, 1);
                break;

	    case 'c': 
		chroot_bool = true; 
		chroot = optarg; 
		break;

            case -1:
                break;

            default:
                fprintf(stderr, "Fatal error, aborting...\n");
                exit(1);
        }
    }

    /* There shouldn't be any other parameters. */
    if (argv[optind]) {
        fprintf(stderr, "Invalid parameter `%s'\n\n", argv[optind]);
        usage(stderr, 1);
    }

    /* Install the signal handlers to cleanup after children and at exit. */
    signal(SIGCHLD, (void (*)())cleanup);
    signal(SIGINT, (void(*)())wrapup);

    /* Create and configure the ssh session. */
    /* Check whether RSA keyfile exists, otherwise create one */
    
    if( access( rsa_keyfile, F_OK ) == -1 ) {
    /* RSA keyfile doesn't exist, let's create one */
    	if (!generate_keyfile(rsa_keyfile)) {
    		fprintf(stderr, "Error generation RSA keyfile\n");
    		return -1;
    	}
    } 
    
    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, listen);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,rsa_keyfile);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner);


    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return -1;
    }

    printf("Listening on port %s:%d.\n", listen, port);

    /* Chroot has to happen before drop_priv! */
    if (chroot_bool) { 
        sshpot_chroot(chroot); 
	}

    /* Drop to non-root user please */
    drop_priv(user, group);

    /* Become a deamon,  if the user wants */
    if (daemon_bool) { 

	printf("Becoming a daemon!\n"); 

	pid_t pid = 0;
	setsid();
	pid = fork();

	if (pid == 0) {}
	else
                {
                    exit(0);
                }
	
	}

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: `%s'.\n",ssh_get_error(sshbind));
            return -1;
        }
        if (DEBUG) { printf("Accepted a connection.\n"); }

        switch (fork())  {
            case -1:
                fprintf(stderr,"Fork returned error: `%d'.\n",-1);
                exit(-1);

            case 0:
                exit(handle_auth(session, logfile, syslog_bool, delay, jsonlog, sensor));

            default:
                break;
        }
    }

    return 0;
}
