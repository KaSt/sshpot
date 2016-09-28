#ifndef CONFIG_H
#define CONFIG_H

#ifdef __APPLE__
#include <sys/syslog.h>
#else
#include <syslog.h>
#endif

#define LISTENADDRESS   "0.0.0.0"
#define DEFAULTPORT     22
#define RSA_PRIV_KEYFILE     "./sshpot.rsa.pem"
#define RSA_PUB_KEYFILE     "./sshpot.rsa.pub"
#define LOGFILE         "sshpot_auth.log"
#define DEBUG		0

#define	USER		"nobody"
#define GROUP		"nogroup"

/* the "SSH-2.0-" is automatically added by libssh! */

#define BANNER		"OpenSSH_6.7p1 Debian-5+deb8u3"

#define DELAY		2

#define SYSLOG_FACILITY	LOG_AUTH
#define SYSLOG_PRIORITY LOG_ALERT

#endif
