#ifndef STATS_H
#define STATS_H

#include <string.h>


typedef struct ip_struct {
    char *clientip;
    int ipcount;
    struct ip_struct * next;
} ip_t;

typedef struct user_struct {
    const char *userid;
    int usercount;
    struct user_struct * next;
} user_t;

typedef struct pass_struct {
    const char *pass;
    int passcount;
    struct pass_struct * next;
} pass_t;

typedef struct combination_struct {
    char *combination;
    int combinationcount;
    struct combination_struct * next;
} combination_t;

typedef struct stats_struct {
	ip_t *iphead;
	ip_t *ipcurrent;
	
	user_t *userhead;
	user_t *usercurrent;
	
	pass_t *passhead;
	pass_t *passcurrent;
	
	combination_t *combinationhead;
	combination_t *combinationcurrent;
	
	long attackcount;
} stats_t;

void update_stats(stats_t *stats, char *clientip, const char *user, const char *pass);
void write_stats();

#endif
