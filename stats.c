#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stats.h"

/* Head of the linked list */
ip_t * iphead = NULL;
user_t * userhead = NULL;
pass_t * passhead = NULL;
combination_t * combinationhead = NULL;

/* Current items */
ip_t * ipcurrent = NULL;
user_t * usercurrent = NULL;
pass_t * passcurrent = NULL;
combination_t * combinationcurrent = NULL;

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

/* Function to update the lists */
void update_stats(stats_t *stats, char *clientip, const char *user, const char *pass) {
	printf("Updating stats\n");
	/* Increment IP count if found, otherwise add the IP */
	int ipfound = 0;
	if (stats == NULL ) {
		printf("It is null\n");
	} else {
		printf("It is not null\n");
	}
	ip_t *ipiterator = stats->iphead;
	printf("Looping\n");
	while ( ipiterator != NULL ) {
		printf("Inside ip loop\n");
		printf("Gettin in \n");

		printf("Checking IP %s against %s\n",clientip, ipiterator->clientip);
		if ( strcmp(ipiterator->clientip, clientip) == 0 ) {
			ipiterator->ipcount++;
			ipfound = 1;
		}
		printf("Next ip\n");
		ipiterator = ipiterator->next;	
	}
	if (ipfound == 0) {
		stats->ipcurrent->next = malloc(sizeof(ip_t));
		stats->ipcurrent = stats->ipcurrent->next;
		stats->ipcurrent->clientip = clientip;
		stats->ipcurrent->ipcount = 1;
		stats->ipcurrent->next = NULL;
	}
	printf("ip done\n");
	/* Increment User count if found, otherwise add the User */
	int userfound = 0;
	user_t * useriterator = stats->userhead;
	while (useriterator != NULL) {
		if (useriterator->userid != NULL && strcmp(useriterator->userid, user)==0) {
			useriterator->usercount++;
			userfound = 1;
		}
		useriterator = useriterator->next;	
	}
	if (!userfound) {
		stats->usercurrent->next = malloc(sizeof(user_t));
		stats->usercurrent = stats->usercurrent->next;
		stats->usercurrent->userid = user;
		stats->usercurrent->usercount = 1;
		stats->usercurrent->next = NULL;
	}
	printf("user done\n");
	/* Increment Password count if found, otherwise add the Password */
	int passfound = 0;
	pass_t * passiterator = stats->passhead;
	while (passiterator != NULL) {
		if (passiterator->pass != NULL && strcmp(passiterator->pass, pass)==0) {
			passiterator->passcount++;
			passfound = 1;
		}
		passiterator = passiterator->next;	
	}
	if (!passfound) {
		stats->passcurrent->next = malloc(sizeof(pass_t));
		stats->passcurrent = stats->passcurrent->next;
		stats->passcurrent->pass = pass;
		stats->passcurrent->passcount = 1;
		stats->passcurrent->next = NULL;
	}
	printf("Pass done\n");
	/* Increment Combination count if found, otherwise add the Combination */
	int combinationfound = 0;
	char *combination = concat(user, "/");
	combination = concat(combination, pass);
	combination_t * combinationiterator = stats->combinationhead;
	while (combinationiterator != NULL) {
		if (combinationiterator->combination != NULL && 
					strcmp(combinationiterator->combination, combination)==0) {
			combinationiterator->combinationcount++;
			combinationfound = 1;
		}
		combinationiterator = combinationiterator->next;	
	}
	if (!combinationfound) {
		stats->combinationcurrent->next = malloc(sizeof(combination_t));
		stats->combinationcurrent = stats->combinationcurrent->next;
		stats->combinationcurrent->combination = combination;
		stats->combinationcurrent->combinationcount = 1;
		stats->combinationcurrent->next = NULL;
	}
	printf("Combination done\n");
	
	printf("Updating stats done\n");
	return;
}

/* Write stats to file */
void write_stats(stats_t *stats) {

	ip_t *ipiterator = stats->iphead;
	while (ipiterator != NULL) {
		printf("IP: %s, count: %i\n", ipiterator->clientip, ipiterator->ipcount);
		ipiterator = ipiterator->next;
	}

}
