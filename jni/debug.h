#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define oprintf(fmt, args...) \
	do { \
		fprintf(stderr, (fmt), ##args); \
	} while(0)
#define PRNO(fmt, args...) \
	do { \
		char err[1024]; \
		fprintf(stderr, fmt ": %s\n", ##args, \
			strerror_r(errno, err, sizeof err)); \
	} while(0)
#define PERR(fmt, args...) oprintf(fmt, ##args)
#define PNFO(fmt, args...) oprintf(fmt, ##args)

#ifdef DEBUG_LOG
#define PDBG(fmt, args...) oprintf(fmt, ##args)
#else
#define PDBG(fmt, args...)
#endif

#endif
