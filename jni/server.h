#ifndef _SERVER_H_
#define _SERVER_H_

#define CMD_SERVER_PORT 54320

enum {
	CMD_QUIT,
	CMD_READ,
	CMD_WRITE,
	CMD_GET_TASKP,
	CMD_GET_KASLR,
	CMD_REPORT_UID,
};

struct t_cmd {
	uint64_t addr;
	uint32_t size;
	uint32_t cmd;
};

#endif
