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

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len);
int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len);

int client_arbitrary_read(uint64_t addr, int size, void *buffer)
{
	return raw_kernel_read(addr, buffer, size) == size ? 0 : -1;
}

int client_arbitrary_write(uint64_t addr, int size, void *buffer)
{
	return raw_kernel_write(addr, buffer, size) == size ? 0 : -1;
}

