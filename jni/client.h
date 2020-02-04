#ifndef _CLIENT_H_
#define _CLIENT_H_

int client_arbitrary_read(uint64_t addr, int size, void *buffer);
int client_arbitrary_write(uint64_t addr, int size, void *buffer);

#endif
