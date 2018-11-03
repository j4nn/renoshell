#ifndef _CLIENT_H_
#define _CLIENT_H_

int client_arbitrary_read(uint64_t addr, int size, void *buffer);
int client_arbitrary_write(uint64_t addr, int size, void *buffer);

int client_curr_get_task_struct_p(uint64_t *addr);
int client_curr_get_kaslr(uint64_t *addr);
void client_report_uid(int uid);

#endif
