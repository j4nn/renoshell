#ifndef OFFSETS_H
#define OFFSETS_H

struct offsets {
	char *targetid; 	// model_fwversion
	void* sidtab;		// for selinux contenxt
	void* policydb;		// for selinux context
	void* selinux_enforcing;
	void *init_task;
	void *init_user_ns;
};

struct offsets* get_offsets();
extern struct offsets offsets[];

#endif /* OFFSETS_H */
