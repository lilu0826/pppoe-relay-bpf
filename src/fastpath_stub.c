/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <syslog.h>
#include <stdio.h>
#include "fastpath.h"

int fastpath_init(const struct InterfaceStruct *ifs, int count, int max, int debug, int foreground)
{
    (void)ifs; (void)count; (void)max; (void)debug;
    const char *msg = "FASTPATH FALLBACK: built without fastpath; use make FASTPATH=1";
    syslog(LOG_WARNING, "%s", msg);
    if (foreground) fprintf(stderr, "%s\n", msg);
    return 0;
}
void fastpath_add_session(struct SessionStruct *s) { (void)s; }
void fastpath_del_session(struct SessionStruct *s) { (void)s; }
void fastpath_tick(struct SessionStruct *s, unsigned int epoch) { (void)s; (void)epoch; }
int fastpath_event_fd(void) { return -1; }
int fastpath_enabled(void) { return 0; }
void fastpath_cleanup(void) {}
