/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RP_FASTPATH_H
#define RP_FASTPATH_H

struct InterfaceStruct;
struct SessionStruct;

int fastpath_init(const struct InterfaceStruct *interfaces, int count,
                  int max_sessions, int debug, int foreground);
void fastpath_add_session(struct SessionStruct *session);
void fastpath_del_session(struct SessionStruct *session);
void fastpath_tick(struct SessionStruct *active, unsigned int epoch);
int fastpath_event_fd(void);
int fastpath_enabled(void);
void fastpath_cleanup(void);

#endif
