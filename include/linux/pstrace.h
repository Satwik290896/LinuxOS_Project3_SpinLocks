#ifndef __PSTRACE_H
#define __PSTRACE_H
#include <linux/sched.h>
#include <linux/spinlock.h>

#define PSTRACE_BUF_SIZE 500	/* The maximum size of the ring buffer */
#define TASK_RUNNABLE 3

/* The data structure used to save the traced process. */
struct pstrace {
	char comm[16];	/* name of the process */
	long state;		/* state of the process */
	pid_t pid;		/* pid of the process, ie returned by getpid */
	pid_t tid;		/* tid of the thread, ie returned by gettid */
};

struct pstrace ring_buf[PSTRACE_BUF_SIZE];

spinlock_t ring_buf_lock; /* used for locking the ring_buf, ring_buf_len, and traced_pid */
int ring_buf_len = 0;  /* index of latest entry in the ring buffer */
int ring_buf_count = 0; /* number of records added since last clear */
pid_t traced_pid = -2; /* the pid we are tracing, or -1 for all processes,
			* or -2 for tracing disabled
			*/

#endif
