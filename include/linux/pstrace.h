#ifndef __PSTRACE_H
#define __PSTRACE_H
#include <linux/sched.h>

#define PSTRACE_BUF_SIZE 500	/* The maximum size of the ring buffer */


/* The data structure used to save the traced process. */
struct pstrace {
	char comm[16];	/* name of the process */
	long state;		/* state of the process */
	pid_t pid;		/* pid of the process, ie returned by getpid */
	pid_t tid;		/* tid of the thread, ie returned by gettid */
};

struct pstrace ring_buf[PSTRACE_BUF_SIZE];

int ring_buf_len = 0;  /* index of latest entry in the ring buffer */
pid_t traced_pid = -2; /* the pid we are tracing, or -1 for all processes,
			* or -2 for tracing disabled
			*/

#endif
