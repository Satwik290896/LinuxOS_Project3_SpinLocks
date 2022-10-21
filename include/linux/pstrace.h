#ifndef __PSTRACE_H
#define __PSTRACE_H

#include <linux/spinlock.h>
#include <linux/sched.h>

#define PSTRACE_BUF_SIZE 500	/* The maximum size of the ring buffer */
#define TASK_RUNNABLE 3

/* The data structure used to save the traced process. */
struct pstrace {
	char comm[16];	/* name of the process */
	long state;		/* state of the process */
	pid_t pid;		/* pid of the process, ie returned by getpid */
	pid_t tid;		/* tid of the thread, ie returned by gettid */
};

/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state);
void pstrace_add_wakeup(struct task_struct *p, long state);

#endif
