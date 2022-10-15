#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>

struct pstrace ring_buf[PSTRACE_BUF_SIZE];

spinlock_t ring_buf_lock; /* used for locking the ring_buf, ring_buf_len, and traced_pid */
int ring_buf_len = 0;  /* index of latest entry in the ring buffer */
int ring_buf_count = 0; /* number of records added since last clear */
pid_t traced_pid = -2; /* the pid we are tracing, or -1 for all processes,
			* or -2 for tracing disabled
			*/

void insert_pstrace_entry(struct task_struct *p, long state)
{
	/* Add the ring buffer entry at index ring_buf_len.
	 * Assumption: we have a lock on the ring buffer.
	 */

	strcpy(ring_buf[ring_buf_len].comm, p->comm);
	ring_buf[ring_buf_len].state = state;
	ring_buf[ring_buf_len].pid = p->tgid;
	ring_buf[ring_buf_len].tid = p->pid;

	ring_buf_count++;
	ring_buf_len++;
	if (ring_buf_len == PSTRACE_BUF_SIZE)
		ring_buf_len = 0;
}

/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
	/* Add to the ring buffer. We need to add the state updates of all those
	 * traced processes.
	 */
	unsigned long flags = 0;

	/* only track states that we care about */
	if (state != TASK_RUNNING &&
	    state != TASK_RUNNABLE &&
	    state != TASK_INTERRUPTIBLE &&
	    state != TASK_UNINTERRUPTIBLE &&
	    state != __TASK_STOPPED &&
	    state != EXIT_ZOMBIE &&
	    state != EXIT_DEAD)
		return;

	spin_lock_irqsave(&ring_buf_lock, flags);
	
	/* is tracing enabled? */
	if (traced_pid == -2) {
		spin_unlock_irqrestore(&ring_buf_lock, flags);
		return;
	}

	/* are we tracing this process? */
	if ((traced_pid != -1) && (traced_pid != p->tgid)) {
		spin_unlock_irqrestore(&ring_buf_lock, flags);
		return;
	}

	insert_pstrace_entry(p, state);
	spin_unlock_irqrestore(&ring_buf_lock, flags);
}


/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
	struct task_struct *task = NULL;
	unsigned long flags = 0;

	/* validate that we are given a valid pid */
	if (pid < -1)
		return -ESRCH;
	else if (pid == 0)
		task = &init_task;
	else if (pid > 0) {
		task = find_task_by_vpid(pid);
	}

	if (pid != -1 && task == NULL)
		return -ESRCH;

	spin_lock_irqsave(&ring_buf_lock, flags);
	traced_pid = pid;
	spin_unlock_irqrestore(&ring_buf_lock, flags);

	return 0;
}


/*
 * Syscall No. 442
 * Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&ring_buf_lock, flags);
	traced_pid = -2;
	spin_unlock_irqrestore(&ring_buf_lock, flags);

	return 0;
}


/*
 * Syscall No. 443
 *
 * Copy the pstrace ring buffer info @buf.
 * If @counter > 0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to 
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
	int i;
	for(i = 0; i < ring_buf_len; i++){
		
	}
	spin_lock_irq(&ring_buf_lock);

	spin_unlock_irq(&ring_buf_lock);
	return 0;
}


/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
SYSCALL_DEFINE0(pstrace_clear)
{
	return 0;
}


