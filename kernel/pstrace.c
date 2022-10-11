#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>

void insert_pstrace_entry(struct task_struct *p, long state)
{
	/* Add the ring buffer entry at index ring_buf_len.
	 * Assumption: we have a lock on the ring buffer.
	 */

	strcpy(ring_buf[ring_buf_len].comm, p->comm);
	ring_buf[ring_buf_len].state = state;
	ring_buf[ring_buf_len].pid = p->tgid;
	ring_buf[ring_buf_len].tid = p->pid;

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

	spin_lock(&ring_buf_lock);
	
	/* is tracing enabled? */
	if (traced_pid == -2) {
		spin_unlock(&ring_buf_lock);
		return;
	}

	/* are we tracing this process? */
	if ((traced_pid != -1) && (traced_pid != p->tgid)) {
		spin_unlock(&ring_buf_lock);
		return;
	}

	insert_pstrace_entry(p, state);
	spin_unlock(&ring_buf_lock);
}


/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
	struct task_struct *task = NULL;

	/* validate that we are given a valid pid */
	if (pid < -1)
		return -ESRCH;
	else if (pid == 0)
		task = &init_task;
	else
		task = find_task_by_vpid(pid);

	if (task == NULL)
		return -ESRCH;

	spin_lock(&ring_buf_lock);
	traced_pid = pid;
	spin_unlock(&ring_buf_lock);

	return 0;
}


/*
 * Syscall No. 442
 * Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
	spin_lock(&ring_buf_lock);
	traced_pid = -2;
	spin_unlock(&ring_buf_lock);

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


