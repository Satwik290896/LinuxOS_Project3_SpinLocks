#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>


/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
	/* Add to the ring buffer. We need to add the state updates of all those
	 * traced processes
	 */
}


/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
	return 0;
}


/*
 * Syscall No. 442
 * Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
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


