#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h>

struct pstrace ring_buf[PSTRACE_BUF_SIZE];

spinlock_t ring_buf_lock; /* used for locking the ring_buf, ring_buf_len, and traced_pid */
spinlock_t wait_queue;
int ring_buf_len = 0;  /* index of latest entry in the ring buffer */
int ring_buf_count = 0; /* number of records added ever */
int ring_buf_valid_count = 0; /* number of records added since last clear */
atomic_t clear_count; /* used for conditionally stopping waiting when we clear the buffer */
pid_t traced_pid = -2; /* the pid we are tracing, or -1 for all processes,
			* or -2 for tracing disabled
			*/
DECLARE_WAIT_QUEUE_HEAD(wq_head);
//struct wait_queue_head wq_head;
bool is_wakeup_required = false;
//wq_head.lock = wait_queue;
struct mutex pstrace_mutex; /* used for locking ring_buf and sleep */

void insert_pstrace_entry(struct task_struct *p, long state)
{
	/* Add the ring buffer entry at index ring_buf_len.
	 * Assumption: we have a lock on the ring buffer.
	 */
	strcpy(ring_buf[ring_buf_len].comm, p->comm);
	ring_buf[ring_buf_len].state = state;
	ring_buf[ring_buf_len].pid = p->tgid;
	ring_buf[ring_buf_len].tid = p->pid;
	printk("Insert Ring_buff[%d] info:\ncomm: %s\nstate: %ld\n", ring_buf_len, ring_buf[ring_buf_len].comm, ring_buf[ring_buf_len].state);
	ring_buf_count++;

	// wake_up?
	ring_buf_valid_count++;
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

	if (state == TASK_STOPPED)
		state = __TASK_STOPPED;

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
	printk("Process to be traced: tgid=%d\n", p->tgid);
	insert_pstrace_entry(p, state);
	spin_unlock_irqrestore(&ring_buf_lock, flags);
	//	if (is_wakeup_required)
	//		wake_up_interruptible(&wq_head);
}

/*int copy_ring_buf(struct pstrace __user *dst, int num_to_copy, int cleared)
{
	int i;

	for (i = 0; i < num_to_copy && (cleared == 0 || i < ring_buf_valid_count); i++) {
		int index = (ring_buf_len + i) % PSTRACE_BUF_SIZE;
		if (copy_to_user(&(dst[i].comm), ring_buf[index].comm, 16) ||
		    put_user(ring_buf[index].state, &(dst[i].state)) ||
		    put_user(ring_buf[index].pid, &(dst[i].pid)) ||
		    put_user(ring_buf[index].tid, &(dst[i].tid)))
			return -EFAULT;
	}

	return 0;
}*/

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
	if(pid != -1)
		printk("traced task tid: %d\n", (int)task->tgid);
	printk(KERN_WARNING "wait_status: [pstrace.c] Enable: %d\n", pid);
	
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
	int num_to_copy;
	long linux_counter;
	long records_copied = 0;
	int cleared = 0;
	unsigned long flags = 0;
	int index;
	int i;
	int wait_status = -ERESTARTSYS;
	
	
	if (!buf || !counter)
		return -EINVAL;

	/* copy *nr from user space into max_entries */
	if (copy_from_user(&linux_counter, counter, sizeof(long)))
		return -EFAULT;

	if (linux_counter < 0)
		return -EINVAL;
		
	else if (linux_counter == 0) {

		spin_lock_irqsave(&ring_buf_lock, flags);
		num_to_copy = (ring_buf_valid_count < PSTRACE_BUF_SIZE ?
			       ring_buf_valid_count : PSTRACE_BUF_SIZE);

		printk(KERN_WARNING "num_to_copy: %d\nring_buf_len: %d\n", num_to_copy, ring_buf_len);

		for (i = 0; i < num_to_copy && i < ring_buf_valid_count; i++)
		{
			// index = (ring_buf_len + i) % PSTRACE_BUF_SIZE;
			if(ring_buf_valid_count > 500)
				index = (ring_buf_valid_count + i) % PSTRACE_BUF_SIZE;
			else
				index = i;
			printk(KERN_WARNING "index: %d\n", index);
			printk("Copy Ring_buff[%d] info:\ncomm: %s\nstate: %ld\n", index, ring_buf[index].comm, ring_buf[index].state);

			if (copy_to_user(buf[i].comm, ring_buf[index].comm, 16*sizeof(char)) ||
			    copy_to_user(&(buf[i].state), &(ring_buf[index].state), sizeof(long)) ||
			    copy_to_user(&(buf[i].pid), &(ring_buf[index].pid), sizeof(pid_t)) ||
			    copy_to_user(&(buf[i].tid), &(ring_buf[index].tid), sizeof(pid_t))) {
				spin_unlock_irqrestore(&ring_buf_lock, flags);
				return -EFAULT;
			}
			records_copied++;
		}

		spin_unlock_irqrestore(&ring_buf_lock, flags);

		return records_copied;
	} else {

		int orig_clear_count = clear_count.counter;
		
		printk(KERN_WARNING "wait_status: [pstrace.c] Entering here: %d\n", wait_status);

		if (ring_buf_count < linux_counter + PSTRACE_BUF_SIZE) {
			printk(KERN_WARNING "wait_status: [pstrace.c] Condition not satisfied %d\n", wait_status);
			wq_head.lock = wait_queue;	
			is_wakeup_required = true;
			//while (wait_status < 0) {
			wait_status = wait_event_interruptible(wq_head,
				   (ring_buf_count >= linux_counter + PSTRACE_BUF_SIZE) ||
				   (orig_clear_count != clear_count.counter));
			printk(KERN_WARNING "wait_status: [pstrace.c] Interrupted? Or not?: %d\n", wait_status);
			//}
			
			if (wait_status !=  0)
				return wait_status;
			if (orig_clear_count != clear_count.counter)
				cleared = 1;
		}
		is_wakeup_required = false;

		/* now, return valid entries between *counter and *counter+PSTRACE_BUF_SIZE */
		spin_lock_irqsave(&ring_buf_lock, flags);
		for (i = 0; i < PSTRACE_BUF_SIZE && (cleared == 0 || i < ring_buf_valid_count); i++) 
		{
			index = (ring_buf_len + i) % PSTRACE_BUF_SIZE;
			if (copy_to_user(buf[i].comm, ring_buf[index].comm, 16*sizeof(char)) ||
			    copy_to_user(&(buf[i].state), &(ring_buf[index].state), sizeof(long)) ||
			    copy_to_user(&(buf[i].pid), &(ring_buf[index].pid), sizeof(pid_t)) ||
			    copy_to_user(&(buf[i].tid), &(ring_buf[index].tid), sizeof(pid_t))) {
				spin_unlock_irqrestore(&ring_buf_lock, flags);
				return -EFAULT;
			}
			records_copied++;
		}

		spin_unlock_irqrestore(&ring_buf_lock, flags);

		return records_copied;
	}
	return records_copied;
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
	unsigned long flags = 0;

	atomic_inc(&clear_count);
	// wake_up?
	if (is_wakeup_required)
		wake_up_interruptible(&wq_head);

	spin_lock_irqsave(&ring_buf_lock, flags);
	ring_buf_valid_count = 0;

	ring_buf_len = 0;
	spin_unlock_irqrestore(&ring_buf_lock, flags);

	return 0;
}


